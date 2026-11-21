//go:build darwin

package collector

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// Listeners enumerates listening TCP sockets with lsof. lsof attributes PIDs
// only for processes the current user may inspect; others degrade to
// unattributed entries plus a coverage gap.
func Listeners() ([]Listener, []Gap) {
	path, err := exec.LookPath("lsof")
	if err != nil {
		return nil, []Gap{{Module: "listeners", Reason: "lsof not found; listener enumeration skipped"}}
	}
	outb, err := exec.Command(path, "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn").Output()
	if err != nil {
		return nil, []Gap{{Module: "listeners", Reason: fmt.Sprintf("lsof failed: %v", err)}}
	}

	var out []Listener
	pid := 0
	comm := ""
	sc := bufio.NewScanner(bytes.NewReader(outb))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
			comm = ""
		case 'c':
			comm = line[1:]
		case 'n':
			l, ok := parseLsofAddr(line[1:])
			if !ok {
				continue
			}
			l.PID = pid
			l.Process = comm
			out = append(out, l)
		}
	}

	cmdlines := map[int][]string{}
	for i := range out {
		p := out[i].PID
		if p == 0 {
			continue
		}
		if cl, ok := cmdlines[p]; ok {
			out[i].Cmdline = cl
			continue
		}
		cl := psCmdline(p)
		cmdlines[p] = cl
		out[i].Cmdline = cl
	}

	var gaps []Gap
	if len(out) > 0 {
		unattributed := 0
		for _, l := range out {
			if l.PID == 0 {
				unattributed++
			}
		}
		if unattributed > 0 {
			gaps = append(gaps, Gap{
				Module: "listeners",
				Reason: fmt.Sprintf("%d listener(s) could not be attributed to a process (macOS permissions); rerun with elevated privileges for full coverage", unattributed),
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Addr < out[j].Addr
	})
	return out, gaps
}

func parseLsofAddr(s string) (Listener, bool) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Listener{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Listener{}, false
	}
	switch host {
	case "*":
		host = "0.0.0.0"
	case "localhost":
		host = "127.0.0.1"
	}
	return Listener{Proto: "tcp", Addr: host, Port: port}, true
}

func psCmdline(pid int) []string {
	outb, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "args=").Output()
	if err != nil {
		return nil
	}
	line := strings.TrimSpace(string(outb))
	if line == "" {
		return nil
	}
	return strings.Fields(line)
}
