//go:build linux

package collector

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Listeners enumerates listening TCP sockets via /proc and resolves owning
// processes through /proc/<pid>/fd. Other users' sockets may be unattributed
// without elevated privileges; callers receive a coverage gap in that case.
func Listeners() ([]Listener, []Gap) {
	var gaps []Gap

	tcp4, ino4, g4 := parseProcNet("/proc/net/tcp", false)
	tcp6, ino6, g6 := parseProcNet("/proc/net/tcp6", true)
	gaps = append(gaps, g4...)
	gaps = append(gaps, g6...)

	out := append(tcp4, tcp6...)
	inodes := append(ino4, ino6...)

	pidByInode, _ := socketOwners()
	uids := map[int]string{}
	unattributed := 0
	for i := range out {
		pid, ok := pidByInode[inodes[i]]
		if !ok {
			unattributed++
			continue
		}
		out[i].PID = pid
		enrichProcess(&out[i], uids)
	}

	if unattributed > 0 {
		gaps = append(gaps, Gap{
			Module: "listeners",
			Kind:   GapPermission,
			Reason: fmt.Sprintf("%d listener(s) could not be attributed to a process (owned by other users); rerun elevated for full coverage", unattributed),
		})
	}
	if inContainer() {
		gaps = append(gaps, Gap{
			Module: "listeners",
			Kind:   GapUnsupported,
			Reason: "scanning the current network namespace only; host or other-container listeners are not visible",
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Addr < out[j].Addr
	})
	return out, gaps
}

func parseProcNet(path string, v6 bool) ([]Listener, []uint64, []Gap) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, []Gap{{Module: "listeners", Reason: fmt.Sprintf("cannot read %s: %v", path, err)}}
	}
	defer f.Close()

	var out []Listener
	var inodes []uint64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[3] != "0A" { // 0A = TCP_LISTEN
			continue
		}
		addr, port, err := decodeProcAddr(fields[1], v6)
		if err != nil {
			continue
		}
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		proto := "tcp"
		if v6 {
			proto = "tcp6"
		}
		out = append(out, Listener{Proto: proto, Addr: addr, Port: port})
		inodes = append(inodes, inode)
	}
	return out, inodes, nil
}

// decodeProcAddr decodes /proc/net/tcp{,6} addresses. IPv4 addresses are
// little-endian per 32-bit word; IPv6 addresses are four little-endian words.
func decodeProcAddr(s string, v6 bool) (string, int, error) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return "", 0, fmt.Errorf("bad address %q", s)
	}
	hexAddr := s[:i]
	port64, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return "", 0, err
	}
	raw, err := hex.DecodeString(hexAddr)
	if err != nil {
		return "", 0, err
	}
	if !v6 {
		if len(raw) != 4 {
			return "", 0, fmt.Errorf("bad ipv4 %q", hexAddr)
		}
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]).String(), int(port64), nil
	}
	if len(raw) != 16 {
		return "", 0, fmt.Errorf("bad ipv6 %q", hexAddr)
	}
	buf := make([]byte, 16)
	for word := 0; word < 4; word++ {
		for b := 0; b < 4; b++ {
			buf[word*4+b] = raw[word*4+3-b]
		}
	}
	return net.IP(buf).String(), int(port64), nil
}

// socketOwners builds an inode→PID map from /proc/<pid>/fd entries the current
// user can read.
func socketOwners() (map[uint64]int, bool) {
	owners := map[uint64]int{}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return owners, true
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join("/proc", p.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
			if err != nil {
				continue
			}
			owners[inode] = pid
		}
	}
	return owners, len(owners) == 0
}

func enrichProcess(l *Listener, uidCache map[int]string) {
	pidDir := filepath.Join("/proc", strconv.Itoa(l.PID))
	if b, err := os.ReadFile(filepath.Join(pidDir, "comm")); err == nil {
		l.Process = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(pidDir, "cmdline")); err == nil {
		l.Cmdline = strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	}
	if uid, err := processUID(pidDir); err == nil {
		if name, ok := uidCache[uid]; ok {
			l.User = name
		} else if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			uidCache[uid] = u.Username
			l.User = u.Username
		} else {
			name := strconv.Itoa(uid)
			uidCache[uid] = name
			l.User = name
		}
	}
}

func processUID(pidDir string) (int, error) {
	f, err := os.Open(filepath.Join(pidDir, "status"))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.Atoi(fields[1])
			}
		}
	}
	return 0, fmt.Errorf("uid not found")
}

func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		return strings.Contains(s, "docker") || strings.Contains(s, "kubepods") || strings.Contains(s, "containerd")
	}
	return false
}
