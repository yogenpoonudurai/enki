//go:build windows

package collector

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPIDListener = 3
	afInet                   = 2
	afInet6                  = 23
)

var (
	modiphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

// Listeners enumerates listening TCP sockets with GetExtendedTcpTable, which
// includes owning PIDs without requiring elevation.
func Listeners() ([]Listener, []Gap) {
	var out []Listener
	var gaps []Gap

	rows4, err := getTCPTable(afInet)
	if err != nil {
		gaps = append(gaps, Gap{Module: "listeners", Reason: "IPv4 listener enumeration failed: " + err.Error()})
	} else {
		out = append(out, parseTCPV4(rows4)...)
	}
	rows6, err := getTCPTable(afInet6)
	if err != nil {
		gaps = append(gaps, Gap{Module: "listeners", Reason: "IPv6 listener enumeration failed: " + err.Error()})
	} else {
		out = append(out, parseTCPV6(rows6)...)
	}

	names := processNames()
	for i := range out {
		if name, ok := names[uint32(out[i].PID)]; ok {
			out[i].Process = name
			out[i].Cmdline = []string{name}
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

func getTCPTable(family uint32) ([]byte, error) {
	var size uint32
	r, _, _ := procGetExtendedTCPTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(tcpTableOwnerPIDListener),
		0,
	)
	if r != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) && r != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable size query failed (code %d)", r)
	}
	if size == 0 {
		return nil, nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		r, _, _ = procGetExtendedTCPTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(family),
			uintptr(tcpTableOwnerPIDListener),
			0,
		)
		if r == 0 {
			return buf, nil
		}
	}
	return nil, fmt.Errorf("GetExtendedTcpTable failed")
}

func parseTCPV4(buf []byte) []Listener {
	if len(buf) < 4 {
		return nil
	}
	count := binary.LittleEndian.Uint32(buf[:4])
	const rowSize = 24 // MIB_TCPROW_OWNER_PID
	out := make([]Listener, 0, count)
	off := 4
	for i := uint32(0); i < count; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		localAddr := binary.LittleEndian.Uint32(row[4:8])
		localPort := binary.LittleEndian.Uint32(row[8:12])
		pid := binary.LittleEndian.Uint32(row[20:24])
		ip := net.IPv4(byte(localAddr), byte(localAddr>>8), byte(localAddr>>16), byte(localAddr>>24))
		out = append(out, Listener{
			Proto: "tcp",
			Addr:  ip.String(),
			Port:  netPort(localPort),
			PID:   int(pid),
		})
		off += rowSize
	}
	return out
}

func parseTCPV6(buf []byte) []Listener {
	if len(buf) < 4 {
		return nil
	}
	count := binary.LittleEndian.Uint32(buf[:4])
	const rowSize = 56 // MIB_TCP6ROW_OWNER_PID
	out := make([]Listener, 0, count)
	off := 4
	for i := uint32(0); i < count; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		var raw [16]byte
		copy(raw[:], row[:16])
		localPort := binary.LittleEndian.Uint32(row[20:24])
		pid := binary.LittleEndian.Uint32(row[52:56])
		out = append(out, Listener{
			Proto: "tcp6",
			Addr:  net.IP(raw[:]).String(),
			Port:  netPort(localPort),
			PID:   int(pid),
		})
		off += rowSize
	}
	return out
}

// netPort converts a MIB port field (network byte order in low 16 bits).
func netPort(v uint32) int {
	return int((v>>8)&0xff | (v&0xff)<<8)
}

func processNames() map[uint32]string {
	names := map[uint32]string{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return names
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		names[pe.ProcessID] = windows.UTF16ToString(pe.ExeFile[:])
	}
	return names
}
