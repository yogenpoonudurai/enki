package platform

import (
	"net"
	"strings"
)

// BindScope classifies a listener bind address.
type BindScope string

const (
	ScopeLoopback BindScope = "loopback"
	ScopeLAN      BindScope = "lan"
	ScopeAll      BindScope = "all" // wildcard 0.0.0.0 / ::
)

// ClassifyBindAddr classifies a bind address string (without port).
func ClassifyBindAddr(addr string) BindScope {
	addr = strings.Trim(addr, "[]")
	switch addr {
	case "", "0.0.0.0", "::", "*":
		return ScopeAll
	case "localhost":
		return ScopeLoopback
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return ScopeLAN
	}
	if ip.IsLoopback() {
		return ScopeLoopback
	}
	return ScopeLAN
}

// IsPrivateOrLoopback reports whether ip is safe for enki to probe:
// loopback, RFC1918/ULA, or link-local only.
func IsPrivateOrLoopback(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// ProbeAddr returns the loopback address enki should use to reach a service
// bound on the given address, or "" if probing is not permitted.
func ProbeAddr(bindAddr string, port int) string {
	scope := ClassifyBindAddr(bindAddr)
	host := net.JoinHostPort("127.0.0.1", itoa(port))
	switch scope {
	case ScopeLoopback, ScopeAll, ScopeLAN:
		if scope == ScopeLAN {
			ip := net.ParseIP(strings.Trim(bindAddr, "[]"))
			if ip == nil || !IsPrivateOrLoopback(ip) {
				return ""
			}
		}
		return host
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
