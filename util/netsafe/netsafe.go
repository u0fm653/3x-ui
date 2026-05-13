// Package netsafe provides SSRF-safe HTTP dialing primitives. A dialer
// installed via SSRFGuardedDialContext resolves the host, rejects
// private/internal IPs unless the per-request context whitelists them,
// and dials the resolved IP directly so the IP checked is the IP used —
// closing the DNS-rebinding TOCTOU window.
package netsafe

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// IsBlockedIP returns true for loopback, RFC1918 private, link-local
// (including 169.254.169.254 cloud-metadata), and unspecified addresses.
func IsBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

type allowPrivateCtxKey struct{}

// ContextWithAllowPrivate marks a context as permitting outbound requests
// to private/internal IPs. Use only for callers (e.g. LAN-resident nodes)
// where the admin has opted in explicitly.
func ContextWithAllowPrivate(ctx context.Context, allow bool) context.Context {
	return context.WithValue(ctx, allowPrivateCtxKey{}, allow)
}

func AllowPrivateFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(allowPrivateCtxKey{}).(bool)
	return v
}

var defaultDialer = &net.Dialer{Timeout: 10 * time.Second}

// SSRFGuardedDialContext is a net/http Transport.DialContext implementation
// that enforces IsBlockedIP unless the context opts in via
// ContextWithAllowPrivate.
func SSRFGuardedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	allowPrivate := AllowPrivateFromContext(ctx)
	var ips []net.IPAddr
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IPAddr{{IP: ip}}
	} else {
		ips, err = net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
	}
	var lastErr error
	for _, ipAddr := range ips {
		if !allowPrivate && IsBlockedIP(ipAddr.IP) {
			lastErr = fmt.Errorf("blocked private/internal address %s", ipAddr.IP)
			continue
		}
		conn, derr := defaultDialer.DialContext(ctx, network, net.JoinHostPort(ipAddr.IP.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable address for %s", host)
	}
	return nil, lastErr
}

// hostnamePattern accepts RFC 1123 hostnames (letters, digits, hyphens,
// dots). Bracketed IPv6 forms ("[::1]") are stripped before this check
// runs in NormalizeHost.
var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

// NormalizeHost validates that addr is a plain hostname or IP literal with
// no embedded path/userinfo/port/scheme — anything that could be used to
// smuggle URL components past callers that string-format URLs from user
// input. Returns the bare host (no brackets); callers wrap IPv6 via
// net.JoinHostPort as needed.
func NormalizeHost(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("address is required")
	}
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		addr = addr[1 : len(addr)-1]
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip.String(), nil
	}
	if len(addr) > 253 || !hostnamePattern.MatchString(addr) {
		return "", fmt.Errorf("invalid host %q", addr)
	}
	return addr, nil
}
