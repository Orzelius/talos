package vm

import "net/netip"

func getLbBindIp(gateway netip.Addr) string {
	return "0.0.0.0"
}
