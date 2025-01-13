package vm

import "net/netip"

func getLbBindIp(gateway netip.Addr) string {
	return gateway.String()
}
