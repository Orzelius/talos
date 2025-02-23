// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vm

import "strings"

func removeIpBindings(dhcpdLeasesContent string, ips []string) (string, error) {
	parts := strings.Split(dhcpdLeasesContent, "}\n")
	parts = parts[:len(parts)-1]
	withoutIps := ""

	for _, p := range parts {
		p += "}\n"
		containsIp := false

		for _, ip := range ips {
			if strings.Contains(p, "ip_address="+ip) {
				containsIp = true

				break
			}
		}

		if !containsIp {
			withoutIps += p
		}
	}

	return withoutIps, nil
}
