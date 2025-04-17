// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vm

import (
	"regexp"
	"strconv"
)

func getVmnetInterfaceName(allCurrentInterfaces []string) string {
	vmnetInterfaceFound := false
	largestVmnetIfIndex := 100
	vmnetInterfaceRegex := regexp.MustCompile(`\bbridge(1\d\d)\b`)

	for _, iface := range allCurrentInterfaces {
		matches := vmnetInterfaceRegex.FindSubmatch([]byte(iface))
		if matches != nil {
			vmnetInterfaceFound = true

			index, _ := strconv.Atoi(string(matches[1]))
			if index > largestVmnetIfIndex {
				largestVmnetIfIndex = index
			}
		}
	}

	if !vmnetInterfaceFound {
		return "bridge100"
	}

	return "bridge" + strconv.Itoa(largestVmnetIfIndex+1)
}
