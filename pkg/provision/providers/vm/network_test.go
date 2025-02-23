// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vm //nolint:testpackage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetVmnetInterfaceNameNoVmnetInterface(t *testing.T) {
	interfaces := []string{
		"bridge", "bridge1", "eth0", "utun1", "bridge001", "bridge1001",
	}

	assert.Equal(t, "bridge100", getVmnetInterfaceName(interfaces))
}

func TestGetVmnetInterfaceNameWithExistingVmnetInterfaces(t *testing.T) {
	interfaces := []string{
		"bridge", "bridge1", "eth0", "utun1", "bridge001", "bridge1001", "bridge100", "bridge101", "bridge103",
	}

	assert.Equal(t, "bridge104", getVmnetInterfaceName(interfaces))
}
