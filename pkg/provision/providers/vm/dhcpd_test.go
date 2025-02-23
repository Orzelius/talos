// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vm //nolint:testpackage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoveIpBindings(t *testing.T) {
	const input = `{
    name=alpine
    ip_address=10.5.0.3
    hw_address=1,3e:9e:a3:74:b7:db
    identifier=1,3e:9e:a3:74:b7:db
    lease=0x67b6a739
}
{
    ip_address=10.7.7.7
    hw_address=1,52:c9:48:30:15:41
    identifier=1,52:c9:48:30:15:41
    lease=0x67b6a70b
    name=talos-orp-hj2
}
{
    ip_address=10.5.0.2
    hw_address=1,52:c9:48:30:15:41
    identifier=1,52:c9:48:30:15:41
    lease=0x67b6a70b
    name=talos-orp-hj2
}
{
    ip_address=10.6.6.6
    hw_address=1,52:c9:48:30:15:41
    identifier=1,52:c9:48:30:15:41
    lease=0x67b6a70b
    name=talos-orp-hj2
}
`

	result, err := removeIpBindings(input, []string{"10.5.0.3", "10.5.0.2"})
	assert.NoError(t, err)

	const expected = `{
    ip_address=10.7.7.7
    hw_address=1,52:c9:48:30:15:41
    identifier=1,52:c9:48:30:15:41
    lease=0x67b6a70b
    name=talos-orp-hj2
}
{
    ip_address=10.6.6.6
    hw_address=1,52:c9:48:30:15:41
    identifier=1,52:c9:48:30:15:41
    lease=0x67b6a70b
    name=talos-orp-hj2
}
`

	assert.Equal(t, expected, result)
}
