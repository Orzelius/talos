// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package qemu

import (
	"context"
	"fmt"
	"os/exec"
)

// withCNI creates network namespace, launches CNI and passes control to the next function
// filling config with netNS and interface details.
//
//nolint:gocyclo
func withCNI(ctx context.Context, config *LaunchConfig, f func(config *LaunchConfig) error) error {
	fmt.Println("withCNI")
	return f(config)
}

func cmdStart(config *LaunchConfig, cmd *exec.Cmd) (bool, error) {
	return true, cmd.Start()
}
