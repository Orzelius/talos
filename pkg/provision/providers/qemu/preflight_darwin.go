// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package qemu

import (
	"context"
)

func (checkContext *preflightCheckContext) verifyPlatformSpecific(ctx context.Context) error {
	return nil
}

func checkKVM() (useKvm bool, err error) {
	return false, nil
}
