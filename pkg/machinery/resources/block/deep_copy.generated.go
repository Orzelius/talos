// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Code generated by "deep-copy -type DeviceSpec -type DiscoveredVolumeSpec -type DiscoveryRefreshRequestSpec -type DiscoveryRefreshStatusSpec -type DiskSpec -type SystemDiskSpec -type UserDiskConfigStatusSpec -type VolumeConfigSpec -type VolumeLifecycleSpec -type VolumeStatusSpec -header-file ../../../../hack/boilerplate.txt -o deep_copy.generated.go ."; DO NOT EDIT.

package block

// DeepCopy generates a deep copy of DeviceSpec.
func (o DeviceSpec) DeepCopy() DeviceSpec {
	var cp DeviceSpec = o
	if o.Secondaries != nil {
		cp.Secondaries = make([]string, len(o.Secondaries))
		copy(cp.Secondaries, o.Secondaries)
	}
	return cp
}

// DeepCopy generates a deep copy of DiscoveredVolumeSpec.
func (o DiscoveredVolumeSpec) DeepCopy() DiscoveredVolumeSpec {
	var cp DiscoveredVolumeSpec = o
	return cp
}

// DeepCopy generates a deep copy of DiscoveryRefreshRequestSpec.
func (o DiscoveryRefreshRequestSpec) DeepCopy() DiscoveryRefreshRequestSpec {
	var cp DiscoveryRefreshRequestSpec = o
	return cp
}

// DeepCopy generates a deep copy of DiscoveryRefreshStatusSpec.
func (o DiscoveryRefreshStatusSpec) DeepCopy() DiscoveryRefreshStatusSpec {
	var cp DiscoveryRefreshStatusSpec = o
	return cp
}

// DeepCopy generates a deep copy of DiskSpec.
func (o DiskSpec) DeepCopy() DiskSpec {
	var cp DiskSpec = o
	if o.SecondaryDisks != nil {
		cp.SecondaryDisks = make([]string, len(o.SecondaryDisks))
		copy(cp.SecondaryDisks, o.SecondaryDisks)
	}
	return cp
}

// DeepCopy generates a deep copy of SystemDiskSpec.
func (o SystemDiskSpec) DeepCopy() SystemDiskSpec {
	var cp SystemDiskSpec = o
	return cp
}

// DeepCopy generates a deep copy of UserDiskConfigStatusSpec.
func (o UserDiskConfigStatusSpec) DeepCopy() UserDiskConfigStatusSpec {
	var cp UserDiskConfigStatusSpec = o
	return cp
}

// DeepCopy generates a deep copy of VolumeConfigSpec.
func (o VolumeConfigSpec) DeepCopy() VolumeConfigSpec {
	var cp VolumeConfigSpec = o
	if o.Encryption.Keys != nil {
		cp.Encryption.Keys = make([]EncryptionKey, len(o.Encryption.Keys))
		copy(cp.Encryption.Keys, o.Encryption.Keys)
		for i3 := range o.Encryption.Keys {
			if o.Encryption.Keys[i3].StaticPassphrase != nil {
				cp.Encryption.Keys[i3].StaticPassphrase = make([]byte, len(o.Encryption.Keys[i3].StaticPassphrase))
				copy(cp.Encryption.Keys[i3].StaticPassphrase, o.Encryption.Keys[i3].StaticPassphrase)
			}
		}
	}
	if o.Encryption.PerfOptions != nil {
		cp.Encryption.PerfOptions = make([]string, len(o.Encryption.PerfOptions))
		copy(cp.Encryption.PerfOptions, o.Encryption.PerfOptions)
	}
	return cp
}

// DeepCopy generates a deep copy of VolumeLifecycleSpec.
func (o VolumeLifecycleSpec) DeepCopy() VolumeLifecycleSpec {
	var cp VolumeLifecycleSpec = o
	return cp
}

// DeepCopy generates a deep copy of VolumeStatusSpec.
func (o VolumeStatusSpec) DeepCopy() VolumeStatusSpec {
	var cp VolumeStatusSpec = o
	if o.EncryptionFailedSyncs != nil {
		cp.EncryptionFailedSyncs = make([]string, len(o.EncryptionFailedSyncs))
		copy(cp.EncryptionFailedSyncs, o.EncryptionFailedSyncs)
	}
	return cp
}
