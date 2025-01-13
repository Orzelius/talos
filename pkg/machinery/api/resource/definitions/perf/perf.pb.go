// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v5.28.3
// source: resource/definitions/perf/perf.proto

package perf

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// CPUSpec represents the last CPU stats snapshot.
type CPUSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Cpu             []*CPUStat `protobuf:"bytes,1,rep,name=cpu,proto3" json:"cpu,omitempty"`
	CpuTotal        *CPUStat   `protobuf:"bytes,2,opt,name=cpu_total,json=cpuTotal,proto3" json:"cpu_total,omitempty"`
	IrqTotal        uint64     `protobuf:"varint,3,opt,name=irq_total,json=irqTotal,proto3" json:"irq_total,omitempty"`
	ContextSwitches uint64     `protobuf:"varint,4,opt,name=context_switches,json=contextSwitches,proto3" json:"context_switches,omitempty"`
	ProcessCreated  uint64     `protobuf:"varint,5,opt,name=process_created,json=processCreated,proto3" json:"process_created,omitempty"`
	ProcessRunning  uint64     `protobuf:"varint,6,opt,name=process_running,json=processRunning,proto3" json:"process_running,omitempty"`
	ProcessBlocked  uint64     `protobuf:"varint,7,opt,name=process_blocked,json=processBlocked,proto3" json:"process_blocked,omitempty"`
	SoftIrqTotal    uint64     `protobuf:"varint,8,opt,name=soft_irq_total,json=softIrqTotal,proto3" json:"soft_irq_total,omitempty"`
}

func (x *CPUSpec) Reset() {
	*x = CPUSpec{}
	mi := &file_resource_definitions_perf_perf_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CPUSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CPUSpec) ProtoMessage() {}

func (x *CPUSpec) ProtoReflect() protoreflect.Message {
	mi := &file_resource_definitions_perf_perf_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CPUSpec.ProtoReflect.Descriptor instead.
func (*CPUSpec) Descriptor() ([]byte, []int) {
	return file_resource_definitions_perf_perf_proto_rawDescGZIP(), []int{0}
}

func (x *CPUSpec) GetCpu() []*CPUStat {
	if x != nil {
		return x.Cpu
	}
	return nil
}

func (x *CPUSpec) GetCpuTotal() *CPUStat {
	if x != nil {
		return x.CpuTotal
	}
	return nil
}

func (x *CPUSpec) GetIrqTotal() uint64 {
	if x != nil {
		return x.IrqTotal
	}
	return 0
}

func (x *CPUSpec) GetContextSwitches() uint64 {
	if x != nil {
		return x.ContextSwitches
	}
	return 0
}

func (x *CPUSpec) GetProcessCreated() uint64 {
	if x != nil {
		return x.ProcessCreated
	}
	return 0
}

func (x *CPUSpec) GetProcessRunning() uint64 {
	if x != nil {
		return x.ProcessRunning
	}
	return 0
}

func (x *CPUSpec) GetProcessBlocked() uint64 {
	if x != nil {
		return x.ProcessBlocked
	}
	return 0
}

func (x *CPUSpec) GetSoftIrqTotal() uint64 {
	if x != nil {
		return x.SoftIrqTotal
	}
	return 0
}

// CPUStat represents a single cpu stat.
type CPUStat struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	User      float64 `protobuf:"fixed64,1,opt,name=user,proto3" json:"user,omitempty"`
	Nice      float64 `protobuf:"fixed64,2,opt,name=nice,proto3" json:"nice,omitempty"`
	System    float64 `protobuf:"fixed64,3,opt,name=system,proto3" json:"system,omitempty"`
	Idle      float64 `protobuf:"fixed64,4,opt,name=idle,proto3" json:"idle,omitempty"`
	Iowait    float64 `protobuf:"fixed64,5,opt,name=iowait,proto3" json:"iowait,omitempty"`
	Irq       float64 `protobuf:"fixed64,6,opt,name=irq,proto3" json:"irq,omitempty"`
	SoftIrq   float64 `protobuf:"fixed64,7,opt,name=soft_irq,json=softIrq,proto3" json:"soft_irq,omitempty"`
	Steal     float64 `protobuf:"fixed64,8,opt,name=steal,proto3" json:"steal,omitempty"`
	Guest     float64 `protobuf:"fixed64,9,opt,name=guest,proto3" json:"guest,omitempty"`
	GuestNice float64 `protobuf:"fixed64,10,opt,name=guest_nice,json=guestNice,proto3" json:"guest_nice,omitempty"`
}

func (x *CPUStat) Reset() {
	*x = CPUStat{}
	mi := &file_resource_definitions_perf_perf_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CPUStat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CPUStat) ProtoMessage() {}

func (x *CPUStat) ProtoReflect() protoreflect.Message {
	mi := &file_resource_definitions_perf_perf_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CPUStat.ProtoReflect.Descriptor instead.
func (*CPUStat) Descriptor() ([]byte, []int) {
	return file_resource_definitions_perf_perf_proto_rawDescGZIP(), []int{1}
}

func (x *CPUStat) GetUser() float64 {
	if x != nil {
		return x.User
	}
	return 0
}

func (x *CPUStat) GetNice() float64 {
	if x != nil {
		return x.Nice
	}
	return 0
}

func (x *CPUStat) GetSystem() float64 {
	if x != nil {
		return x.System
	}
	return 0
}

func (x *CPUStat) GetIdle() float64 {
	if x != nil {
		return x.Idle
	}
	return 0
}

func (x *CPUStat) GetIowait() float64 {
	if x != nil {
		return x.Iowait
	}
	return 0
}

func (x *CPUStat) GetIrq() float64 {
	if x != nil {
		return x.Irq
	}
	return 0
}

func (x *CPUStat) GetSoftIrq() float64 {
	if x != nil {
		return x.SoftIrq
	}
	return 0
}

func (x *CPUStat) GetSteal() float64 {
	if x != nil {
		return x.Steal
	}
	return 0
}

func (x *CPUStat) GetGuest() float64 {
	if x != nil {
		return x.Guest
	}
	return 0
}

func (x *CPUStat) GetGuestNice() float64 {
	if x != nil {
		return x.GuestNice
	}
	return 0
}

// MemorySpec represents the last Memory stats snapshot.
type MemorySpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MemTotal          uint64 `protobuf:"varint,1,opt,name=mem_total,json=memTotal,proto3" json:"mem_total,omitempty"`
	MemUsed           uint64 `protobuf:"varint,2,opt,name=mem_used,json=memUsed,proto3" json:"mem_used,omitempty"`
	MemAvailable      uint64 `protobuf:"varint,3,opt,name=mem_available,json=memAvailable,proto3" json:"mem_available,omitempty"`
	Buffers           uint64 `protobuf:"varint,4,opt,name=buffers,proto3" json:"buffers,omitempty"`
	Cached            uint64 `protobuf:"varint,5,opt,name=cached,proto3" json:"cached,omitempty"`
	SwapCached        uint64 `protobuf:"varint,6,opt,name=swap_cached,json=swapCached,proto3" json:"swap_cached,omitempty"`
	Active            uint64 `protobuf:"varint,7,opt,name=active,proto3" json:"active,omitempty"`
	Inactive          uint64 `protobuf:"varint,8,opt,name=inactive,proto3" json:"inactive,omitempty"`
	ActiveAnon        uint64 `protobuf:"varint,9,opt,name=active_anon,json=activeAnon,proto3" json:"active_anon,omitempty"`
	InactiveAnon      uint64 `protobuf:"varint,10,opt,name=inactive_anon,json=inactiveAnon,proto3" json:"inactive_anon,omitempty"`
	ActiveFile        uint64 `protobuf:"varint,11,opt,name=active_file,json=activeFile,proto3" json:"active_file,omitempty"`
	InactiveFile      uint64 `protobuf:"varint,12,opt,name=inactive_file,json=inactiveFile,proto3" json:"inactive_file,omitempty"`
	Unevictable       uint64 `protobuf:"varint,13,opt,name=unevictable,proto3" json:"unevictable,omitempty"`
	Mlocked           uint64 `protobuf:"varint,14,opt,name=mlocked,proto3" json:"mlocked,omitempty"`
	SwapTotal         uint64 `protobuf:"varint,15,opt,name=swap_total,json=swapTotal,proto3" json:"swap_total,omitempty"`
	SwapFree          uint64 `protobuf:"varint,16,opt,name=swap_free,json=swapFree,proto3" json:"swap_free,omitempty"`
	Dirty             uint64 `protobuf:"varint,17,opt,name=dirty,proto3" json:"dirty,omitempty"`
	Writeback         uint64 `protobuf:"varint,18,opt,name=writeback,proto3" json:"writeback,omitempty"`
	AnonPages         uint64 `protobuf:"varint,19,opt,name=anon_pages,json=anonPages,proto3" json:"anon_pages,omitempty"`
	Mapped            uint64 `protobuf:"varint,20,opt,name=mapped,proto3" json:"mapped,omitempty"`
	Shmem             uint64 `protobuf:"varint,21,opt,name=shmem,proto3" json:"shmem,omitempty"`
	Slab              uint64 `protobuf:"varint,22,opt,name=slab,proto3" json:"slab,omitempty"`
	SReclaimable      uint64 `protobuf:"varint,23,opt,name=s_reclaimable,json=sReclaimable,proto3" json:"s_reclaimable,omitempty"`
	SUnreclaim        uint64 `protobuf:"varint,24,opt,name=s_unreclaim,json=sUnreclaim,proto3" json:"s_unreclaim,omitempty"`
	KernelStack       uint64 `protobuf:"varint,25,opt,name=kernel_stack,json=kernelStack,proto3" json:"kernel_stack,omitempty"`
	PageTables        uint64 `protobuf:"varint,26,opt,name=page_tables,json=pageTables,proto3" json:"page_tables,omitempty"`
	NfSunstable       uint64 `protobuf:"varint,27,opt,name=nf_sunstable,json=nfSunstable,proto3" json:"nf_sunstable,omitempty"`
	Bounce            uint64 `protobuf:"varint,28,opt,name=bounce,proto3" json:"bounce,omitempty"`
	WritebackTmp      uint64 `protobuf:"varint,29,opt,name=writeback_tmp,json=writebackTmp,proto3" json:"writeback_tmp,omitempty"`
	CommitLimit       uint64 `protobuf:"varint,30,opt,name=commit_limit,json=commitLimit,proto3" json:"commit_limit,omitempty"`
	CommittedAs       uint64 `protobuf:"varint,31,opt,name=committed_as,json=committedAs,proto3" json:"committed_as,omitempty"`
	VmallocTotal      uint64 `protobuf:"varint,32,opt,name=vmalloc_total,json=vmallocTotal,proto3" json:"vmalloc_total,omitempty"`
	VmallocUsed       uint64 `protobuf:"varint,33,opt,name=vmalloc_used,json=vmallocUsed,proto3" json:"vmalloc_used,omitempty"`
	VmallocChunk      uint64 `protobuf:"varint,34,opt,name=vmalloc_chunk,json=vmallocChunk,proto3" json:"vmalloc_chunk,omitempty"`
	HardwareCorrupted uint64 `protobuf:"varint,35,opt,name=hardware_corrupted,json=hardwareCorrupted,proto3" json:"hardware_corrupted,omitempty"`
	AnonHugePages     uint64 `protobuf:"varint,36,opt,name=anon_huge_pages,json=anonHugePages,proto3" json:"anon_huge_pages,omitempty"`
	ShmemHugePages    uint64 `protobuf:"varint,37,opt,name=shmem_huge_pages,json=shmemHugePages,proto3" json:"shmem_huge_pages,omitempty"`
	ShmemPmdMapped    uint64 `protobuf:"varint,38,opt,name=shmem_pmd_mapped,json=shmemPmdMapped,proto3" json:"shmem_pmd_mapped,omitempty"`
	CmaTotal          uint64 `protobuf:"varint,39,opt,name=cma_total,json=cmaTotal,proto3" json:"cma_total,omitempty"`
	CmaFree           uint64 `protobuf:"varint,40,opt,name=cma_free,json=cmaFree,proto3" json:"cma_free,omitempty"`
	HugePagesTotal    uint64 `protobuf:"varint,41,opt,name=huge_pages_total,json=hugePagesTotal,proto3" json:"huge_pages_total,omitempty"`
	HugePagesFree     uint64 `protobuf:"varint,42,opt,name=huge_pages_free,json=hugePagesFree,proto3" json:"huge_pages_free,omitempty"`
	HugePagesRsvd     uint64 `protobuf:"varint,43,opt,name=huge_pages_rsvd,json=hugePagesRsvd,proto3" json:"huge_pages_rsvd,omitempty"`
	HugePagesSurp     uint64 `protobuf:"varint,44,opt,name=huge_pages_surp,json=hugePagesSurp,proto3" json:"huge_pages_surp,omitempty"`
	Hugepagesize      uint64 `protobuf:"varint,45,opt,name=hugepagesize,proto3" json:"hugepagesize,omitempty"`
	DirectMap4K       uint64 `protobuf:"varint,46,opt,name=direct_map4k,json=directMap4k,proto3" json:"direct_map4k,omitempty"`
	DirectMap2M       uint64 `protobuf:"varint,47,opt,name=direct_map2m,json=directMap2m,proto3" json:"direct_map2m,omitempty"`
	DirectMap1G       uint64 `protobuf:"varint,48,opt,name=direct_map1g,json=directMap1g,proto3" json:"direct_map1g,omitempty"`
}

func (x *MemorySpec) Reset() {
	*x = MemorySpec{}
	mi := &file_resource_definitions_perf_perf_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MemorySpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MemorySpec) ProtoMessage() {}

func (x *MemorySpec) ProtoReflect() protoreflect.Message {
	mi := &file_resource_definitions_perf_perf_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MemorySpec.ProtoReflect.Descriptor instead.
func (*MemorySpec) Descriptor() ([]byte, []int) {
	return file_resource_definitions_perf_perf_proto_rawDescGZIP(), []int{2}
}

func (x *MemorySpec) GetMemTotal() uint64 {
	if x != nil {
		return x.MemTotal
	}
	return 0
}

func (x *MemorySpec) GetMemUsed() uint64 {
	if x != nil {
		return x.MemUsed
	}
	return 0
}

func (x *MemorySpec) GetMemAvailable() uint64 {
	if x != nil {
		return x.MemAvailable
	}
	return 0
}

func (x *MemorySpec) GetBuffers() uint64 {
	if x != nil {
		return x.Buffers
	}
	return 0
}

func (x *MemorySpec) GetCached() uint64 {
	if x != nil {
		return x.Cached
	}
	return 0
}

func (x *MemorySpec) GetSwapCached() uint64 {
	if x != nil {
		return x.SwapCached
	}
	return 0
}

func (x *MemorySpec) GetActive() uint64 {
	if x != nil {
		return x.Active
	}
	return 0
}

func (x *MemorySpec) GetInactive() uint64 {
	if x != nil {
		return x.Inactive
	}
	return 0
}

func (x *MemorySpec) GetActiveAnon() uint64 {
	if x != nil {
		return x.ActiveAnon
	}
	return 0
}

func (x *MemorySpec) GetInactiveAnon() uint64 {
	if x != nil {
		return x.InactiveAnon
	}
	return 0
}

func (x *MemorySpec) GetActiveFile() uint64 {
	if x != nil {
		return x.ActiveFile
	}
	return 0
}

func (x *MemorySpec) GetInactiveFile() uint64 {
	if x != nil {
		return x.InactiveFile
	}
	return 0
}

func (x *MemorySpec) GetUnevictable() uint64 {
	if x != nil {
		return x.Unevictable
	}
	return 0
}

func (x *MemorySpec) GetMlocked() uint64 {
	if x != nil {
		return x.Mlocked
	}
	return 0
}

func (x *MemorySpec) GetSwapTotal() uint64 {
	if x != nil {
		return x.SwapTotal
	}
	return 0
}

func (x *MemorySpec) GetSwapFree() uint64 {
	if x != nil {
		return x.SwapFree
	}
	return 0
}

func (x *MemorySpec) GetDirty() uint64 {
	if x != nil {
		return x.Dirty
	}
	return 0
}

func (x *MemorySpec) GetWriteback() uint64 {
	if x != nil {
		return x.Writeback
	}
	return 0
}

func (x *MemorySpec) GetAnonPages() uint64 {
	if x != nil {
		return x.AnonPages
	}
	return 0
}

func (x *MemorySpec) GetMapped() uint64 {
	if x != nil {
		return x.Mapped
	}
	return 0
}

func (x *MemorySpec) GetShmem() uint64 {
	if x != nil {
		return x.Shmem
	}
	return 0
}

func (x *MemorySpec) GetSlab() uint64 {
	if x != nil {
		return x.Slab
	}
	return 0
}

func (x *MemorySpec) GetSReclaimable() uint64 {
	if x != nil {
		return x.SReclaimable
	}
	return 0
}

func (x *MemorySpec) GetSUnreclaim() uint64 {
	if x != nil {
		return x.SUnreclaim
	}
	return 0
}

func (x *MemorySpec) GetKernelStack() uint64 {
	if x != nil {
		return x.KernelStack
	}
	return 0
}

func (x *MemorySpec) GetPageTables() uint64 {
	if x != nil {
		return x.PageTables
	}
	return 0
}

func (x *MemorySpec) GetNfSunstable() uint64 {
	if x != nil {
		return x.NfSunstable
	}
	return 0
}

func (x *MemorySpec) GetBounce() uint64 {
	if x != nil {
		return x.Bounce
	}
	return 0
}

func (x *MemorySpec) GetWritebackTmp() uint64 {
	if x != nil {
		return x.WritebackTmp
	}
	return 0
}

func (x *MemorySpec) GetCommitLimit() uint64 {
	if x != nil {
		return x.CommitLimit
	}
	return 0
}

func (x *MemorySpec) GetCommittedAs() uint64 {
	if x != nil {
		return x.CommittedAs
	}
	return 0
}

func (x *MemorySpec) GetVmallocTotal() uint64 {
	if x != nil {
		return x.VmallocTotal
	}
	return 0
}

func (x *MemorySpec) GetVmallocUsed() uint64 {
	if x != nil {
		return x.VmallocUsed
	}
	return 0
}

func (x *MemorySpec) GetVmallocChunk() uint64 {
	if x != nil {
		return x.VmallocChunk
	}
	return 0
}

func (x *MemorySpec) GetHardwareCorrupted() uint64 {
	if x != nil {
		return x.HardwareCorrupted
	}
	return 0
}

func (x *MemorySpec) GetAnonHugePages() uint64 {
	if x != nil {
		return x.AnonHugePages
	}
	return 0
}

func (x *MemorySpec) GetShmemHugePages() uint64 {
	if x != nil {
		return x.ShmemHugePages
	}
	return 0
}

func (x *MemorySpec) GetShmemPmdMapped() uint64 {
	if x != nil {
		return x.ShmemPmdMapped
	}
	return 0
}

func (x *MemorySpec) GetCmaTotal() uint64 {
	if x != nil {
		return x.CmaTotal
	}
	return 0
}

func (x *MemorySpec) GetCmaFree() uint64 {
	if x != nil {
		return x.CmaFree
	}
	return 0
}

func (x *MemorySpec) GetHugePagesTotal() uint64 {
	if x != nil {
		return x.HugePagesTotal
	}
	return 0
}

func (x *MemorySpec) GetHugePagesFree() uint64 {
	if x != nil {
		return x.HugePagesFree
	}
	return 0
}

func (x *MemorySpec) GetHugePagesRsvd() uint64 {
	if x != nil {
		return x.HugePagesRsvd
	}
	return 0
}

func (x *MemorySpec) GetHugePagesSurp() uint64 {
	if x != nil {
		return x.HugePagesSurp
	}
	return 0
}

func (x *MemorySpec) GetHugepagesize() uint64 {
	if x != nil {
		return x.Hugepagesize
	}
	return 0
}

func (x *MemorySpec) GetDirectMap4K() uint64 {
	if x != nil {
		return x.DirectMap4K
	}
	return 0
}

func (x *MemorySpec) GetDirectMap2M() uint64 {
	if x != nil {
		return x.DirectMap2M
	}
	return 0
}

func (x *MemorySpec) GetDirectMap1G() uint64 {
	if x != nil {
		return x.DirectMap1G
	}
	return 0
}

var File_resource_definitions_perf_perf_proto protoreflect.FileDescriptor

var file_resource_definitions_perf_perf_proto_rawDesc = []byte{
	0x0a, 0x24, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2f, 0x64, 0x65, 0x66, 0x69, 0x6e,
	0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x70, 0x65, 0x72, 0x66, 0x2f, 0x70, 0x65, 0x72, 0x66,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1f, 0x74, 0x61, 0x6c, 0x6f, 0x73, 0x2e, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x70, 0x65, 0x72, 0x66, 0x22, 0xf5, 0x02, 0x0a, 0x07, 0x43, 0x50, 0x55, 0x53,
	0x70, 0x65, 0x63, 0x12, 0x3a, 0x0a, 0x03, 0x63, 0x70, 0x75, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x28, 0x2e, 0x74, 0x61, 0x6c, 0x6f, 0x73, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x2e, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x65,
	0x72, 0x66, 0x2e, 0x43, 0x50, 0x55, 0x53, 0x74, 0x61, 0x74, 0x52, 0x03, 0x63, 0x70, 0x75, 0x12,
	0x45, 0x0a, 0x09, 0x63, 0x70, 0x75, 0x5f, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x28, 0x2e, 0x74, 0x61, 0x6c, 0x6f, 0x73, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x2e, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x70, 0x65, 0x72, 0x66, 0x2e, 0x43, 0x50, 0x55, 0x53, 0x74, 0x61, 0x74, 0x52, 0x08, 0x63, 0x70,
	0x75, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x1b, 0x0a, 0x09, 0x69, 0x72, 0x71, 0x5f, 0x74, 0x6f,
	0x74, 0x61, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x69, 0x72, 0x71, 0x54, 0x6f,
	0x74, 0x61, 0x6c, 0x12, 0x29, 0x0a, 0x10, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x5f, 0x73,
	0x77, 0x69, 0x74, 0x63, 0x68, 0x65, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0f, 0x63,
	0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x65, 0x73, 0x12, 0x27,
	0x0a, 0x0f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0e, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x12, 0x27, 0x0a, 0x0f, 0x70, 0x72, 0x6f, 0x63, 0x65,
	0x73, 0x73, 0x5f, 0x72, 0x75, 0x6e, 0x6e, 0x69, 0x6e, 0x67, 0x18, 0x06, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x0e, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x52, 0x75, 0x6e, 0x6e, 0x69, 0x6e, 0x67,
	0x12, 0x27, 0x0a, 0x0f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x65, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0e, 0x70, 0x72, 0x6f, 0x63, 0x65,
	0x73, 0x73, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x12, 0x24, 0x0a, 0x0e, 0x73, 0x6f, 0x66,
	0x74, 0x5f, 0x69, 0x72, 0x71, 0x5f, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x0c, 0x73, 0x6f, 0x66, 0x74, 0x49, 0x72, 0x71, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x22,
	0xed, 0x01, 0x0a, 0x07, 0x43, 0x50, 0x55, 0x53, 0x74, 0x61, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x75,
	0x73, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x01, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x12,
	0x12, 0x0a, 0x04, 0x6e, 0x69, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x01, 0x52, 0x04, 0x6e,
	0x69, 0x63, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x01, 0x52, 0x06, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x12, 0x12, 0x0a, 0x04, 0x69,
	0x64, 0x6c, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x01, 0x52, 0x04, 0x69, 0x64, 0x6c, 0x65, 0x12,
	0x16, 0x0a, 0x06, 0x69, 0x6f, 0x77, 0x61, 0x69, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x01, 0x52,
	0x06, 0x69, 0x6f, 0x77, 0x61, 0x69, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x69, 0x72, 0x71, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x01, 0x52, 0x03, 0x69, 0x72, 0x71, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x6f, 0x66,
	0x74, 0x5f, 0x69, 0x72, 0x71, 0x18, 0x07, 0x20, 0x01, 0x28, 0x01, 0x52, 0x07, 0x73, 0x6f, 0x66,
	0x74, 0x49, 0x72, 0x71, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x74, 0x65, 0x61, 0x6c, 0x18, 0x08, 0x20,
	0x01, 0x28, 0x01, 0x52, 0x05, 0x73, 0x74, 0x65, 0x61, 0x6c, 0x12, 0x14, 0x0a, 0x05, 0x67, 0x75,
	0x65, 0x73, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x01, 0x52, 0x05, 0x67, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x1d, 0x0a, 0x0a, 0x67, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x6e, 0x69, 0x63, 0x65, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x01, 0x52, 0x09, 0x67, 0x75, 0x65, 0x73, 0x74, 0x4e, 0x69, 0x63, 0x65, 0x22,
	0xb8, 0x0c, 0x0a, 0x0a, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x53, 0x70, 0x65, 0x63, 0x12, 0x1b,
	0x0a, 0x09, 0x6d, 0x65, 0x6d, 0x5f, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x08, 0x6d, 0x65, 0x6d, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x19, 0x0a, 0x08, 0x6d,
	0x65, 0x6d, 0x5f, 0x75, 0x73, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x6d,
	0x65, 0x6d, 0x55, 0x73, 0x65, 0x64, 0x12, 0x23, 0x0a, 0x0d, 0x6d, 0x65, 0x6d, 0x5f, 0x61, 0x76,
	0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0c, 0x6d,
	0x65, 0x6d, 0x41, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x62,
	0x75, 0x66, 0x66, 0x65, 0x72, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x62, 0x75,
	0x66, 0x66, 0x65, 0x72, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x63, 0x61, 0x63, 0x68, 0x65, 0x64, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06, 0x63, 0x61, 0x63, 0x68, 0x65, 0x64, 0x12, 0x1f, 0x0a,
	0x0b, 0x73, 0x77, 0x61, 0x70, 0x5f, 0x63, 0x61, 0x63, 0x68, 0x65, 0x64, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x0a, 0x73, 0x77, 0x61, 0x70, 0x43, 0x61, 0x63, 0x68, 0x65, 0x64, 0x12, 0x16,
	0x0a, 0x06, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06,
	0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69,
	0x76, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69,
	0x76, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x61, 0x6e, 0x6f,
	0x6e, 0x18, 0x09, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x41,
	0x6e, 0x6f, 0x6e, 0x12, 0x23, 0x0a, 0x0d, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x5f,
	0x61, 0x6e, 0x6f, 0x6e, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0c, 0x69, 0x6e, 0x61, 0x63,
	0x74, 0x69, 0x76, 0x65, 0x41, 0x6e, 0x6f, 0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x61, 0x63, 0x74, 0x69,
	0x76, 0x65, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x61,
	0x63, 0x74, 0x69, 0x76, 0x65, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x23, 0x0a, 0x0d, 0x69, 0x6e, 0x61,
	0x63, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x0c, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x20,
	0x0a, 0x0b, 0x75, 0x6e, 0x65, 0x76, 0x69, 0x63, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x18, 0x0d, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x0b, 0x75, 0x6e, 0x65, 0x76, 0x69, 0x63, 0x74, 0x61, 0x62, 0x6c, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x6d, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x18, 0x0e, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x07, 0x6d, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x77,
	0x61, 0x70, 0x5f, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09,
	0x73, 0x77, 0x61, 0x70, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x1b, 0x0a, 0x09, 0x73, 0x77, 0x61,
	0x70, 0x5f, 0x66, 0x72, 0x65, 0x65, 0x18, 0x10, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x73, 0x77,
	0x61, 0x70, 0x46, 0x72, 0x65, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x69, 0x72, 0x74, 0x79, 0x18,
	0x11, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x64, 0x69, 0x72, 0x74, 0x79, 0x12, 0x1c, 0x0a, 0x09,
	0x77, 0x72, 0x69, 0x74, 0x65, 0x62, 0x61, 0x63, 0x6b, 0x18, 0x12, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x09, 0x77, 0x72, 0x69, 0x74, 0x65, 0x62, 0x61, 0x63, 0x6b, 0x12, 0x1d, 0x0a, 0x0a, 0x61, 0x6e,
	0x6f, 0x6e, 0x5f, 0x70, 0x61, 0x67, 0x65, 0x73, 0x18, 0x13, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09,
	0x61, 0x6e, 0x6f, 0x6e, 0x50, 0x61, 0x67, 0x65, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x6d, 0x61, 0x70,
	0x70, 0x65, 0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06, 0x6d, 0x61, 0x70, 0x70, 0x65,
	0x64, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x68, 0x6d, 0x65, 0x6d, 0x18, 0x15, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x05, 0x73, 0x68, 0x6d, 0x65, 0x6d, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x6c, 0x61, 0x62, 0x18,
	0x16, 0x20, 0x01, 0x28, 0x04, 0x52, 0x04, 0x73, 0x6c, 0x61, 0x62, 0x12, 0x23, 0x0a, 0x0d, 0x73,
	0x5f, 0x72, 0x65, 0x63, 0x6c, 0x61, 0x69, 0x6d, 0x61, 0x62, 0x6c, 0x65, 0x18, 0x17, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x0c, 0x73, 0x52, 0x65, 0x63, 0x6c, 0x61, 0x69, 0x6d, 0x61, 0x62, 0x6c, 0x65,
	0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x5f, 0x75, 0x6e, 0x72, 0x65, 0x63, 0x6c, 0x61, 0x69, 0x6d, 0x18,
	0x18, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x73, 0x55, 0x6e, 0x72, 0x65, 0x63, 0x6c, 0x61, 0x69,
	0x6d, 0x12, 0x21, 0x0a, 0x0c, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x5f, 0x73, 0x74, 0x61, 0x63,
	0x6b, 0x18, 0x19, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x53,
	0x74, 0x61, 0x63, 0x6b, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x61, 0x62,
	0x6c, 0x65, 0x73, 0x18, 0x1a, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x70, 0x61, 0x67, 0x65, 0x54,
	0x61, 0x62, 0x6c, 0x65, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x6e, 0x66, 0x5f, 0x73, 0x75, 0x6e, 0x73,
	0x74, 0x61, 0x62, 0x6c, 0x65, 0x18, 0x1b, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x6e, 0x66, 0x53,
	0x75, 0x6e, 0x73, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x62, 0x6f, 0x75, 0x6e,
	0x63, 0x65, 0x18, 0x1c, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06, 0x62, 0x6f, 0x75, 0x6e, 0x63, 0x65,
	0x12, 0x23, 0x0a, 0x0d, 0x77, 0x72, 0x69, 0x74, 0x65, 0x62, 0x61, 0x63, 0x6b, 0x5f, 0x74, 0x6d,
	0x70, 0x18, 0x1d, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0c, 0x77, 0x72, 0x69, 0x74, 0x65, 0x62, 0x61,
	0x63, 0x6b, 0x54, 0x6d, 0x70, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x5f,
	0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x63, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d,
	0x69, 0x74, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x73, 0x18, 0x1f, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b,
	0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x74, 0x65, 0x64, 0x41, 0x73, 0x12, 0x23, 0x0a, 0x0d, 0x76,
	0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x5f, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x20, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x0c, 0x76, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x54, 0x6f, 0x74, 0x61, 0x6c,
	0x12, 0x21, 0x0a, 0x0c, 0x76, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x5f, 0x75, 0x73, 0x65, 0x64,
	0x18, 0x21, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x76, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x55,
	0x73, 0x65, 0x64, 0x12, 0x23, 0x0a, 0x0d, 0x76, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x5f, 0x63,
	0x68, 0x75, 0x6e, 0x6b, 0x18, 0x22, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0c, 0x76, 0x6d, 0x61, 0x6c,
	0x6c, 0x6f, 0x63, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x12, 0x2d, 0x0a, 0x12, 0x68, 0x61, 0x72, 0x64,
	0x77, 0x61, 0x72, 0x65, 0x5f, 0x63, 0x6f, 0x72, 0x72, 0x75, 0x70, 0x74, 0x65, 0x64, 0x18, 0x23,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x11, 0x68, 0x61, 0x72, 0x64, 0x77, 0x61, 0x72, 0x65, 0x43, 0x6f,
	0x72, 0x72, 0x75, 0x70, 0x74, 0x65, 0x64, 0x12, 0x26, 0x0a, 0x0f, 0x61, 0x6e, 0x6f, 0x6e, 0x5f,
	0x68, 0x75, 0x67, 0x65, 0x5f, 0x70, 0x61, 0x67, 0x65, 0x73, 0x18, 0x24, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x0d, 0x61, 0x6e, 0x6f, 0x6e, 0x48, 0x75, 0x67, 0x65, 0x50, 0x61, 0x67, 0x65, 0x73, 0x12,
	0x28, 0x0a, 0x10, 0x73, 0x68, 0x6d, 0x65, 0x6d, 0x5f, 0x68, 0x75, 0x67, 0x65, 0x5f, 0x70, 0x61,
	0x67, 0x65, 0x73, 0x18, 0x25, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0e, 0x73, 0x68, 0x6d, 0x65, 0x6d,
	0x48, 0x75, 0x67, 0x65, 0x50, 0x61, 0x67, 0x65, 0x73, 0x12, 0x28, 0x0a, 0x10, 0x73, 0x68, 0x6d,
	0x65, 0x6d, 0x5f, 0x70, 0x6d, 0x64, 0x5f, 0x6d, 0x61, 0x70, 0x70, 0x65, 0x64, 0x18, 0x26, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x0e, 0x73, 0x68, 0x6d, 0x65, 0x6d, 0x50, 0x6d, 0x64, 0x4d, 0x61, 0x70,
	0x70, 0x65, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6d, 0x61, 0x5f, 0x74, 0x6f, 0x74, 0x61, 0x6c,
	0x18, 0x27, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x63, 0x6d, 0x61, 0x54, 0x6f, 0x74, 0x61, 0x6c,
	0x12, 0x19, 0x0a, 0x08, 0x63, 0x6d, 0x61, 0x5f, 0x66, 0x72, 0x65, 0x65, 0x18, 0x28, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x07, 0x63, 0x6d, 0x61, 0x46, 0x72, 0x65, 0x65, 0x12, 0x28, 0x0a, 0x10, 0x68,
	0x75, 0x67, 0x65, 0x5f, 0x70, 0x61, 0x67, 0x65, 0x73, 0x5f, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x18,
	0x29, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0e, 0x68, 0x75, 0x67, 0x65, 0x50, 0x61, 0x67, 0x65, 0x73,
	0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x26, 0x0a, 0x0f, 0x68, 0x75, 0x67, 0x65, 0x5f, 0x70, 0x61,
	0x67, 0x65, 0x73, 0x5f, 0x66, 0x72, 0x65, 0x65, 0x18, 0x2a, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0d,
	0x68, 0x75, 0x67, 0x65, 0x50, 0x61, 0x67, 0x65, 0x73, 0x46, 0x72, 0x65, 0x65, 0x12, 0x26, 0x0a,
	0x0f, 0x68, 0x75, 0x67, 0x65, 0x5f, 0x70, 0x61, 0x67, 0x65, 0x73, 0x5f, 0x72, 0x73, 0x76, 0x64,
	0x18, 0x2b, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0d, 0x68, 0x75, 0x67, 0x65, 0x50, 0x61, 0x67, 0x65,
	0x73, 0x52, 0x73, 0x76, 0x64, 0x12, 0x26, 0x0a, 0x0f, 0x68, 0x75, 0x67, 0x65, 0x5f, 0x70, 0x61,
	0x67, 0x65, 0x73, 0x5f, 0x73, 0x75, 0x72, 0x70, 0x18, 0x2c, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0d,
	0x68, 0x75, 0x67, 0x65, 0x50, 0x61, 0x67, 0x65, 0x73, 0x53, 0x75, 0x72, 0x70, 0x12, 0x22, 0x0a,
	0x0c, 0x68, 0x75, 0x67, 0x65, 0x70, 0x61, 0x67, 0x65, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x2d, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x0c, 0x68, 0x75, 0x67, 0x65, 0x70, 0x61, 0x67, 0x65, 0x73, 0x69, 0x7a,
	0x65, 0x12, 0x21, 0x0a, 0x0c, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x5f, 0x6d, 0x61, 0x70, 0x34,
	0x6b, 0x18, 0x2e, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x4d,
	0x61, 0x70, 0x34, 0x6b, 0x12, 0x21, 0x0a, 0x0c, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x5f, 0x6d,
	0x61, 0x70, 0x32, 0x6d, 0x18, 0x2f, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x64, 0x69, 0x72, 0x65,
	0x63, 0x74, 0x4d, 0x61, 0x70, 0x32, 0x6d, 0x12, 0x21, 0x0a, 0x0c, 0x64, 0x69, 0x72, 0x65, 0x63,
	0x74, 0x5f, 0x6d, 0x61, 0x70, 0x31, 0x67, 0x18, 0x30, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x64,
	0x69, 0x72, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x31, 0x67, 0x42, 0x72, 0x0a, 0x27, 0x64, 0x65,
	0x76, 0x2e, 0x74, 0x61, 0x6c, 0x6f, 0x73, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x2e, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x70, 0x65, 0x72, 0x66, 0x5a, 0x47, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x73, 0x69, 0x64, 0x65, 0x72, 0x6f, 0x6c, 0x61, 0x62, 0x73, 0x2f, 0x74, 0x61, 0x6c,
	0x6f, 0x73, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x72, 0x79,
	0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2f, 0x64, 0x65,
	0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x70, 0x65, 0x72, 0x66, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_resource_definitions_perf_perf_proto_rawDescOnce sync.Once
	file_resource_definitions_perf_perf_proto_rawDescData = file_resource_definitions_perf_perf_proto_rawDesc
)

func file_resource_definitions_perf_perf_proto_rawDescGZIP() []byte {
	file_resource_definitions_perf_perf_proto_rawDescOnce.Do(func() {
		file_resource_definitions_perf_perf_proto_rawDescData = protoimpl.X.CompressGZIP(file_resource_definitions_perf_perf_proto_rawDescData)
	})
	return file_resource_definitions_perf_perf_proto_rawDescData
}

var file_resource_definitions_perf_perf_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_resource_definitions_perf_perf_proto_goTypes = []any{
	(*CPUSpec)(nil),    // 0: talos.resource.definitions.perf.CPUSpec
	(*CPUStat)(nil),    // 1: talos.resource.definitions.perf.CPUStat
	(*MemorySpec)(nil), // 2: talos.resource.definitions.perf.MemorySpec
}
var file_resource_definitions_perf_perf_proto_depIdxs = []int32{
	1, // 0: talos.resource.definitions.perf.CPUSpec.cpu:type_name -> talos.resource.definitions.perf.CPUStat
	1, // 1: talos.resource.definitions.perf.CPUSpec.cpu_total:type_name -> talos.resource.definitions.perf.CPUStat
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_resource_definitions_perf_perf_proto_init() }
func file_resource_definitions_perf_perf_proto_init() {
	if File_resource_definitions_perf_perf_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_resource_definitions_perf_perf_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_resource_definitions_perf_perf_proto_goTypes,
		DependencyIndexes: file_resource_definitions_perf_perf_proto_depIdxs,
		MessageInfos:      file_resource_definitions_perf_perf_proto_msgTypes,
	}.Build()
	File_resource_definitions_perf_perf_proto = out.File
	file_resource_definitions_perf_perf_proto_rawDesc = nil
	file_resource_definitions_perf_perf_proto_goTypes = nil
	file_resource_definitions_perf_perf_proto_depIdxs = nil
}
