// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: xsuportal/services/bench/receiving.proto

package bench

import (
	proto "github.com/golang/protobuf/proto"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type ReceiveBenchmarkJobRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// string token = 1;
	// string instance_name = 2;
	TeamId int64 `protobuf:"varint,3,opt,name=team_id,json=teamId,proto3" json:"team_id,omitempty"`
}

func (x *ReceiveBenchmarkJobRequest) Reset() {
	*x = ReceiveBenchmarkJobRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_xsuportal_services_bench_receiving_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReceiveBenchmarkJobRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReceiveBenchmarkJobRequest) ProtoMessage() {}

func (x *ReceiveBenchmarkJobRequest) ProtoReflect() protoreflect.Message {
	mi := &file_xsuportal_services_bench_receiving_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReceiveBenchmarkJobRequest.ProtoReflect.Descriptor instead.
func (*ReceiveBenchmarkJobRequest) Descriptor() ([]byte, []int) {
	return file_xsuportal_services_bench_receiving_proto_rawDescGZIP(), []int{0}
}

func (x *ReceiveBenchmarkJobRequest) GetTeamId() int64 {
	if x != nil {
		return x.TeamId
	}
	return 0
}

type ReceiveBenchmarkJobResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// optional
	JobHandle *ReceiveBenchmarkJobResponse_JobHandle `protobuf:"bytes,1,opt,name=job_handle,json=jobHandle,proto3" json:"job_handle,omitempty"`
}

func (x *ReceiveBenchmarkJobResponse) Reset() {
	*x = ReceiveBenchmarkJobResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_xsuportal_services_bench_receiving_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReceiveBenchmarkJobResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReceiveBenchmarkJobResponse) ProtoMessage() {}

func (x *ReceiveBenchmarkJobResponse) ProtoReflect() protoreflect.Message {
	mi := &file_xsuportal_services_bench_receiving_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReceiveBenchmarkJobResponse.ProtoReflect.Descriptor instead.
func (*ReceiveBenchmarkJobResponse) Descriptor() ([]byte, []int) {
	return file_xsuportal_services_bench_receiving_proto_rawDescGZIP(), []int{1}
}

func (x *ReceiveBenchmarkJobResponse) GetJobHandle() *ReceiveBenchmarkJobResponse_JobHandle {
	if x != nil {
		return x.JobHandle
	}
	return nil
}

type ReceiveBenchmarkJobResponse_JobHandle struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	JobId          int64  `protobuf:"varint,1,opt,name=job_id,json=jobId,proto3" json:"job_id,omitempty"`
	Handle         string `protobuf:"bytes,2,opt,name=handle,proto3" json:"handle,omitempty"`
	TargetHostname string `protobuf:"bytes,3,opt,name=target_hostname,json=targetHostname,proto3" json:"target_hostname,omitempty"`
	// string description_human = 4;
	ContestStartedAt *timestamp.Timestamp `protobuf:"bytes,10,opt,name=contest_started_at,json=contestStartedAt,proto3" json:"contest_started_at,omitempty"`
	JobCreatedAt     *timestamp.Timestamp `protobuf:"bytes,11,opt,name=job_created_at,json=jobCreatedAt,proto3" json:"job_created_at,omitempty"`
}

func (x *ReceiveBenchmarkJobResponse_JobHandle) Reset() {
	*x = ReceiveBenchmarkJobResponse_JobHandle{}
	if protoimpl.UnsafeEnabled {
		mi := &file_xsuportal_services_bench_receiving_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReceiveBenchmarkJobResponse_JobHandle) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReceiveBenchmarkJobResponse_JobHandle) ProtoMessage() {}

func (x *ReceiveBenchmarkJobResponse_JobHandle) ProtoReflect() protoreflect.Message {
	mi := &file_xsuportal_services_bench_receiving_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReceiveBenchmarkJobResponse_JobHandle.ProtoReflect.Descriptor instead.
func (*ReceiveBenchmarkJobResponse_JobHandle) Descriptor() ([]byte, []int) {
	return file_xsuportal_services_bench_receiving_proto_rawDescGZIP(), []int{1, 0}
}

func (x *ReceiveBenchmarkJobResponse_JobHandle) GetJobId() int64 {
	if x != nil {
		return x.JobId
	}
	return 0
}

func (x *ReceiveBenchmarkJobResponse_JobHandle) GetHandle() string {
	if x != nil {
		return x.Handle
	}
	return ""
}

func (x *ReceiveBenchmarkJobResponse_JobHandle) GetTargetHostname() string {
	if x != nil {
		return x.TargetHostname
	}
	return ""
}

func (x *ReceiveBenchmarkJobResponse_JobHandle) GetContestStartedAt() *timestamp.Timestamp {
	if x != nil {
		return x.ContestStartedAt
	}
	return nil
}

func (x *ReceiveBenchmarkJobResponse_JobHandle) GetJobCreatedAt() *timestamp.Timestamp {
	if x != nil {
		return x.JobCreatedAt
	}
	return nil
}

var File_xsuportal_services_bench_receiving_proto protoreflect.FileDescriptor

var file_xsuportal_services_bench_receiving_proto_rawDesc = []byte{
	0x0a, 0x28, 0x78, 0x73, 0x75, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x6c, 0x2f, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x73, 0x2f, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x2f, 0x72, 0x65, 0x63, 0x65, 0x69,
	0x76, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1e, 0x78, 0x73, 0x75, 0x70,
	0x6f, 0x72, 0x74, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x73, 0x2e, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x35, 0x0a, 0x1a, 0x52,
	0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x42, 0x65, 0x6e, 0x63, 0x68, 0x6d, 0x61, 0x72, 0x6b, 0x4a,
	0x6f, 0x62, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x74, 0x65, 0x61,
	0x6d, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x74, 0x65, 0x61, 0x6d,
	0x49, 0x64, 0x22, 0xf5, 0x02, 0x0a, 0x1b, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x42, 0x65,
	0x6e, 0x63, 0x68, 0x6d, 0x61, 0x72, 0x6b, 0x4a, 0x6f, 0x62, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x64, 0x0a, 0x0a, 0x6a, 0x6f, 0x62, 0x5f, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x45, 0x2e, 0x78, 0x73, 0x75, 0x70, 0x6f, 0x72, 0x74,
	0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x73, 0x2e, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x2e, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x42,
	0x65, 0x6e, 0x63, 0x68, 0x6d, 0x61, 0x72, 0x6b, 0x4a, 0x6f, 0x62, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x2e, 0x4a, 0x6f, 0x62, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x52, 0x09, 0x6a,
	0x6f, 0x62, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x1a, 0xef, 0x01, 0x0a, 0x09, 0x4a, 0x6f, 0x62,
	0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x6a, 0x6f, 0x62, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x05, 0x6a, 0x6f, 0x62, 0x49, 0x64, 0x12, 0x16, 0x0a,
	0x06, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x68,
	0x61, 0x6e, 0x64, 0x6c, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f,
	0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e,
	0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x48,
	0x0a, 0x12, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65,
	0x64, 0x5f, 0x61, 0x74, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x10, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x73, 0x74, 0x53,
	0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x40, 0x0a, 0x0e, 0x6a, 0x6f, 0x62, 0x5f,
	0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x6a, 0x6f,
	0x62, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x32, 0xa1, 0x01, 0x0a, 0x0e, 0x42,
	0x65, 0x6e, 0x63, 0x68, 0x6d, 0x61, 0x72, 0x6b, 0x51, 0x75, 0x65, 0x75, 0x65, 0x12, 0x8e, 0x01,
	0x0a, 0x13, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x42, 0x65, 0x6e, 0x63, 0x68, 0x6d, 0x61,
	0x72, 0x6b, 0x4a, 0x6f, 0x62, 0x12, 0x3a, 0x2e, 0x78, 0x73, 0x75, 0x70, 0x6f, 0x72, 0x74, 0x61,
	0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x2e, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x2e, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x42, 0x65,
	0x6e, 0x63, 0x68, 0x6d, 0x61, 0x72, 0x6b, 0x4a, 0x6f, 0x62, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x3b, 0x2e, 0x78, 0x73, 0x75, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x6c, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x62, 0x65, 0x6e,
	0x63, 0x68, 0x2e, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x42, 0x65, 0x6e, 0x63, 0x68, 0x6d,
	0x61, 0x72, 0x6b, 0x4a, 0x6f, 0x62, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x4f,
	0x5a, 0x4d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x69, 0x73, 0x75,
	0x63, 0x6f, 0x6e, 0x2f, 0x69, 0x73, 0x75, 0x63, 0x6f, 0x6e, 0x31, 0x30, 0x2d, 0x66, 0x69, 0x6e,
	0x61, 0x6c, 0x2f, 0x77, 0x65, 0x62, 0x61, 0x70, 0x70, 0x2f, 0x67, 0x6f, 0x6c, 0x61, 0x6e, 0x67,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x78, 0x73, 0x75, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x6c,
	0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_xsuportal_services_bench_receiving_proto_rawDescOnce sync.Once
	file_xsuportal_services_bench_receiving_proto_rawDescData = file_xsuportal_services_bench_receiving_proto_rawDesc
)

func file_xsuportal_services_bench_receiving_proto_rawDescGZIP() []byte {
	file_xsuportal_services_bench_receiving_proto_rawDescOnce.Do(func() {
		file_xsuportal_services_bench_receiving_proto_rawDescData = protoimpl.X.CompressGZIP(file_xsuportal_services_bench_receiving_proto_rawDescData)
	})
	return file_xsuportal_services_bench_receiving_proto_rawDescData
}

var file_xsuportal_services_bench_receiving_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_xsuportal_services_bench_receiving_proto_goTypes = []interface{}{
	(*ReceiveBenchmarkJobRequest)(nil),            // 0: xsuportal.proto.services.bench.ReceiveBenchmarkJobRequest
	(*ReceiveBenchmarkJobResponse)(nil),           // 1: xsuportal.proto.services.bench.ReceiveBenchmarkJobResponse
	(*ReceiveBenchmarkJobResponse_JobHandle)(nil), // 2: xsuportal.proto.services.bench.ReceiveBenchmarkJobResponse.JobHandle
	(*timestamp.Timestamp)(nil),                   // 3: google.protobuf.Timestamp
}
var file_xsuportal_services_bench_receiving_proto_depIdxs = []int32{
	2, // 0: xsuportal.proto.services.bench.ReceiveBenchmarkJobResponse.job_handle:type_name -> xsuportal.proto.services.bench.ReceiveBenchmarkJobResponse.JobHandle
	3, // 1: xsuportal.proto.services.bench.ReceiveBenchmarkJobResponse.JobHandle.contest_started_at:type_name -> google.protobuf.Timestamp
	3, // 2: xsuportal.proto.services.bench.ReceiveBenchmarkJobResponse.JobHandle.job_created_at:type_name -> google.protobuf.Timestamp
	0, // 3: xsuportal.proto.services.bench.BenchmarkQueue.ReceiveBenchmarkJob:input_type -> xsuportal.proto.services.bench.ReceiveBenchmarkJobRequest
	1, // 4: xsuportal.proto.services.bench.BenchmarkQueue.ReceiveBenchmarkJob:output_type -> xsuportal.proto.services.bench.ReceiveBenchmarkJobResponse
	4, // [4:5] is the sub-list for method output_type
	3, // [3:4] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_xsuportal_services_bench_receiving_proto_init() }
func file_xsuportal_services_bench_receiving_proto_init() {
	if File_xsuportal_services_bench_receiving_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_xsuportal_services_bench_receiving_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReceiveBenchmarkJobRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_xsuportal_services_bench_receiving_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReceiveBenchmarkJobResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_xsuportal_services_bench_receiving_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReceiveBenchmarkJobResponse_JobHandle); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_xsuportal_services_bench_receiving_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_xsuportal_services_bench_receiving_proto_goTypes,
		DependencyIndexes: file_xsuportal_services_bench_receiving_proto_depIdxs,
		MessageInfos:      file_xsuportal_services_bench_receiving_proto_msgTypes,
	}.Build()
	File_xsuportal_services_bench_receiving_proto = out.File
	file_xsuportal_services_bench_receiving_proto_rawDesc = nil
	file_xsuportal_services_bench_receiving_proto_goTypes = nil
	file_xsuportal_services_bench_receiving_proto_depIdxs = nil
}
