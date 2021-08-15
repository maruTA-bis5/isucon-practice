// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: xsuportal/resources/contestant.proto

package resources

import (
	proto "github.com/golang/protobuf/proto"
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

type Contestant struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id        string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	TeamId    int64  `protobuf:"varint,2,opt,name=team_id,json=teamId,proto3" json:"team_id,omitempty"`
	Name      string `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	IsStudent bool   `protobuf:"varint,4,opt,name=is_student,json=isStudent,proto3" json:"is_student,omitempty"`
	IsStaff   bool   `protobuf:"varint,5,opt,name=is_staff,json=isStaff,proto3" json:"is_staff,omitempty"`
}

func (x *Contestant) Reset() {
	*x = Contestant{}
	if protoimpl.UnsafeEnabled {
		mi := &file_xsuportal_resources_contestant_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Contestant) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Contestant) ProtoMessage() {}

func (x *Contestant) ProtoReflect() protoreflect.Message {
	mi := &file_xsuportal_resources_contestant_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Contestant.ProtoReflect.Descriptor instead.
func (*Contestant) Descriptor() ([]byte, []int) {
	return file_xsuportal_resources_contestant_proto_rawDescGZIP(), []int{0}
}

func (x *Contestant) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Contestant) GetTeamId() int64 {
	if x != nil {
		return x.TeamId
	}
	return 0
}

func (x *Contestant) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Contestant) GetIsStudent() bool {
	if x != nil {
		return x.IsStudent
	}
	return false
}

func (x *Contestant) GetIsStaff() bool {
	if x != nil {
		return x.IsStaff
	}
	return false
}

var File_xsuportal_resources_contestant_proto protoreflect.FileDescriptor

var file_xsuportal_resources_contestant_proto_rawDesc = []byte{
	0x0a, 0x24, 0x78, 0x73, 0x75, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x6c, 0x2f, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x73, 0x74, 0x61, 0x6e, 0x74,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x19, 0x78, 0x73, 0x75, 0x70, 0x6f, 0x72, 0x74, 0x61,
	0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x73, 0x22, 0x83, 0x01, 0x0a, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x73, 0x74, 0x61, 0x6e, 0x74,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64,
	0x12, 0x17, 0x0a, 0x07, 0x74, 0x65, 0x61, 0x6d, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x06, 0x74, 0x65, 0x61, 0x6d, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1d, 0x0a,
	0x0a, 0x69, 0x73, 0x5f, 0x73, 0x74, 0x75, 0x64, 0x65, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x09, 0x69, 0x73, 0x53, 0x74, 0x75, 0x64, 0x65, 0x6e, 0x74, 0x12, 0x19, 0x0a, 0x08,
	0x69, 0x73, 0x5f, 0x73, 0x74, 0x61, 0x66, 0x66, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07,
	0x69, 0x73, 0x53, 0x74, 0x61, 0x66, 0x66, 0x42, 0x4a, 0x5a, 0x48, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x69, 0x73, 0x75, 0x63, 0x6f, 0x6e, 0x2f, 0x69, 0x73, 0x75,
	0x63, 0x6f, 0x6e, 0x31, 0x30, 0x2d, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x2f, 0x77, 0x65, 0x62, 0x61,
	0x70, 0x70, 0x2f, 0x67, 0x6f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x78, 0x73, 0x75, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x6c, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_xsuportal_resources_contestant_proto_rawDescOnce sync.Once
	file_xsuportal_resources_contestant_proto_rawDescData = file_xsuportal_resources_contestant_proto_rawDesc
)

func file_xsuportal_resources_contestant_proto_rawDescGZIP() []byte {
	file_xsuportal_resources_contestant_proto_rawDescOnce.Do(func() {
		file_xsuportal_resources_contestant_proto_rawDescData = protoimpl.X.CompressGZIP(file_xsuportal_resources_contestant_proto_rawDescData)
	})
	return file_xsuportal_resources_contestant_proto_rawDescData
}

var file_xsuportal_resources_contestant_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_xsuportal_resources_contestant_proto_goTypes = []interface{}{
	(*Contestant)(nil), // 0: xsuportal.proto.resources.Contestant
}
var file_xsuportal_resources_contestant_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_xsuportal_resources_contestant_proto_init() }
func file_xsuportal_resources_contestant_proto_init() {
	if File_xsuportal_resources_contestant_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_xsuportal_resources_contestant_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Contestant); i {
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
			RawDescriptor: file_xsuportal_resources_contestant_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_xsuportal_resources_contestant_proto_goTypes,
		DependencyIndexes: file_xsuportal_resources_contestant_proto_depIdxs,
		MessageInfos:      file_xsuportal_resources_contestant_proto_msgTypes,
	}.Build()
	File_xsuportal_resources_contestant_proto = out.File
	file_xsuportal_resources_contestant_proto_rawDesc = nil
	file_xsuportal_resources_contestant_proto_goTypes = nil
	file_xsuportal_resources_contestant_proto_depIdxs = nil
}
