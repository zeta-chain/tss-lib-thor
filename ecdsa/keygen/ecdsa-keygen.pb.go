// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.12
// source: protob/ecdsa-keygen.proto

package keygen

import (
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

// Represents a BROADCAST message sent during Round 1 of the ECDSA TSS keygen protocol.
type KGRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Commitment []byte                    `protobuf:"bytes,1,opt,name=commitment,proto3" json:"commitment,omitempty"`
	PaillierN  []byte                    `protobuf:"bytes,2,opt,name=paillier_n,json=paillierN,proto3" json:"paillier_n,omitempty"`
	NTilde     []byte                    `protobuf:"bytes,3,opt,name=n_tilde,json=nTilde,proto3" json:"n_tilde,omitempty"`
	H1         []byte                    `protobuf:"bytes,4,opt,name=h1,proto3" json:"h1,omitempty"`
	H2         []byte                    `protobuf:"bytes,5,opt,name=h2,proto3" json:"h2,omitempty"`
	Dlnproof_1 *KGRound1Message_DLNProof `protobuf:"bytes,8,opt,name=dlnproof_1,json=dlnproof1,proto3" json:"dlnproof_1,omitempty"`
	Dlnproof_2 *KGRound1Message_DLNProof `protobuf:"bytes,9,opt,name=dlnproof_2,json=dlnproof2,proto3" json:"dlnproof_2,omitempty"`
	Modproof   *KGRound1Message_ModProof `protobuf:"bytes,10,opt,name=modproof,proto3" json:"modproof,omitempty"`
}

func (x *KGRound1Message) Reset() {
	*x = KGRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_keygen_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound1Message) ProtoMessage() {}

func (x *KGRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_keygen_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound1Message.ProtoReflect.Descriptor instead.
func (*KGRound1Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_keygen_proto_rawDescGZIP(), []int{0}
}

func (x *KGRound1Message) GetCommitment() []byte {
	if x != nil {
		return x.Commitment
	}
	return nil
}

func (x *KGRound1Message) GetPaillierN() []byte {
	if x != nil {
		return x.PaillierN
	}
	return nil
}

func (x *KGRound1Message) GetNTilde() []byte {
	if x != nil {
		return x.NTilde
	}
	return nil
}

func (x *KGRound1Message) GetH1() []byte {
	if x != nil {
		return x.H1
	}
	return nil
}

func (x *KGRound1Message) GetH2() []byte {
	if x != nil {
		return x.H2
	}
	return nil
}

func (x *KGRound1Message) GetDlnproof_1() *KGRound1Message_DLNProof {
	if x != nil {
		return x.Dlnproof_1
	}
	return nil
}

func (x *KGRound1Message) GetDlnproof_2() *KGRound1Message_DLNProof {
	if x != nil {
		return x.Dlnproof_2
	}
	return nil
}

func (x *KGRound1Message) GetModproof() *KGRound1Message_ModProof {
	if x != nil {
		return x.Modproof
	}
	return nil
}

// Represents a P2P message sent to each party during Round 2 of the ECDSA TSS keygen protocol.
type KGRound2Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Share    []byte                        `protobuf:"bytes,1,opt,name=share,proto3" json:"share,omitempty"`
	Facproof *KGRound2Message1_FactorProof `protobuf:"bytes,2,opt,name=facproof,proto3" json:"facproof,omitempty"`
}

func (x *KGRound2Message1) Reset() {
	*x = KGRound2Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_keygen_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound2Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound2Message1) ProtoMessage() {}

func (x *KGRound2Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_keygen_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound2Message1.ProtoReflect.Descriptor instead.
func (*KGRound2Message1) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_keygen_proto_rawDescGZIP(), []int{1}
}

func (x *KGRound2Message1) GetShare() []byte {
	if x != nil {
		return x.Share
	}
	return nil
}

func (x *KGRound2Message1) GetFacproof() *KGRound2Message1_FactorProof {
	if x != nil {
		return x.Facproof
	}
	return nil
}

// Represents a BROADCAST message sent to each party during Round 2 of the ECDSA TSS keygen protocol.
type KGRound2Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DeCommitment [][]byte `protobuf:"bytes,1,rep,name=de_commitment,json=deCommitment,proto3" json:"de_commitment,omitempty"`
}

func (x *KGRound2Message2) Reset() {
	*x = KGRound2Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_keygen_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound2Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound2Message2) ProtoMessage() {}

func (x *KGRound2Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_keygen_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound2Message2.ProtoReflect.Descriptor instead.
func (*KGRound2Message2) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_keygen_proto_rawDescGZIP(), []int{2}
}

func (x *KGRound2Message2) GetDeCommitment() [][]byte {
	if x != nil {
		return x.DeCommitment
	}
	return nil
}

// Represents a BROADCAST message sent to each party during Round 3 of the ECDSA TSS keygen protocol.
type KGRound3Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaillierProof [][]byte `protobuf:"bytes,1,rep,name=paillier_proof,json=paillierProof,proto3" json:"paillier_proof,omitempty"`
}

func (x *KGRound3Message) Reset() {
	*x = KGRound3Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_keygen_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound3Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound3Message) ProtoMessage() {}

func (x *KGRound3Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_keygen_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound3Message.ProtoReflect.Descriptor instead.
func (*KGRound3Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_keygen_proto_rawDescGZIP(), []int{3}
}

func (x *KGRound3Message) GetPaillierProof() [][]byte {
	if x != nil {
		return x.PaillierProof
	}
	return nil
}

type KGRound1Message_DLNProof struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Alpha [][]byte `protobuf:"bytes,1,rep,name=alpha,proto3" json:"alpha,omitempty"`
	T     [][]byte `protobuf:"bytes,2,rep,name=t,proto3" json:"t,omitempty"`
}

func (x *KGRound1Message_DLNProof) Reset() {
	*x = KGRound1Message_DLNProof{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_keygen_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound1Message_DLNProof) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound1Message_DLNProof) ProtoMessage() {}

func (x *KGRound1Message_DLNProof) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_keygen_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound1Message_DLNProof.ProtoReflect.Descriptor instead.
func (*KGRound1Message_DLNProof) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_keygen_proto_rawDescGZIP(), []int{0, 0}
}

func (x *KGRound1Message_DLNProof) GetAlpha() [][]byte {
	if x != nil {
		return x.Alpha
	}
	return nil
}

func (x *KGRound1Message_DLNProof) GetT() [][]byte {
	if x != nil {
		return x.T
	}
	return nil
}

type KGRound1Message_ParamProof struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	A [][]byte `protobuf:"bytes,1,rep,name=a,proto3" json:"a,omitempty"`
	Z [][]byte `protobuf:"bytes,2,rep,name=z,proto3" json:"z,omitempty"`
}

func (x *KGRound1Message_ParamProof) Reset() {
	*x = KGRound1Message_ParamProof{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_keygen_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound1Message_ParamProof) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound1Message_ParamProof) ProtoMessage() {}

func (x *KGRound1Message_ParamProof) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_keygen_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound1Message_ParamProof.ProtoReflect.Descriptor instead.
func (*KGRound1Message_ParamProof) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_keygen_proto_rawDescGZIP(), []int{0, 1}
}

func (x *KGRound1Message_ParamProof) GetA() [][]byte {
	if x != nil {
		return x.A
	}
	return nil
}

func (x *KGRound1Message_ParamProof) GetZ() [][]byte {
	if x != nil {
		return x.Z
	}
	return nil
}

type KGRound1Message_ModProof struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	W []byte   `protobuf:"bytes,1,opt,name=w,proto3" json:"w,omitempty"`
	X [][]byte `protobuf:"bytes,2,rep,name=x,proto3" json:"x,omitempty"`
	A []bool   `protobuf:"varint,3,rep,packed,name=a,proto3" json:"a,omitempty"`
	B []bool   `protobuf:"varint,4,rep,packed,name=b,proto3" json:"b,omitempty"`
	Z [][]byte `protobuf:"bytes,5,rep,name=z,proto3" json:"z,omitempty"`
}

func (x *KGRound1Message_ModProof) Reset() {
	*x = KGRound1Message_ModProof{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_keygen_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound1Message_ModProof) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound1Message_ModProof) ProtoMessage() {}

func (x *KGRound1Message_ModProof) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_keygen_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound1Message_ModProof.ProtoReflect.Descriptor instead.
func (*KGRound1Message_ModProof) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_keygen_proto_rawDescGZIP(), []int{0, 2}
}

func (x *KGRound1Message_ModProof) GetW() []byte {
	if x != nil {
		return x.W
	}
	return nil
}

func (x *KGRound1Message_ModProof) GetX() [][]byte {
	if x != nil {
		return x.X
	}
	return nil
}

func (x *KGRound1Message_ModProof) GetA() []bool {
	if x != nil {
		return x.A
	}
	return nil
}

func (x *KGRound1Message_ModProof) GetB() []bool {
	if x != nil {
		return x.B
	}
	return nil
}

func (x *KGRound1Message_ModProof) GetZ() [][]byte {
	if x != nil {
		return x.Z
	}
	return nil
}

type KGRound2Message1_FactorProof struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	P     []byte `protobuf:"bytes,1,opt,name=p,proto3" json:"p,omitempty"`
	Q     []byte `protobuf:"bytes,2,opt,name=q,proto3" json:"q,omitempty"`
	A     []byte `protobuf:"bytes,3,opt,name=a,proto3" json:"a,omitempty"`
	B     []byte `protobuf:"bytes,4,opt,name=b,proto3" json:"b,omitempty"`
	T     []byte `protobuf:"bytes,5,opt,name=t,proto3" json:"t,omitempty"`
	Sigma []byte `protobuf:"bytes,6,opt,name=sigma,proto3" json:"sigma,omitempty"`
	Z1    []byte `protobuf:"bytes,7,opt,name=z1,proto3" json:"z1,omitempty"`
	Z2    []byte `protobuf:"bytes,8,opt,name=z2,proto3" json:"z2,omitempty"`
	W1    []byte `protobuf:"bytes,9,opt,name=w1,proto3" json:"w1,omitempty"`
	W2    []byte `protobuf:"bytes,10,opt,name=w2,proto3" json:"w2,omitempty"`
	V     []byte `protobuf:"bytes,11,opt,name=v,proto3" json:"v,omitempty"`
}

func (x *KGRound2Message1_FactorProof) Reset() {
	*x = KGRound2Message1_FactorProof{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_keygen_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound2Message1_FactorProof) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound2Message1_FactorProof) ProtoMessage() {}

func (x *KGRound2Message1_FactorProof) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_keygen_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound2Message1_FactorProof.ProtoReflect.Descriptor instead.
func (*KGRound2Message1_FactorProof) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_keygen_proto_rawDescGZIP(), []int{1, 0}
}

func (x *KGRound2Message1_FactorProof) GetP() []byte {
	if x != nil {
		return x.P
	}
	return nil
}

func (x *KGRound2Message1_FactorProof) GetQ() []byte {
	if x != nil {
		return x.Q
	}
	return nil
}

func (x *KGRound2Message1_FactorProof) GetA() []byte {
	if x != nil {
		return x.A
	}
	return nil
}

func (x *KGRound2Message1_FactorProof) GetB() []byte {
	if x != nil {
		return x.B
	}
	return nil
}

func (x *KGRound2Message1_FactorProof) GetT() []byte {
	if x != nil {
		return x.T
	}
	return nil
}

func (x *KGRound2Message1_FactorProof) GetSigma() []byte {
	if x != nil {
		return x.Sigma
	}
	return nil
}

func (x *KGRound2Message1_FactorProof) GetZ1() []byte {
	if x != nil {
		return x.Z1
	}
	return nil
}

func (x *KGRound2Message1_FactorProof) GetZ2() []byte {
	if x != nil {
		return x.Z2
	}
	return nil
}

func (x *KGRound2Message1_FactorProof) GetW1() []byte {
	if x != nil {
		return x.W1
	}
	return nil
}

func (x *KGRound2Message1_FactorProof) GetW2() []byte {
	if x != nil {
		return x.W2
	}
	return nil
}

func (x *KGRound2Message1_FactorProof) GetV() []byte {
	if x != nil {
		return x.V
	}
	return nil
}

var File_protob_ecdsa_keygen_proto protoreflect.FileDescriptor

var file_protob_ecdsa_keygen_proto_rawDesc = []byte{
	0x0a, 0x19, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x6b,
	0x65, 0x79, 0x67, 0x65, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1b, 0x62, 0x69, 0x6e,
	0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x65, 0x63, 0x64, 0x73,
	0x61, 0x2e, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x22, 0xc0, 0x04, 0x0a, 0x0f, 0x4b, 0x47, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1e, 0x0a, 0x0a,
	0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x1d, 0x0a, 0x0a,
	0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x5f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x09, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x4e, 0x12, 0x17, 0x0a, 0x07, 0x6e,
	0x5f, 0x74, 0x69, 0x6c, 0x64, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x6e, 0x54,
	0x69, 0x6c, 0x64, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x68, 0x31, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x02, 0x68, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x68, 0x32, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x02, 0x68, 0x32, 0x12, 0x54, 0x0a, 0x0a, 0x64, 0x6c, 0x6e, 0x70, 0x72, 0x6f, 0x6f, 0x66,
	0x5f, 0x31, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x62, 0x69, 0x6e, 0x61, 0x6e,
	0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2e,
	0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x2e, 0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x44, 0x4c, 0x4e, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x52,
	0x09, 0x64, 0x6c, 0x6e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x31, 0x12, 0x54, 0x0a, 0x0a, 0x64, 0x6c,
	0x6e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x32, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35,
	0x2e, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e,
	0x65, 0x63, 0x64, 0x73, 0x61, 0x2e, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x2e, 0x4b, 0x47, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x44, 0x4c, 0x4e,
	0x50, 0x72, 0x6f, 0x6f, 0x66, 0x52, 0x09, 0x64, 0x6c, 0x6e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x32,
	0x12, 0x51, 0x0a, 0x08, 0x6d, 0x6f, 0x64, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x0a, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x35, 0x2e, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73,
	0x6c, 0x69, 0x62, 0x2e, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2e, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e,
	0x2e, 0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x2e, 0x4d, 0x6f, 0x64, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x52, 0x08, 0x6d, 0x6f, 0x64, 0x70, 0x72,
	0x6f, 0x6f, 0x66, 0x1a, 0x2e, 0x0a, 0x08, 0x44, 0x4c, 0x4e, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12,
	0x14, 0x0a, 0x05, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x05,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x12, 0x0c, 0x0a, 0x01, 0x74, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x01, 0x74, 0x1a, 0x28, 0x0a, 0x0a, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x50, 0x72, 0x6f, 0x6f,
	0x66, 0x12, 0x0c, 0x0a, 0x01, 0x61, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x01, 0x61, 0x12,
	0x0c, 0x0a, 0x01, 0x7a, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x01, 0x7a, 0x1a, 0x50, 0x0a,
	0x08, 0x4d, 0x6f, 0x64, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x0c, 0x0a, 0x01, 0x77, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x77, 0x12, 0x0c, 0x0a, 0x01, 0x78, 0x18, 0x02, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x01, 0x78, 0x12, 0x0c, 0x0a, 0x01, 0x61, 0x18, 0x03, 0x20, 0x03, 0x28, 0x08,
	0x52, 0x01, 0x61, 0x12, 0x0c, 0x0a, 0x01, 0x62, 0x18, 0x04, 0x20, 0x03, 0x28, 0x08, 0x52, 0x01,
	0x62, 0x12, 0x0c, 0x0a, 0x01, 0x7a, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x01, 0x7a, 0x4a,
	0x04, 0x08, 0x06, 0x10, 0x07, 0x4a, 0x04, 0x08, 0x07, 0x10, 0x08, 0x22, 0xb9, 0x02, 0x0a, 0x10,
	0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31,
	0x12, 0x14, 0x0a, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x12, 0x55, 0x0a, 0x08, 0x66, 0x61, 0x63, 0x70, 0x72, 0x6f,
	0x6f, 0x66, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x39, 0x2e, 0x62, 0x69, 0x6e, 0x61, 0x6e,
	0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2e,
	0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x2e, 0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x2e, 0x46, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x50, 0x72,
	0x6f, 0x6f, 0x66, 0x52, 0x08, 0x66, 0x61, 0x63, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x1a, 0xb7, 0x01,
	0x0a, 0x0b, 0x46, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x0c, 0x0a,
	0x01, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x70, 0x12, 0x0c, 0x0a, 0x01, 0x71,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x71, 0x12, 0x0c, 0x0a, 0x01, 0x61, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x61, 0x12, 0x0c, 0x0a, 0x01, 0x62, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x01, 0x62, 0x12, 0x0c, 0x0a, 0x01, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x01, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x69, 0x67, 0x6d, 0x61, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x05, 0x73, 0x69, 0x67, 0x6d, 0x61, 0x12, 0x0e, 0x0a, 0x02, 0x7a, 0x31, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x7a, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x7a, 0x32, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x7a, 0x32, 0x12, 0x0e, 0x0a, 0x02, 0x77, 0x31, 0x18,
	0x09, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x77, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x77, 0x32, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x77, 0x32, 0x12, 0x0c, 0x0a, 0x01, 0x76, 0x18, 0x0b,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x76, 0x22, 0x37, 0x0a, 0x10, 0x4b, 0x47, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x23, 0x0a, 0x0d, 0x64,
	0x65, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x0c, 0x64, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74,
	0x22, 0x38, 0x0a, 0x0f, 0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x12, 0x25, 0x0a, 0x0e, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x5f,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0d, 0x70, 0x61, 0x69,
	0x6c, 0x6c, 0x69, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x42, 0x0e, 0x5a, 0x0c, 0x65, 0x63,
	0x64, 0x73, 0x61, 0x2f, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_protob_ecdsa_keygen_proto_rawDescOnce sync.Once
	file_protob_ecdsa_keygen_proto_rawDescData = file_protob_ecdsa_keygen_proto_rawDesc
)

func file_protob_ecdsa_keygen_proto_rawDescGZIP() []byte {
	file_protob_ecdsa_keygen_proto_rawDescOnce.Do(func() {
		file_protob_ecdsa_keygen_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_ecdsa_keygen_proto_rawDescData)
	})
	return file_protob_ecdsa_keygen_proto_rawDescData
}

var file_protob_ecdsa_keygen_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_protob_ecdsa_keygen_proto_goTypes = []interface{}{
	(*KGRound1Message)(nil),              // 0: binance.tsslib.ecdsa.keygen.KGRound1Message
	(*KGRound2Message1)(nil),             // 1: binance.tsslib.ecdsa.keygen.KGRound2Message1
	(*KGRound2Message2)(nil),             // 2: binance.tsslib.ecdsa.keygen.KGRound2Message2
	(*KGRound3Message)(nil),              // 3: binance.tsslib.ecdsa.keygen.KGRound3Message
	(*KGRound1Message_DLNProof)(nil),     // 4: binance.tsslib.ecdsa.keygen.KGRound1Message.DLNProof
	(*KGRound1Message_ParamProof)(nil),   // 5: binance.tsslib.ecdsa.keygen.KGRound1Message.ParamProof
	(*KGRound1Message_ModProof)(nil),     // 6: binance.tsslib.ecdsa.keygen.KGRound1Message.ModProof
	(*KGRound2Message1_FactorProof)(nil), // 7: binance.tsslib.ecdsa.keygen.KGRound2Message1.FactorProof
}
var file_protob_ecdsa_keygen_proto_depIdxs = []int32{
	4, // 0: binance.tsslib.ecdsa.keygen.KGRound1Message.dlnproof_1:type_name -> binance.tsslib.ecdsa.keygen.KGRound1Message.DLNProof
	4, // 1: binance.tsslib.ecdsa.keygen.KGRound1Message.dlnproof_2:type_name -> binance.tsslib.ecdsa.keygen.KGRound1Message.DLNProof
	6, // 2: binance.tsslib.ecdsa.keygen.KGRound1Message.modproof:type_name -> binance.tsslib.ecdsa.keygen.KGRound1Message.ModProof
	7, // 3: binance.tsslib.ecdsa.keygen.KGRound2Message1.facproof:type_name -> binance.tsslib.ecdsa.keygen.KGRound2Message1.FactorProof
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_protob_ecdsa_keygen_proto_init() }
func file_protob_ecdsa_keygen_proto_init() {
	if File_protob_ecdsa_keygen_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_ecdsa_keygen_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound1Message); i {
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
		file_protob_ecdsa_keygen_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound2Message1); i {
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
		file_protob_ecdsa_keygen_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound2Message2); i {
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
		file_protob_ecdsa_keygen_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound3Message); i {
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
		file_protob_ecdsa_keygen_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound1Message_DLNProof); i {
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
		file_protob_ecdsa_keygen_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound1Message_ParamProof); i {
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
		file_protob_ecdsa_keygen_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound1Message_ModProof); i {
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
		file_protob_ecdsa_keygen_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound2Message1_FactorProof); i {
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
			RawDescriptor: file_protob_ecdsa_keygen_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_ecdsa_keygen_proto_goTypes,
		DependencyIndexes: file_protob_ecdsa_keygen_proto_depIdxs,
		MessageInfos:      file_protob_ecdsa_keygen_proto_msgTypes,
	}.Build()
	File_protob_ecdsa_keygen_proto = out.File
	file_protob_ecdsa_keygen_proto_rawDesc = nil
	file_protob_ecdsa_keygen_proto_goTypes = nil
	file_protob_ecdsa_keygen_proto_depIdxs = nil
}
