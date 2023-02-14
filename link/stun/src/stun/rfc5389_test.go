package stun

import (
	"testing"
	"net"
	"strings"
)

// -------------------------------------------------------------------------------------------------

func Test_Func_genTrasactionID_is_randomized(t *testing.T) {

	for i := 0; i < 100; i++ {
		a, b := genTransactionID(), genTransactionID()
		for j := 0; j < 12; j++ {
			if a[j] != b[j] {
				break
			}
			if j == 11 {
				t.Fatalf("collision occurs at #%d", i)
			}
		}
	}
}

func Test_Func_decodeXorAddr_ipv4(t *testing.T) {

	attr := &attribute{
		length: 8,
		value: []byte{ 0x00, ADDR_FAMILY_IPV4, 0xef, 0x0d, 0x8d, 0x03, 0xa4, 0x43 },
	}

	if addr, err := decodeXorAddr(attr, nil); err != nil {
		t.Fatalf("decode error: %s", err)
	} else if !addr.IP.Equal(net.ParseIP("172.17.0.1")) {
		t.Fatal("IP mismatch")
	} else if addr.Port != 52767 {
		t.Fatal("port mismatch")
	}
}

func Test_Func_decodeXorAddr_ipv6(t *testing.T) {

	attr := &attribute{
		length: 20,
		value: []byte{
			0x00, ADDR_FAMILY_IPV6, 0xef, 0x0d, 0x21, 0x12, 0xa4, 0x42, 0xef, 0x4c,
			0x79, 0x46, 0x30, 0x64, 0x06, 0xfc, 0x4f, 0x7e, 0x5d, 0x4f,
		},
	}

	transaction := []byte{ 0xef, 0x4c, 0x79, 0x46, 0x30, 0x64, 0x06, 0xfc, 0x4f, 0x7e, 0x5d, 0x4e }

	if addr, err := decodeXorAddr(attr, transaction); err != nil {
		t.Fatalf("decode error: %s", err)
	} else if !addr.IP.Equal(net.ParseIP("::1")) {
		t.Fatal("IP mismatch")
	} else if addr.Port != 52767 {
		t.Fatal("port mismatch")
	}
}

func Test_Func_decodeXorAddr_invalid_xor_addr_format(t *testing.T) {

	const ADDR_FAMILY_UNKNOWN = 0x99

	attr := &attribute{
		length: 8,
		value: []byte{ 0x00, ADDR_FAMILY_UNKNOWN, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	}

	if _, err := decodeXorAddr(attr, nil); err == nil {
		t.Fatal("assertion: not a valid IP family")
	}
}

func Test_Func_decodeErrorCode_not_an_errorcode_attr(t *testing.T) {

	attr := &attribute{
		typevalue: STUN_ATTR_REALM,
		length: 29,
		value: []byte{
			0x00, 0x00, 0x04, 0x25, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61,
			0x6c, 0x72, 0x65, 0x61, 0x64, 0x79, 0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x73, 0x00, 0x00, 0x00,
		},
	}

	if _, _, err := decodeErrorCode(attr); err == nil {
		t.Fatal("assertion: not a error number attribute")
	}
}

func Test_Func_decodeErrorCode_error_code_value(t *testing.T) {

	attr := &attribute{
		typevalue: STUN_ATTR_ERROR_CODE,
		length: 63,
		value: []byte{
			0x00, 0x00, 0x05, 0x00, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x65, 0x64, 0x20, 0x74, 0x72, 0x61, 0x6e,
			0x73, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65,
			0x64, 0x3a, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x69, 0x6e,
			0x64, 0x20, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x20, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x00,
		},
	}

	if code, str, err := decodeErrorCode(attr); err != nil {
		t.Fatalf("decode error code: %s", err)
	} else if code != 500 && str != "relayed transport not created: could not bind local address" {
		t.Fatal("decoding failed")
	}
}

// -------------------------------------------------------------------------------------------------

func Test_Func_checkMessage_too_short(t *testing.T) {

	data := []byte{
		0x00, 0x01, 0x00,
	}

	if _, err := checkMessage(data); err == nil {
		t.Fatal("assertion: header length is too short")
	}
}

func Test_Func_checkMessage_invalid_header_initial_byte(t *testing.T) {

	data := []byte{
		0xff, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x44, 0x41, 0x4e, 0x30, 0x51, 0x4a, 0x73, 0x72,
		0x30, 0x74, 0x39, 0x65,
	}

	if _, err := checkMessage(data); err == nil {
		t.Fatal("assertion: header begins with 0x00 or 0x01")
	}
}

func Test_Func_checkMessage_invalid_header_magic_cookie(t *testing.T) {

	data := []byte{
		0x00, 0x01, 0x00, 0x00, 0x20, 0x12, 0xa4, 0x42, 0x44, 0x41, 0x4e, 0x30, 0x51, 0x4a, 0x73, 0x72,
		0x30, 0x74, 0x39, 0x65,
	}

	if _, err := checkMessage(data); err == nil {
		t.Fatal("assertion: magic cookie mismatch")
	} else if !strings.Contains(err.Error(), "magic cookie mismatch") {
		t.Fatal("magic cookie error mismatch")
	}
}

func Test_Func_checkMessage_payload_larger_than_length_with_aligned_paddings(t *testing.T) {

	data := []byte{
		0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x44, 0x41, 0x4e, 0x30, 0x51, 0x4a, 0x73, 0x72,
		0x30, 0x74, 0x39, 0x65, 0x00, 0x00, 0x00, 0x00,
	}

	if _, err := checkMessage(data); err != nil {
		t.Fatalf("should be passed but now check failed: %s", err)
	}
}

func Test_Func_checkMessage_length_greater_than_payload_size(t *testing.T) {

	data := []byte{
		0x00, 0x01, 0x00, 0x04, 0x21, 0x12, 0xa4, 0x42, 0x44, 0x41, 0x4e, 0x30, 0x51, 0x4a, 0x73, 0x72,
		0x30, 0x74, 0x39, 0x65,
	}

	if _, err := checkMessage(data); err == nil {
		t.Fatal("assertion: payload size should be lower than length")
	}
}

func Test_Func_checkMessage_not_aligned_with_paddings(t *testing.T) {

	data := []byte{
		0x00, 0x01, 0x00, 0x03, 0x21, 0x12, 0xa4, 0x42, 0x44, 0x41, 0x4e, 0x30, 0x51, 0x4a, 0x73, 0x72,
		0x30, 0x74, 0x39, 0x65, 0xff, 0xff, 0xff,
	}

	if _, err := checkMessage(data); err == nil {
		t.Fatal("assertion: payload contents should be aligned in 32-bit")
	}
}

// -------------------------------------------------------------------------------------------------

func Test_message_Func_buffer_content(t *testing.T) {

	msg := &message{
		method:        STUN_MSG_METHOD_BINDING,
		encoding:      STUN_MSG_SUCCESS,
		length:        12,
		transactionID: []byte{ 0x44, 0x41, 0x4e, 0x30, 0x51, 0x4a, 0x73, 0x72, 0x30, 0x74, 0x39, 0x65 },
		attributes:    []*attribute{
			&attribute{
				typevalue: STUN_ATTR_XOR_MAPPED_ADDR,
				length: 8,
				value: []byte{ 0x00, 0x01, 0xd4, 0xcc, 0x96, 0x91, 0xca, 0x70 },
			},
		},
	}

	data := []byte{
		0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0x44, 0x41, 0x4e, 0x30, 0x51, 0x4a, 0x73, 0x72,
		0x30, 0x74, 0x39, 0x65, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xd4, 0xcc, 0x96, 0x91, 0xca, 0x70,
	}

	buff := msg.buffer()
	if len(buff) != len(data) {
		t.Fatal("length mismatch")
	}

	for i := 0; i < len(buff); i++ {
		if buff[i] != data[i] {
			t.Fatal("content mismatch")
		}
	}
}

func Test_message_Func_bufferBeforeAttr_with_attr_message_integrity(t *testing.T) {

	// payloads contain message integrity
	data := []byte{
		0x01, 0x09, 0x00, 0x18, 0x21, 0x12, 0xa4, 0x42, 0x44, 0x59, 0x74, 0x6c, 0x4a, 0x37, 0x68, 0x59,
		0x75, 0x6d, 0x4e, 0x53, 0x00, 0x08, 0x00, 0x14, 0x50, 0x7b, 0x7c, 0x66, 0xff, 0x43, 0x35, 0x40,
		0x89, 0x96, 0x99, 0x6f, 0x8f, 0x95, 0x33, 0xe1, 0x69, 0x6f, 0xa1, 0x93,
	}

	if msg, err := getMessage(data); err != nil {
		t.Fatalf("%s", err)
	} else {
		buf := msg.bufferBeforeAttr(STUN_ATTR_MESSAGE_INTEGRITY, 0)
		noIntegrity := []byte{
			0x01, 0x09, 0x00, 0x18, 0x21, 0x12, 0xa4, 0x42, 0x44, 0x59, 0x74, 0x6c, 0x4a, 0x37, 0x68, 0x59,
			0x75, 0x6d, 0x4e, 0x53,
		}
		if len(noIntegrity) != len(buf) {
			t.Fatal("length mismatch")
		}
		for i := 0; i < len(noIntegrity); i++ {
			if buf[i] != noIntegrity[i] {
				t.Fatal("content mismatch")
			}
		}
	}
}

func Test_message_Func_bufferBeforeAttr_with_attr_fingerprint(t *testing.T) {

	// payloads contain fingerprint
	data := []byte{
		0x00, 0x01, 0x00, 0x50, 0x21, 0x12, 0xa4, 0x42, 0x73, 0x58, 0x41, 0x58, 0x55, 0x73, 0x6e, 0x57,
		0x6e, 0x62, 0x30, 0x79, 0x00, 0x06, 0x00, 0x09, 0x41, 0x52, 0x4f, 0x53, 0x3a, 0x71, 0x79, 0x54,
		0x79, 0x00, 0x00, 0x00, 0xc0, 0x57, 0x00, 0x04, 0x00, 0x00, 0x03, 0xe7, 0x80, 0x2a, 0x00, 0x08,
		0xf4, 0x2b, 0xa1, 0xcb, 0xe4, 0xa3, 0x88, 0x4c, 0x00, 0x25, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04,
		0x6e, 0x00, 0x1e, 0xff, 0x00, 0x08, 0x00, 0x14, 0xff, 0x0e, 0xb8, 0xad, 0x22, 0x5d, 0x7d, 0x34,
		0x9d, 0xe3, 0x24, 0x52, 0x26, 0x27, 0xde, 0x40, 0x00, 0xd3, 0xa5, 0xa2, 0x80, 0x28, 0x00, 0x04,
		0x12, 0x54, 0x7d, 0x53,
	}

	if msg, err := getMessage(data); err != nil {
		t.Fatalf("%s", err)
	} else {
		buf := msg.bufferBeforeAttr(STUN_ATTR_FINGERPRINT, -1)
		if len(data) != len(buf) {
			t.Fatal("length mismatch")
		}
		for i := 0; i < len(data); i++ {
			if buf[i] != data[i] {
				if i != 3 {
					t.Fatalf("content mismatch %d", i)
				}
				// reserved length should be included
				if buf[i] != data[i] + 8 {
					t.Fatalf("reserved length mismatch")
				}
			}
		}
	}
}

// -------------------------------------------------------------------------------------------------

func Test_Func_getMessage_attribute_length_greater_than_payload_size(t *testing.T) {

	msg := &message{
		method: STUN_MSG_METHOD_BINDING,
		encoding: STUN_MSG_REQUEST,
		transactionID: genTransactionID(),
	}

	username := "test"
	attr := &attribute{}
	attr.typevalue = STUN_ATTR_USERNAME
	attr.length = len(username)
	attr.value = make([]byte, len(username))
	copy(attr.value, []byte(username))

	// incorrect length for attribute
	attr.length += 10

	// message length is correct
	msg.attributes = append(msg.attributes, attr)
	msg.length += 4 + len(attr.value)

	if _, err := getMessage(msg.buffer()); err == nil {
		t.Fatal("should have an error")
	} else if !strings.Contains(err.Error(), "stun attribute length") {
		t.Fatalf("assertion: expected error: invalid stun attribute length, actual: %s", err)
	}
}

func Test_Func_getMessage_attribute_payload_size_greater_than_attribute_length(t *testing.T) {

	msg := &message{
		method: STUN_MSG_METHOD_BINDING,
		encoding: STUN_MSG_REQUEST,
		transactionID: genTransactionID(),
	}

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_USERNAME
	attr.length = 1
	attr.value = make([]byte, 4)
	copy(attr.value, []byte{ 't', 0, 0, 0 })

	// message length is correct
	msg.attributes = append(msg.attributes, attr)
	msg.length += 4 + len(attr.value)

	if _, err := getMessage(msg.buffer()); err != nil {
		t.Fatalf("should have no error, err: %s", err)
	}
}

func Test_Func_getMessage_attribute_length_not_aligned_in_4_bytes(t *testing.T) {

	msg := &message{
		method: STUN_MSG_METHOD_BINDING,
		encoding: STUN_MSG_REQUEST,
		transactionID: genTransactionID(),
	}

	// first attr
	attr1 := &attribute{}
	attr1.typevalue = STUN_ATTR_USERNAME
	attr1.length = 1
	attr1.value = make([]byte, 1)
	copy(attr1.value, []byte{ 't' })
	msg.attributes = append(msg.attributes, attr1)
	msg.length += 4 + len(attr1.value)

	// second attr
	attr2 := &attribute{}
	attr2.typevalue = STUN_ATTR_REALM
	attr2.length = 3
	attr2.value = make([]byte, 3)
	copy(attr2.value, []byte{ 'e', 's', 't' })
	msg.attributes = append(msg.attributes, attr2)
	msg.length += 4 + len(attr2.value)


	if _, err := getMessage(msg.buffer()); err == nil {
		t.Fatal("should have an error")
	} else if !strings.Contains(err.Error(), "invalid stun attribute length") {
		t.Fatalf("assertion: expected error: invalid stun attribute length, actual: %s", err)
	}
}

func Test_Func_getMessage_message_not_aligned_in_4_bytes(t *testing.T) {

	msg := &message{
		method: STUN_MSG_METHOD_BINDING,
		encoding: STUN_MSG_REQUEST,
		transactionID: genTransactionID(),
	}

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_USERNAME
	attr.length = 1
	attr.value = make([]byte, 1)
	copy(attr.value, []byte{ 't' })
	msg.attributes = append(msg.attributes, attr)
	msg.length += 4 + len(attr.value)

	if _, err := getMessage(msg.buffer()); err == nil {
		t.Fatal("should have an error")
	} else if !strings.Contains(err.Error(), "stun message is not aligned") {
		t.Fatalf("assertion: expected error: stun message is not aligned, actual: %s", err)
	}
}

// -------------------------------------------------------------------------------------------------

func Test_message_Func_computeIntegrity(t *testing.T) {

	msg := &message{
		method: STUN_MSG_METHOD_BINDING,
		encoding: STUN_MSG_REQUEST,
		transactionID: []byte{ 0xef, 0x4c, 0x79, 0x46, 0x30, 0x64, 0x06, 0xfc, 0x4f, 0x7e, 0x5d, 0x4e },
	}

	hash := msg.computeIntegrity("test")
	expected := []byte{ 71, 123, 34, 128, 14, 163, 29, 188, 222, 37, 223, 67, 154, 59, 116, 37, 140, 136, 97, 136 }
	
	if hash != string(expected) {
		t.Fatalf("check failed, %v", []byte(hash))
	}
}

func Test_message_Func_computeIntegrity_length(t *testing.T) {

	for i := 0; i < 1000; i++ {
		msg := &message{
			method: STUN_MSG_METHOD_BINDING,
			encoding: STUN_MSG_REQUEST,
			transactionID: genTransactionID(),
		}
		if len(msg.computeIntegrity("test")) != 20 {
			t.Fatalf("length check failed, buffer: %v", msg.buffer())
		}
	}
}

func Test_message_Func_computeFingerprint(t *testing.T) {

	data := []byte{
		0x00, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0x73, 0x58, 0x41, 0x58, 0x55, 0x73, 0x6e, 0x57,
		0x6e, 0x62, 0x30, 0x79, 0x00, 0x06, 0x00, 0x09, 0x41, 0x52, 0x4f, 0x53, 0x3a, 0x71, 0x79, 0x54,
		0x79, 0x00, 0x00, 0x00, 0xc0, 0x57, 0x00, 0x04, 0x00, 0x00, 0x03, 0xe7, 0x80, 0x2a, 0x00, 0x08,
		0xf4, 0x2b, 0xa1, 0xcb, 0xe4, 0xa3, 0x88, 0x4c, 0x00, 0x25, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04,
		0x6e, 0x00, 0x1e, 0xff, 0x00, 0x08, 0x00, 0x14, 0xff, 0x0e, 0xb8, 0xad, 0x22, 0x5d, 0x7d, 0x34,
		0x9d, 0xe3, 0x24, 0x52, 0x26, 0x27, 0xde, 0x40, 0x00, 0xd3, 0xa5, 0xa2,
	}

	if msg, err := getMessage(data); err != nil {
		t.Fatalf("%s", err)
	} else {
		buf := msg.computeFingerprint(0)
		fp := []byte { 0x12, 0x54, 0x7d, 0x53 }
		if len(fp) != len(buf) {
			t.Fatal("length mismatch")
		}
		for i := 0; i < len(fp); i++ {
			if fp[i] != buf[i] {
				t.Fatalf("content mismatch %d", i)
			}
		}
	}
}
