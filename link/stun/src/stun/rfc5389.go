package stun

import (
	"net"
	"fmt"
	"time"
	"math/rand"
	"encoding/binary"
	"crypto/hmac"
	"crypto/sha1"
	"util/dbg"
	"conf"
	. "util/log"
)

const (
	STUN_MSG_HEADER_SIZE  = 20
	STUN_MSG_MAGIC_COOKIE = 0x2112A442
	STUN_NONCE_LENGTH     = 32              // < 128, https://tools.ietf.org/html/rfc5389#section-15.8
)

const (
	STUN_MSG_TYPE_METHOD_MASK    = 0x3eef   // 0b 0011 1110 1110 1111
	STUN_MSG_TYPE_ENCODING_MASK  = 0x0110   // 0b 0000 0001 0001 0000

	STUN_MSG_METHOD_BINDING      = 0x0001

	STUN_MSG_REQUEST             = 0x0000
	STUN_MSG_INDICATION          = 0x0010
	STUN_MSG_SUCCESS             = 0x0100
	STUN_MSG_ERROR               = 0x0110
)

const (
	STUN_ATTR_MAPPED_ADDR       = 0x0001
	STUN_ATTR_USERNAME          = 0x0006
	STUN_ATTR_MESSAGE_INTEGRITY = 0x0008
	STUN_ATTR_ERROR_CODE        = 0x0009
	STUN_ATTR_UNKNOWN_ATTR      = 0x000a
	STUN_ATTR_REALM             = 0x0014
	STUN_ATTR_NONCE             = 0x0015
	STUN_ATTR_XOR_MAPPED_ADDR   = 0x0020

	STUN_ATTR_SOFTWARE          = 0x8022
	STUN_ATTR_ALTERNATE_SERVER  = 0x8023
	STUN_ATTR_FINGERPRINT       = 0x8028
)

const (
	STUN_ERR_TRY_ALTERNATE      = 300
	STUN_ERR_BAD_REQUEST        = 400
	STUN_ERR_UNAUTHORIZED       = 401
	STUN_ERR_UNKNOWN_ATTRIBUTE  = 420
	STUN_ERR_STALE_NONCE        = 438
	STUN_ERR_SERVER_ERROR       = 500
)

type attribute struct {
	typename          string
	typevalue         uint16
	length            int
	value             []byte
}

type message struct {
	methodName        string
	encodingName      string
	method            uint16
	encoding          uint16
	length            int
	transactionID     []byte
	attributes        []*attribute
}

// -------------------------------------------------------------------------------------------------

func genTransactionID() []byte {

	id := make([]byte, 12)

	// get a random 96-bit number
	rand.Seed(time.Now().UnixNano())
	binary.BigEndian.PutUint32(id[0:], rand.Uint32())
	binary.BigEndian.PutUint32(id[4:], rand.Uint32())
	binary.BigEndian.PutUint32(id[8:], rand.Uint32())

	return id
}

func decodeXorAddr(attr *attribute) (*address, error) {

	fm := attr.value[1]

	xport := binary.BigEndian.Uint16(attr.value[2:])
	port := xport ^ (STUN_MSG_MAGIC_COOKIE >> 16)

	if fm == 0x01 {
		xip := binary.BigEndian.Uint32(attr.value[4:])
		ip := xip ^ STUN_MSG_MAGIC_COOKIE
		bytes := make([]byte, 4)
		binary.BigEndian.PutUint32(bytes[0:], ip)
		ip4 := net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3]).To4()
		if ip4 == nil {
			return nil, fmt.Errorf("invalid IPv4")
		}

		return &address{
			IP:   ip4,
			Port: int(port),
		}, nil
	} else if fm == 0x02 {
		// TODO ipv6
		return nil, fmt.Errorf("peer could not be IPv6")
	} else {
		return nil, fmt.Errorf("invalid address")
	}
}

func decodeErrorCode(attr *attribute) (code int, errStr string, err error) {

	if attr.typevalue != STUN_ATTR_ERROR_CODE {
		return 0, "", fmt.Errorf("not an ERROR-CODE attribute")
	}

	// Class * 100 + Number = code (https://tools.ietf.org/html/rfc5389#section-15.6)
	code = int(attr.value[2]) * 100 + int(attr.value[3])
	errStr = string(attr.value[4:])

	return code, errStr, nil
}

func decodeStringValue(attr *attribute) string {

	return string(attr.value[0:attr.length])
}

// -------------------------------------------------------------------------------------------------

func (this *message) buffer() []byte {

	payload := make([]byte, 20)

	// message type
	binary.BigEndian.PutUint16(payload[0:], uint16(this.method | this.encoding))

	// message length
	binary.BigEndian.PutUint16(payload[2:], uint16(this.length))

	// put magic cookie
	binary.BigEndian.PutUint32(payload[4:], uint32(STUN_MSG_MAGIC_COOKIE))

	// put transaction ID
	copy(payload[8:], this.transactionID)

	// append attributes
	for _, attr := range this.attributes {
		bytes := make([]byte, 4)
		binary.BigEndian.PutUint16(bytes[0:], attr.typevalue)
		binary.BigEndian.PutUint16(bytes[2:], uint16(attr.length))
		payload = append(payload, bytes...)
		payload = append(payload, attr.value...)
	}

	return payload
}

func (this *message) transactionIDString() (str string) {

	for _, v := range this.transactionID {
		str += fmt.Sprintf("%02x", v)
	}

	return str
}

// this function is only used to compute message integrity value
func (this *message) bufferExIntegrityAttr() []byte {

	payload := make([]byte, 20)

	// message type
	binary.BigEndian.PutUint16(payload[0:], uint16(this.method | this.encoding))

	// put magic cookie
	binary.BigEndian.PutUint32(payload[4:], uint32(STUN_MSG_MAGIC_COOKIE))

	// put transaction ID
	copy(payload[8:], this.transactionID)

	// this message length should reflect actual bytes above attribute MESSAGE_INTEGRITY
	msgLen := 0

	// a flag for STUN_ATTR_MESSAGE_INTEGRITY_SHA256
	useSHA256 := false

	// append attributes
	for _, attr := range this.attributes {

		// fall out of for loop when this message already contains attribute message integrity
		// otherwise we compute the whole message length, anyway we need involve 24 byte length
		// of integrity attr to compute the integrity value

		if attr.typevalue == STUN_ATTR_MESSAGE_INTEGRITY {
			break
		} else if attr.typevalue == STUN_ATTR_MESSAGE_INTEGRITY_SHA256 {
			useSHA256 = true
			break
		}

		bytes := make([]byte, 4)
		binary.BigEndian.PutUint16(bytes[0:], attr.typevalue)
		binary.BigEndian.PutUint16(bytes[2:], uint16(attr.length))
		payload = append(payload, bytes...)
		payload = append(payload, attr.value...)

		// notice: because of paddings inside attr
		// sometimes len(attr.value) is not equal to attr.length
		msgLen += 4 + len(attr.value)
	}

	// message-integrity attribute should not be included in integrity computing
	// while its attribute length should be counted in stun message length
	if useSHA256 {
		msgLen += 4 + STUN_MSG_INTEGRITY_SHA256_LENGTH // 32-byte hash by default
	} else {
		msgLen += 24 // 4 + 20 (SHA1)
	}

	// message length
	binary.BigEndian.PutUint16(payload[2:], uint16(msgLen))

	return payload
}

func (this *message) newErrorMessage(code int, reason string) (*message) {

	msg := &message{}

	// generate a new error response message
	msg.transactionID = append(msg.transactionID, this.transactionID...)
	msg.method = this.method
	msg.encoding = STUN_MSG_ERROR
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)

	// add error code attribute
	msg.attributes = []*attribute{}
	len := msg.addAttrErrorCode(code, reason)
	msg.length = len

	return msg
}

func (this *message) addAttrErrorCode(code int, reason string) int {

/*
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Reserved, should be 0         |Class|     Number    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      Reason Phrase (variable)                                ..
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_ERROR_CODE
	attr.typename = parseAttributeType(attr.typevalue)

	// padding to 4 bytes
	rs := []byte(reason)
	attr.length = 4 + len(rs)

	// add paddings
	total := attr.length
	if total % 4 != 0 {
		total += 4 - total % 4
	}

	// fill in the value
	attr.value = make([]byte, total) // including paddings
	hd := int(code / 100)
	attr.value[2] = byte(hd)
	attr.value[3] = byte(code - hd * 100)
	copy(attr.value[4:], rs)

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

func (this *message) isRequest() bool {

	return this.encoding == STUN_MSG_REQUEST
}

func (this *message) isIndication() bool {

	return this.encoding == STUN_MSG_INDICATION
}

func (this *message) isResponse() bool {

	return this.encoding == STUN_MSG_SUCCESS || this.encoding == STUN_MSG_ERROR
}

func (this *message) isBindingRequest() bool {

	return (this.method | this.encoding) == (STUN_MSG_METHOD_BINDING | STUN_MSG_REQUEST)
}

func (this *message) doBindingRequest(r *address) (*message, error) {

	msg := &message{}
	msg.method = STUN_MSG_METHOD_BINDING
	msg.transactionID = append(msg.transactionID, this.transactionID...)

	// add xor port and address
	len := msg.addAttrXorMappedAddr(r)

	msg.length = len
	msg.encoding = STUN_MSG_SUCCESS
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
	return msg, nil
}

func newBindingRequest() (*message, error) {

	msg := &message{}
	msg.method = STUN_MSG_METHOD_BINDING
	msg.encoding = STUN_MSG_REQUEST
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
	msg.transactionID = append(msg.transactionID, genTransactionID()...)

	return msg, nil
}

func (this *message) getAttrXorMappedAddr() (addr *address, err error) {

	attr := this.findAttr(STUN_ATTR_XOR_MAPPED_ADDR)
	if attr == nil {
		return nil, fmt.Errorf("XOR mapped address not found")
	}
	return decodeXorAddr(attr)
}

func (this *message) getAttrErrorCode() (code int, errStr string, err error) {

	attr := this.findAttr(STUN_ATTR_ERROR_CODE)
	if attr == nil {
		return 0, "", fmt.Errorf("ERROR-CODE not found")
	}

	return decodeErrorCode(attr)
}

func (this *message) getAttrRealm() (string, error) {

	return this.getAttrStringValue(STUN_ATTR_REALM, "REALM")
}

func (this *message) getAttrNonce() (string, error) {

	return this.getAttrStringValue(STUN_ATTR_NONCE, "NONCE")
}

func (this *message) getAttrUsername() (string, error) {

	return this.getAttrStringValue(STUN_ATTR_USERNAME, "USERNAME")
}

func (this *message) getAttrMsgIntegrity() (string, error) {

	return this.getAttrStringValue(STUN_ATTR_MESSAGE_INTEGRITY, "MESSAGE-INTEGRITY")
}

func (this *message) getAttrStringValue(typevalue uint16, typename string) (string, error) {

	attr := this.findAttr(typevalue)
	if attr == nil {
		return "", fmt.Errorf("%s not found", typename)
	}

	return decodeStringValue(attr), nil
}

func (this *message) addAttrXorAddr(r *address, typeval uint16) int {

	attr := &attribute{}
	attr.typevalue = typeval
	attr.typename = parseAttributeType(attr.typevalue)

	if r.IP.To4() == nil {
		attr.value = make([]byte, 20)
	} else {
		attr.value = make([]byte, 8)
	}
	attr.length = len(attr.value)

	// first byte is 0
	attr.value[0] = 0x00

	// family
	attr.value[1] = 0x01
	if r.IP.To4() == nil {
		attr.value[1] = 0x02
	}

	// x-port
	port16 := uint16(r.Port)
	xor := port16 ^ (STUN_MSG_MAGIC_COOKIE >> 16)
	binary.BigEndian.PutUint16(attr.value[2:], xor)

	// x-address
	if r.IP.To4() == nil {
		// TODO ipv6 x-address
	} else {
		addr32 := binary.BigEndian.Uint32(r.IP)
		xor := addr32 ^ STUN_MSG_MAGIC_COOKIE
		binary.BigEndian.PutUint32(attr.value[4:], xor)
	}

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

func (this *message) addAttrXorMappedAddr(r *address) int {

/*
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |x x x x x x x x|    Family     |         X-Port                |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                X-Address (Variable)
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

	return this.addAttrXorAddr(r, STUN_ATTR_XOR_MAPPED_ADDR)
}

func (this *message) addAttrRealm(realm string) int {

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_REALM
	attr.typename = parseAttributeType(attr.typevalue)

	// realm should be less than 128 characters
	if len(realm) > 128 {
		realm = realm[0:128]
	}
	attr.length = len(realm)

	// paddings
	total := attr.length
	if total % 4 != 0 {
		total += 4 - total % 4
	}

	attr.value = make([]byte, total)
	copy(attr.value[0:], []byte(realm))

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

func (this *message) addAttrUsername(username string) int {

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_USERNAME
	attr.typename = parseAttributeType(attr.typevalue)

	// username should be less than 513 (<=512) bytes
	// https://tools.ietf.org/html/rfc5389#section-15.3
	if len(username) > 513 {
		username = username[0:513]
	}
	attr.length = len(username)

	// paddings
	total := attr.length
	if total % 4 != 0 {
		total += 4 - total % 4
	}

	attr.value = make([]byte, total)
	copy(attr.value[0:], []byte(username))

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

func (this *message) addAttrNonce(nonce string) int {

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_NONCE
	attr.typename = parseAttributeType(attr.typevalue)
	attr.length = len(nonce)

	// nonce should be less than 128 characters
	if len(nonce) > 128 {
		nonce = nonce[0:128]
	}
	attr.length = len(nonce)

	// paddings
	total := attr.length
	if total % 4 != 0 {
		total += 4 - total % 4
	}

	attr.value = make([]byte, total)
	copy(attr.value[0:], []byte(nonce))

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

func (this *message) addAttrMsgIntegrity(key string) int {

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_MESSAGE_INTEGRITY
	attr.typename = parseAttributeType(attr.typevalue)
	attr.length = 20

	// refer to https://tools.ietf.org/html/rfc5389#section-15.4

	// msg length should include integrity attribute
	hash := this.computeIntegrity(key)

	// copy hash result to attribute body
	attr.value = make([]byte, len(hash))
	copy(attr.value[0:], hash)

	// add to attribute array
	this.attributes = append(this.attributes, attr)

	return 4 + len(attr.value)
}

func getMessage(buf []byte) (*message, error) {

	buf, err := checkMessage(buf)
	if err != nil {
		return nil, fmt.Errorf("invalid stun msg: %s", err)
	}

	msg := &message{}

	// get method and encoding
	msg.method = binary.BigEndian.Uint16(buf[0:]) & STUN_MSG_TYPE_METHOD_MASK
	msg.encoding = binary.BigEndian.Uint16(buf[0:]) & STUN_MSG_TYPE_ENCODING_MASK
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)

	// get length
	msg.length = len(buf) - STUN_MSG_HEADER_SIZE

	// get transactionID
	msg.transactionID = append(msg.transactionID, buf[8:20]...)

	// get attributes
	for i := 0; i < msg.length; {
		attr := &attribute{}

		// check attr length
		if i + 4 > msg.length {
			return nil, fmt.Errorf("attribute length overflow")
		}

		// first 4 bytes are Type and Length
		attr.typevalue = binary.BigEndian.Uint16(buf[20+i:])
		attr.typename = parseAttributeType(attr.typevalue)
		len := int(binary.BigEndian.Uint16(buf[20+i+2:]))
		attr.length = len

		// following bytes are attributes
		if len % 4 != 0 {
			// buffer should include padding bytes while attr.length does not
			len += 4 - len % 4
		}
		// check attr length which could overflow
		if i + 4 + len > msg.length {
			return nil, fmt.Errorf("invalid stun attribute length");
		}
		attr.value = append(attr.value, buf[20+i+4:20+i+4+len]...)
		msg.attributes = append(msg.attributes, attr)

		// padding for 4 bytes per attribute item
		i += len + 4
	}

	return msg, nil
}

func checkMessage(buf []byte) ([]byte, error) {

	// STUN message len does not meet the min requirement
	if len(buf) < STUN_MSG_HEADER_SIZE {
		return nil, fmt.Errorf("stun msg is too short: size=%d", len(buf))
	}

	// first byte should be 0x0 or 0x1
	if buf[0] != 0x00 && buf[0] != 0x01 {
		return nil, fmt.Errorf("invalid stun msg type: first_byte=0x%02x", buf[0])
	}

	// check STUN message length
	msgLen := int(binary.BigEndian.Uint16(buf[2:]))
	if msgLen + 20 > len(buf) {
		return nil, fmt.Errorf("msg length is too large: len=%d, actual=%d", msgLen, len(buf) - 20)
	}

	// STUN message is always padded to a multiple of 4 bytes
	if msgLen & 0x03 != 0 {
		return nil, fmt.Errorf("stun message is not aligned")
	}

	return buf[:msgLen + 20], nil
}

func (this *message) print(title string) {

	str := fmt.Sprintf("========== %s ==========\n", title)
	str += fmt.Sprintf("method=%s %s, length=%d bytes\n", this.methodName, this.encodingName, this.length)
	str += fmt.Sprintf("  transactionID=")
	for _, v := range this.transactionID {
		str += fmt.Sprintf("0x%02x ", v)
	}
	str += "\n"
	str += fmt.Sprintf("  attributes:\n")

	// show extra info like decoded xor addresses
	showExtra := func(attr *attribute) string {
		if attr.typevalue == STUN_ATTR_XOR_MAPPED_ADDR ||
			attr.typevalue == STUN_ATTR_XOR_RELAYED_ADDR ||
			attr.typevalue == STUN_ATTR_XOR_PEER_ADDR {
			addr, err := decodeXorAddr(attr)
			if err != nil {
				return fmt.Sprintf("(%v)", err)
			}
			return fmt.Sprintf("(%s:%d)", addr.IP, addr.Port)
		} else if attr.typevalue == STUN_ATTR_ERROR_CODE {
			code, errStr, err := decodeErrorCode(attr)
			if err != nil {
				return fmt.Sprintf("(%v)", err)
			}
			return fmt.Sprintf("(status=%d, %s)", code, errStr)
		} else if attr.typevalue == STUN_ATTR_NONCE || attr.typevalue == STUN_ATTR_REALM ||
			attr.typevalue == STUN_ATTR_USERNAME {
			return fmt.Sprintf("(%s)", decodeStringValue(attr))
		} else if attr.typevalue == STUN_ATTR_LIFETIME {
			return fmt.Sprintf("(%d seconds)", binary.BigEndian.Uint32(attr.value))
		} else {
			return ""
		}
	}

	// print all attributes
	for _, v := range this.attributes {
		str += fmt.Sprintf("    type=0x%04x(%s), len=%d, value=%s%s\n",
			v.typevalue, v.typename, v.length, dbg.DumpMem(v.value, 0), showExtra(v))
	}
	fmt.Println(str)
}

func (this *message) print4Log() string {

	// print stun message basic info
	str := fmt.Sprintf("%s %s %dB ", this.methodName, this.encodingName, this.length)

	// print stun attributes
	for _, v := range this.attributes {
		str += fmt.Sprintf("%s(%dB %s) ", v.typename, v.length, func(attr *attribute) string {

			if attr.typevalue == STUN_ATTR_XOR_MAPPED_ADDR ||
				attr.typevalue == STUN_ATTR_XOR_RELAYED_ADDR ||
				attr.typevalue == STUN_ATTR_XOR_PEER_ADDR {
				addr, err := decodeXorAddr(attr)
				if err != nil {
					return fmt.Sprintf("err=%v", err)
				}
				return fmt.Sprintf("addr=%s:%d", addr.IP, addr.Port)
			} else if attr.typevalue == STUN_ATTR_ERROR_CODE {
				code, errStr, err := decodeErrorCode(attr)
				if err != nil {
					return fmt.Sprintf("err=%v", attr.typename, err)
				}
				return fmt.Sprintf("reason=%d %s", code, errStr)
			} else if attr.typevalue == STUN_ATTR_NONCE {
				return fmt.Sprintf("nonce=%s", decodeStringValue(attr))
			} else if attr.typevalue == STUN_ATTR_REALM {
				return fmt.Sprintf("realm=%s", decodeStringValue(attr))
			} else if attr.typevalue == STUN_ATTR_USERNAME {
				return fmt.Sprintf("user=%s", decodeStringValue(attr))
			} else if attr.typevalue == STUN_ATTR_LIFETIME {
				return fmt.Sprintf("t=%d", binary.BigEndian.Uint32(attr.value))
			} else {
				return "-"
			}
		}(v))
	}

	return str
}

func (this *message) findAttr(typevalue uint16) *attribute {

	for _, attr := range this.attributes {
		if attr.typevalue == typevalue {
			return attr
		}
	}
	return nil
}

func (this *message) findAttrAll(typevalue uint16) []*attribute {

	list := []*attribute{}
	for _, attr := range this.attributes {
		if attr.typevalue == typevalue {
			list = append(list, attr)
		}
	}
	return list
}

// -------------------------------------------------------------------------------------------------

// STUN long-term credential
// https://tools.ietf.org/html/rfc5389#page-24

func (this *message) computeIntegrity(key string) string {

	// hmac, use sha1
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write(this.bufferExIntegrityAttr())
	return string(mac.Sum(nil))
}

func (this *message) checkIntegrity(key string) error {

	integritySHA1, err1 := this.getAttrMsgIntegrity()
	integritySHA256, err2 := this.getAttrMsgIntegritySHA256()
	if err1 != nil && err2 != nil {
		return fmt.Errorf("missing message integrity attribute")
	}

	// check MESSAGE-INTEGRITY
	if err1 == nil && this.computeIntegrity(key) != integritySHA1 {
		return fmt.Errorf("wrong message integrity")
	}

	// check MESSAGE-INTEGRITY-SHA256
	if err2 == nil && this.computeIntegritySHA256(key) != integritySHA256 {
		return fmt.Errorf("wrong message integrity sha256")
	}

	return nil
}

func (this *message) addIntegrity(username string) error {

	key, err := conf.Users.Find(username)
	if err != nil {
		return err
	}
	this.length += this.addAttrMsgIntegrity(key)

	return nil
}

func (this *message) getCredential() (username, realm, nonce string, err error) {

	if username, err = this.getAttrUsername(); err != nil {
		return
	}
	if realm, err = this.getAttrRealm(); err != nil {
		return
	}
	if nonce, err = this.getAttrNonce(); err != nil {
		return
	}

	return
}

func (this *message) checkCredential() (code int, err error) {

	// get username realm nonce integrity
	username, realm, _, err := this.getCredential()
	if err != nil {
		return STUN_ERR_BAD_REQUEST, fmt.Errorf("credential error")
	}

	// check realm
	if realm != *conf.Args.Realm {
		return STUN_ERR_WRONG_CRED, fmt.Errorf("realm mismatch")
	}

	if username == "" {
		return STUN_ERR_WRONG_CRED, fmt.Errorf("username is empty")
	}

	// check username and password
	key, err := conf.Users.Find(username)
	if err != nil {
		return STUN_ERR_WRONG_CRED, fmt.Errorf("username or password error")
	}
	if err = this.checkIntegrity(key); err != nil {
		return STUN_ERR_WRONG_CRED, fmt.Errorf("username or password error")
	}

	return 0, nil
}

// -------------------------------------------------------------------------------------------------

func (cl *stunclient) Bind() (err error) {

	// create request
	msg, _ := newBindingRequest()
	if cl.DebugOn { msg.print(fmt.Sprintf("client > server(%s)", cl.remote)) }
	Info("client > server(%s): %s", cl.remote, msg.print4Log())
	resp, err := cl.transmitMessage(msg)
	if err != nil {
		return fmt.Errorf("binding request: %s", err)
	}

	msg, err = getMessage(resp)
	if err != nil {
		return fmt.Errorf("binding response: %s", err)
	}
	if cl.DebugOn { msg.print(fmt.Sprintf("server(%s) > client", cl.remote)) }
	Info("server(%s) > client: %s", cl.remote, msg.print4Log())

	// save srflx IP address
	cl.srflx, err = msg.getAttrXorMappedAddr()
	if err != nil {
		return fmt.Errorf("binding response: srflx: %s", err)
	}
	cl.srflx.Proto = cl.remote.Proto

	return nil
}
