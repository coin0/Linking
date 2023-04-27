package stun

import (
	"fmt"
	"time"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/base64"
)

const (
	STUN_ATTR_MESSAGE_INTEGRITY_SHA256 = 0x001C
	STUN_ATTR_PASSWORD_ALGORITHM       = 0x001D
	STUN_ATTR_USERHASH                 = 0x001E

	STUN_ATTR_PASSWORD_ALGORITHMS      = 0x8002
	STUN_ATTR_ALTERNATE_DOMAIN         = 0x8003
)

const (
	STUN_USERHASH_LENGTH               = 32
	STUN_MSG_INTEGRITY_SHA256_LENGTH   = 32

	// https://www.rfc-editor.org/rfc/rfc8489#section-9.2
	// detailed info about nonce cookie
	STUN_NONCE_COOKIE_LENGTH           = 13
	STUN_NONCE_COOKIE_PREFIX           = "obMatJos2"
	STUN_SEC_FEAT_MASK_PSW_ALGORITHMS  = 0x80
	STUN_SEC_FEAT_MASK_USR_ANONYMITY   = 0x40

	STUN_PASSWORD_ALGORITHM_RESERVED   = 0x0000
	STUN_PASSWORD_ALGORITHM_MD5        = 0x0001
	STUN_PASSWORD_ALGORITHM_SHA256     = 0x0002
)

// -------------------------------------------------------------------------------------------------

func genNonceWithCookie(length int) string {

	cookie := STUN_NONCE_COOKIE_PREFIX

	// https://www.rfc-editor.org/rfc/rfc8489#section-18.1
	// 24-bit security feature set
	set := []byte{ 0, 0, 0 } // disable all security feature currently

	// encode as 4-byte base64 strings
	eb := make([]byte, base64.StdEncoding.EncodedLen(len(set)))
	base64.StdEncoding.Encode(eb, set)

	cookie += string(eb)
	return cookie + genNonce(STUN_NONCE_LENGTH - len(cookie))
}

func genFirstNonceWithCookie(addr *address, length int) string {

	nonce := genNonceWithCookie(length)
	req, loaded := allocPool.requests.LoadOrStore(keygen(addr), &allocreq{ time: time.Now(), nonce: nonce })
	if loaded {
		return req.(*allocreq).nonce
	}

	return nonce
}

// -------------------------------------------------------------------------------------------------

func (this *message) addAttrMsgIntegritySHA256(key string) int {

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_MESSAGE_INTEGRITY_SHA256
	attr.typename = parseAttributeType(attr.typevalue)
	attr.length = 20

	// refer to https://www.rfc-editor.org/rfc/rfc8489#section-14.6

	hash := this.computeIntegritySHA256(key)

	attr.value = make([]byte, len(hash))
	copy(attr.value[0:], hash)

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

func (this *message) addAttrPswAlgorithm(algorithm uint16, params []byte) int {

/*
      https://www.rfc-editor.org/rfc/rfc8489#section-14.12

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          Algorithm           |  Algorithm Parameters Length   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Algorithm Parameters (variable)
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_PASSWORD_ALGORITHM
	attr.typename = parseAttributeType(attr.typevalue)
	attr.length = 4 + len(params)

	// paddings
	total := attr.length
	if total % 4 != 0 {
		total += 4 - total % 4
	}
	attr.value = make([]byte, total)

	// algorithm
	binary.BigEndian.PutUint16(attr.value[0:], algorithm)
	// algorithm parameter length
	binary.BigEndian.PutUint16(attr.value[2:], uint16(len(params)))
	// algorithm parameters
	if len(params) > 0 {
		copy(attr.value[4:], params)
	}

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

func (this *message) addAttrUserHash(hash []byte) int {

	if len(hash) > STUN_USERHASH_LENGTH {
		hash = hash[0:STUN_USERHASH_LENGTH]
	}
	if len(hash) < STUN_USERHASH_LENGTH {
		return 0
	}

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_USERHASH
	attr.typename = parseAttributeType(attr.typevalue)
	attr.length = STUN_USERHASH_LENGTH

	attr.value = make([]byte, len(hash))
	copy(attr.value[0:], hash)

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

func (this *message) addAttrPswAlgorithms(set map[uint16][]byte) int {

/*
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Algorithm 1           | Algorithm 1 Parameters Length |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Algorithm 1 Parameters (variable)
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Algorithm 2           | Algorithm 2 Parameters Length |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Algorithm 2 Parameters (variable)
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                             ...
*/

	if set == nil {
		return 0
	}

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_PASSWORD_ALGORITHMS
	attr.typename = parseAttributeType(attr.typevalue)

	// fill algorithm list in attributes
	attr.value = []byte{}
	for al, params := range set {
		total := 4 + len(params)
		if total % 4 != 0 {
			total += 4 - total % 4
		}
		buf := make([]byte, total)

		binary.BigEndian.PutUint16(buf[0:], al)
		binary.BigEndian.PutUint16(buf[2:], uint16(len(params)))
		if len(params) > 0 {
			copy(buf[4:], params)
		}
		attr.value = append(attr.value, buf...)
	}

	// total length with calculated paddings
	attr.length = len(attr.value)

	this.attributes = append(this.attributes, attr)
	return 4 + attr.length
}

func (this *message) getAttrMsgIntegritySHA256() (string, error) {

	return this.getAttrStringValue(STUN_ATTR_MESSAGE_INTEGRITY_SHA256, "MESSAGE-INTEGRITY-SHA256")
}

func (this *message) getAttrPswAlgorithm() (uint16, []byte, error) {

	attr := this.findAttr(STUN_ATTR_PASSWORD_ALGORITHM)
	if attr == nil {
		return 0, nil, fmt.Errorf("not found")
	}

	if len(attr.value) < 4 {
		return 0, nil, fmt.Errorf("invalid length")
	}

	// read algorithm / length / parameters
	algorithm := binary.BigEndian.Uint16(attr.value[0:])
	length := binary.BigEndian.Uint16(attr.value[2:])
	// return error when algorithm + algorithm param length > attribute value length
	if int(length) + 4 > attr.length {
		return 0, nil, fmt.Errorf("params tool long")
	}

	return algorithm, attr.value[4:4+length], nil
}

func (this *message) getAttrUserHash() ([]byte, error) {

	attr := this.findAttr(STUN_ATTR_USERHASH)
	if attr == nil {
		return nil, fmt.Errorf("not found")
	}

	return attr.value, nil
}

func (this *message) getAttrPswAlgorithms() (map[uint16][]byte, error) {

	attr := this.findAttr(STUN_ATTR_PASSWORD_ALGORITHMS)
	if attr == nil {
		return nil, fmt.Errorf("not found")
	}

	if attr.length < 4 {
		return nil, fmt.Errorf("invalid length")
	}

	res := map[uint16][]byte{}
	for n := 0; n < attr.length; {
		// get algorithm and length
		algorithm := binary.BigEndian.Uint16(attr.value[n:])
		length := int(binary.BigEndian.Uint16(attr.value[n+2:]))

		// check params length
		if n + 4 + length > attr.length {
			break
		}

		// copy params
		params := []byte{}
		copy(params, attr.value[n+4:n+4+length])

		res[algorithm] = params

		// skip paddings
		n += 4 + length
		if n % 4 != 0 {
			n += 4 - n % 4
		}
	}

	if len(res) == 0 {
		return nil, fmt.Errorf("no available algorithm")
	}
	return res, nil
}

// -------------------------------------------------------------------------------------------------

func (this *message) computeIntegritySHA256(key string) string {

	// hmac, use sha256
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(this.bufferBeforeAttr(STUN_ATTR_MESSAGE_INTEGRITY_SHA256, 0))

	// https://www.rfc-editor.org/rfc/rfc8489#section-14.6
	// >= 16 bytes and <= 32 bytes, 32 bytes long by default
	return string(mac.Sum(nil)[0:STUN_MSG_INTEGRITY_SHA256_LENGTH])
}
