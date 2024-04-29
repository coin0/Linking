package stun

import (
	"fmt"
	"net"
	"math/rand"
	"encoding/binary"
	. "util/log"
	"time"
)

const (
	// recommended ranges of 32768-49151
	STUN_NAT_PROBE_MIN_PORT    = 32768
	STUN_NAT_PROBE_MAX_PORT    = 49151
)

// https://datatracker.ietf.org/doc/html/rfc5780#section-9
const (
	STUN_ATTR_CHANGE_REQUEST   = 0x0003
	STUN_ATTR_RESPONSE_PORT    = 0x0027

	STUN_ATTR_PADDING          = 0x0026
	STUN_ATTR_CACHE_TIMEOUT    = 0x8027
	STUN_ATTR_RESPONSE_ORIGIN  = 0x802b
	STUN_ATTR_OTHER_ADDRESS    = 0x802c
)

// -------------------------------------------------------------------------------------------------

func selectPort() int {

	// https://datatracker.ietf.org/doc/html/rfc5780#section-4.1
	total := STUN_NAT_PROBE_MAX_PORT - STUN_NAT_PROBE_MIN_PORT + 1
	r := rand.New(rand.NewSource(time.Now().Unix()))
	return STUN_NAT_PROBE_MIN_PORT + int(r.Uint32()) % total
}

// -------------------------------------------------------------------------------------------------

func (this *message) getAttrChangeRequest() (changePort, changeIP bool, err error) {

	attr := this.findAttr(STUN_ATTR_CHANGE_REQUEST)
	if attr == nil {
		return false, false, fmt.Errorf("CHANGE-REQUEST not found")
	}

	if len(attr.value) != 4 {
		return false, false, fmt.Errorf("invalid CHANGE-REQUEST length")
	}

	return uint8(attr.value[3]) & 0x02 > 0, uint8(attr.value[3]) & 0x04 > 0, nil
}

func (this *message) getAttrResponseOrigin() (addr *address, err error) {

	attr := this.findAttr(STUN_ATTR_RESPONSE_ORIGIN)
	if attr == nil {
		return nil, fmt.Errorf("RESPONSE-ORIGIN not found")
	}

	return decodeAddr(attr)
}

func (this *message) getAttrResponsePort() (port uint16, err error) {

	attr := this.findAttr(STUN_ATTR_RESPONSE_PORT)
	if attr == nil {
		return 0, fmt.Errorf("RESPONSE-PORT not found")
	}

	// RESPONSE-PORT is a 16-bit unsigned integer in network byte order
	// followed by 2 bytes of padding.  Allowable values of RESPONSE-PORT
	// are 0-65536

	if len(attr.value) != 4 {
		return 0, fmt.Errorf("invalid RESPONSE-PORT length")
	}

	return binary.BigEndian.Uint16(attr.value[0:]), nil
}

func (this *message) getAttrOtherAddress() (addr *address, err error) {

	attr := this.findAttr(STUN_ATTR_OTHER_ADDRESS)
	if attr == nil {
		return nil, fmt.Errorf("OTHER-ADDRESS not found")
	}

	return decodeAddr(attr)
}

func (this *message) getAttrPadding() (bytes int, err error) {

	attr := this.findAttr(STUN_ATTR_PADDING)
	if attr == nil {
		return 0, fmt.Errorf("PADDING not found")
	}

	return attr.length, nil
}

func (this *message) addAttrChangeRequest(changePort, changeIP bool) int {

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

	attr := &attribute{
		typevalue: STUN_ATTR_CHANGE_REQUEST,
		typename:  parseAttributeType(STUN_ATTR_CHANGE_REQUEST),
		length:    4,
	}

	attr.value = make([]byte, 4)
	if changePort {
		attr.value[3] |= 0x2
	}
	if changeIP {
		attr.value[3] |= 0x4
	}

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

func (this *message) addAttrResponseOrigin(addr *address) int {

	return this.addAttrAddr(addr, STUN_ATTR_RESPONSE_ORIGIN)
}

func (this *message) addAttrResponsePort(port uint16) int {

	attr := &attribute{
		typevalue: STUN_ATTR_RESPONSE_PORT,
		typename:  parseAttributeType(STUN_ATTR_RESPONSE_PORT),
		length:    4,
	}

	attr.value = make([]byte, 4)
	binary.BigEndian.PutUint16(attr.value[0:], port)

	this.attributes = append(this.attributes, attr)
	return 4 + 4
}

func (this *message) addAttrOtherAddress(addr *address) int {

	return this.addAttrAddr(addr, STUN_ATTR_OTHER_ADDRESS)
}

func (this *message) addAttrPadding(bytes int) int {

	attr := &attribute{
		typevalue: STUN_ATTR_PADDING,
		typename:  parseAttributeType(STUN_ATTR_RESPONSE_PORT),
		length:    bytes,
	}

	// stun paddings alignment
	total := attr.length
	if total % 4 != 0 {
		total += 4 - total % 4
	}
	attr.value = make([]byte, total)

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

// -------------------------------------------------------------------------------------------------

func (cl *stunclient) pickUDPAddress() *net.UDPAddr {

	return &net.UDPAddr{
		IP: nil,
		Port: selectPort(),
	}
}

func (cl *stunclient) pickTCPAddress() *net.TCPAddr {

	return &net.TCPAddr{
		IP: nil,
		Port: selectPort(),
	}
}

// this interface mostly follows the flow defined in the standard document
// https://datatracker.ietf.org/doc/html/rfc5780#section-4.3
func (cl *stunclient) Probe() error {

	// determining NAT Mapping Behavior
	if err := cl.probeMapping(); err != nil {
		return err
	}

	return nil
}

func (cl *stunclient) probeMapping() (err error) {

	// test I: UDP connectivity test

	// a copy from Bind() request
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
	// end of copy

	// examine reflexive address
	if cl.local.Equal(cl.srflx) {
		cl.natType = NAT_TYPE_NOT_NATED
		return nil
	}

	// get the other server address
	otherServer, err := msg.getAttrOtherAddress()
	if err != nil {
		return fmt.Errorf("get other address: %s", err)
	}
	fmt.Println(otherServer)

	return nil
}

func (cl *stunclient) LocalAddr() (string, string, int, error) {

	if cl.local != nil {
		return parseNetType(cl.local.Proto), cl.local.IP.String(), cl.local.Port, nil
	}

	return "", "", 0, fmt.Errorf("local address unknown")
}

func (cl *stunclient) NATTypeString() string {

	return parseNATType(cl.natType)
}
