package stun

import (
	"testing"
	"net"
	. "util/log"
	"conf"
	"crypto/md5"
	"fmt"
	"time"
)

// -------------------------------------------------------------------------------------------------

func init() {

	SetLog("/dev/null")

	// init config
	relayedIP := "127.0.0.1"
	conf.Args.RelayedIP = &relayedIP

	realm := "test"
	conf.Args.Realm = &realm

	conf.Users.Add("test", "test", "abcdef")
}

// -------------------------------------------------------------------------------------------------

func process_binding_response(buf []byte, addr *address, t *testing.T) {

	res := process(buf, addr)

	resp, err := getMessage(res)
	if err != nil {
		t.Fatalf("%s", err)
	}
	if !(resp.method | resp.encoding == STUN_MSG_METHOD_BINDING | STUN_MSG_SUCCESS) {
		t.Fatal("wrong response type")
	}
	rflx, err := resp.getAttrXorMappedAddr()
	if err != nil {
		t.Fatalf("%s", err)
	}
	if !addr.IP.Equal(rflx.IP) || addr.Port != rflx.Port {
		t.Fatal("reflexive address does not match")
	}	
}

func Test_Func_process_binding_request_ipv4(t *testing.T) {

	tranID := genTransactionID()
	msg := &message{
		method:   STUN_MSG_METHOD_BINDING,
		encoding: STUN_MSG_REQUEST,
		transactionID: tranID,
		attributes: []*attribute{},
		length: 0,
	}
	addr := &address{
		Proto: NET_TCP,
		IP: net.ParseIP("1.2.3.4"),
		Port: 4000,
	}

	process_binding_response(msg.buffer(), addr, t)
}

func Test_Func_process_binding_request_ipv6(t *testing.T) {

	tranID := genTransactionID()
	msg := &message{
		method:   STUN_MSG_METHOD_BINDING,
		encoding: STUN_MSG_REQUEST,
		transactionID: tranID,
		attributes: []*attribute{},
		length: 0,
	}
	addr := &address{
		Proto: NET_TCP,
		IP: net.ParseIP("240a:d1:4000:1006:5::10"),
		Port: 4000,
	}

	process_binding_response(msg.buffer(), addr, t)
}

// -------------------------------------------------------------------------------------------------

func process_stun_response(buf []byte, addr *address, want int, t *testing.T) {

	resp, err := getMessage(process(buf, addr))
	if err != nil {
		t.Fatal(err)
	}
	code, errstr, err := resp.getAttrErrorCode()
	if code != want {
		t.Fatalf("expected error: %d, actual code: %d: %s", want, code, errstr)
	}
}

func Test_Func_process_initial_alloc_request(t *testing.T) {

	addr := &address{
		Proto: NET_TLS,
		IP: net.ParseIP("240a:d1:4000:1006:5::11"),
		Port: 4000,
	}

	msg, err := newInitAllocationRequest(PROTO_NUM_UDP)
	if err != nil {
		t.Fatal(err)
	}

	process_stun_response(msg.buffer(), addr, 401, t)
}

func Test_Func_process_initial_alloc_request_with_credential(t *testing.T) {

	addr := &address{
		Proto: NET_TLS,
		IP: net.ParseIP("240a:d1:4000:1006:5::12"),
		Port: 4000,
	}

	msg, err := newSubAllocationRequest(PROTO_NUM_UDP, ADDR_FAMILY_IPV4,
		"test", "test", genNonceWithCookie(STUN_NONCE_LENGTH))
	if err != nil {
		t.Fatal(err)
	}
	key := md5.Sum([]byte("test:test:abcdef"))
	msg.length += msg.addAttrMsgIntegrity(string(key[0:16]))

	process_stun_response(msg.buffer(), addr, 438, t)
}

func Test_Func_process_subsequent_alloc_request(t *testing.T) {

	addr := &address{
		Proto: NET_TLS,
		IP: net.ParseIP("240a:d1:4000:1006:5::11"),
		Port: 4000,
	}

	msg, err := newInitAllocationRequest(PROTO_NUM_UDP)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := getMessage(process(msg.buffer(), addr))
	if err != nil {
		t.Fatal(err)
	}
	realm, _ := resp.getAttrRealm()
	nonce, _ := resp.getAttrNonce()
	if len(realm) == 0 || len(nonce) == 0 {
		t.Fatal("realm or nonce missing")
	}

	msg, err = newSubAllocationRequest(PROTO_NUM_UDP, ADDR_FAMILY_IPV4, "test", realm, nonce)
	if err != nil {
		t.Fatal(err)
	}
	key := md5.Sum([]byte(fmt.Sprintf("test:%s:abcdef", realm)))
	msg.length += msg.addAttrMsgIntegrity(string(key[0:16]))

	process_stun_response(msg.buffer(), addr, 0, t)
}

func Test_Func_process_expired_subsequent_alloc_request(t *testing.T) {

	addr := &address{
		Proto: NET_TLS,
		IP: net.ParseIP("240a:d1:4000:1006:5::11"),
		Port: 4000,
	}

	msg, err := newInitAllocationRequest(PROTO_NUM_UDP)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := getMessage(process(msg.buffer(), addr))
	if err != nil {
		t.Fatal(err)
	}
	realm, _ := resp.getAttrRealm()
	nonce, _ := resp.getAttrNonce()
	if len(realm) == 0 || len(nonce) == 0 {
		t.Fatal("realm or nonce missing")
	}

	// initial allocation has expired
	time.Sleep(time.Second * TURN_INIT_ALLOC_EXPIRY)

	msg, err = newSubAllocationRequest(PROTO_NUM_UDP, ADDR_FAMILY_IPV4, "test", realm, nonce)
	if err != nil {
		t.Fatal(err)
	}
	key := md5.Sum([]byte(fmt.Sprintf("test:%s:abcdef", realm)))
	msg.length += msg.addAttrMsgIntegrity(string(key[0:16]))

	process_stun_response(msg.buffer(), addr, 437, t)
}
