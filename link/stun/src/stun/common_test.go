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

var (
	testSkipSleep = false
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

func sleep_for_nsec(seconds int, t *testing.T) {

	if testSkipSleep {
		t.SkipNow()
	}
	for i := seconds; i > 0; i-- {
		fmt.Printf("%d..", i)
		time.Sleep(time.Second)
	}
	fmt.Println("done!")
}

func process_stun_response(buf []byte, addr *address, want int, t *testing.T) *message {

	resp, err := getMessage(process(buf, addr))
	if err != nil {
		t.Fatal(err)
	}
	code, errstr, err := resp.getAttrErrorCode()
	if code != want {
		t.Fatalf("expected error: %d, actual code: %d: %s", want, code, errstr)
	}

	return resp
}

func prepare_allocation(proto, ipfam byte, addr *address, t *testing.T) (*message, string) {

	msg, err := newInitAllocationRequest(proto)
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

	msg, err = newSubAllocationRequest(proto, ipfam, "test", realm, nonce)
	if err != nil {
		t.Fatal(err)
	}
	key := md5.Sum([]byte(fmt.Sprintf("test:%s:abcdef", realm)))
	msg.length += msg.addAttrMsgIntegrity(string(key[0:16]))

	resp, err = getMessage(process(msg.buffer(), addr))
	if err != nil {
		t.Fatal(err)
	}

	return resp, nonce
}

// create an allocation
func prepare_udp_ipv4_allocation(addr *address, t *testing.T) (*message, string) {

	return prepare_allocation(PROTO_NUM_UDP, ADDR_FAMILY_IPV4, addr, t)
}

// -------------------------------------------------------------------------------------------------

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
		IP: net.ParseIP("240a:d1:4000:1006:5::13"),
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
		IP: net.ParseIP("240a:d1:4000:1006:5::14"),
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
	sleep_for_nsec(TURN_INIT_ALLOC_EXPIRY, t)

	msg, err = newSubAllocationRequest(PROTO_NUM_UDP, ADDR_FAMILY_IPV4, "test", realm, nonce)
	if err != nil {
		t.Fatal(err)
	}
	key := md5.Sum([]byte(fmt.Sprintf("test:%s:abcdef", realm)))
	msg.length += msg.addAttrMsgIntegrity(string(key[0:16]))

	process_stun_response(msg.buffer(), addr, STUN_ERR_STALE_NONCE, t)
}

func Test_Func_process_dup_alloc(t *testing.T) {

	addr := &address{
		Proto: NET_TLS,
		IP: net.ParseIP("240a:d1:4000:1006:5::15"),
		Port: 4000,
	}

	msg, _ := prepare_udp_ipv4_allocation(addr, t)
	if _, err := msg.getAttrXorRelayedAddr(); err != nil {
		t.Fatal(err, msg.print4Log())
	}
	msg, _ = prepare_udp_ipv4_allocation(addr, t)
	if code, errstr, _ := msg.getAttrErrorCode(); code != STUN_ERR_ALLOC_MISMATCH {
		t.Fatalf("dup allocation returns unexpected error code: %d: %s", code, errstr)
	}
}

// -------------------------------------------------------------------------------------------------

func Test_Func_process_refresh_0(t *testing.T) {

	addr := &address{
		Proto: NET_TLS,
		IP: net.ParseIP("240a:d1:4000:1006:5::16"),
		Port: 4000,
	}

	msg, nonce := prepare_udp_ipv4_allocation(addr, t)
	if _, err := msg.getAttrXorRelayedAddr(); err != nil {
		t.Fatal(err, msg.print4Log())
	}

	refresh, _ := newRefreshRequest(0, "test", "abcdef", "test", nonce)
	process_stun_response(refresh.buffer(), addr, 0, t)

	msg, _ = prepare_udp_ipv4_allocation(addr, t)
	if _, err := msg.getAttrXorRelayedAddr(); err != nil {
		t.Fatal(err)
	}
}

func Test_Func_process_refresh_5(t *testing.T) {

	addr := &address{
		Proto: NET_TLS,
		IP: net.ParseIP("240a:d1:4000:1006:5::17"),
		Port: 4000,
	}

	msg, nonce := prepare_udp_ipv4_allocation(addr, t)
	if _, err := msg.getAttrXorRelayedAddr(); err != nil {
		t.Fatal(err, msg.print4Log())
	}

	sleep_for_nsec(1, t)

	refresh, _ := newRefreshRequest(5, "test", "abcdef", "test", nonce)
	process_stun_response(refresh.buffer(), addr, 0, t)

	sleep_for_nsec(10, t)

	refresh, _ = newRefreshRequest(0, "test", "abcdef", "test", nonce)
	process_stun_response(refresh.buffer(), addr, STUN_ERR_ALLOC_MISMATCH, t)
}

// -------------------------------------------------------------------------------------------------

func prepare_tcp_ipv4_allocation(addr *address, t *testing.T) (*message, string) {

	return prepare_allocation(PROTO_NUM_TCP, ADDR_FAMILY_IPV4, addr, t)
}

func Test_Func_process_connect_request(t *testing.T) {

	addr := &address{
		Proto: NET_TLS,
		Port: 12345,
		IP: net.ParseIP("::ffff:7fff:1"),
	}

	msg, nonce := prepare_tcp_ipv4_allocation(addr, t)
	relay, err := msg.getAttrXorRelayedAddr()
	if err != nil {
		t.Fatal(err, msg.print4Log())
	}

	msg, err = newConnectRequest("test", "abcdef", "test", nonce, relay)
	if err != nil {
		t.Fatal(err)
	}
	resp := process_stun_response(msg.buffer(), addr, 0, t)
	_, err = resp.getAttrConnID()
	if err != nil {
		t.Fatal(err)
	}
}
