#ifndef _STUN_H_
#define _STUN_H_

// Utility
extern int stun_gen_transactionID(char* buffer);

// Requests

// Binding request
typedef struct {
				char transID[12];
} binding_req_t;
extern int stun_binding_req(char* buffer, const binding_req_t* param);

// Allocation request
// - username
// - password
// - realm
// - nonce
// - lifetime
// - no-fragment*
// - even-port*
// - reservation-token*
typedef struct {
				char transID[12];
				char username[128];
				char password[128];
				char realm[128];
				char nonce[128];
				int  lifetime;
} alloc_req_t;
extern int stun_alloc_req(char* buffer, const alloc_req_t* param);

// Refresh request
// - username
// - password
// - realm
// - nonce
// - lifetime
typedef struct {
				char transID[12];
				char username[128];
				char passowrd[128];
				char realm[128];
				char nonce[128];
				int  lifetime;
} refresh_req_t;
extern int stun_refresh_req(char* buffer, const refresh_req_t* param);

// Create-Permission request
// - username
// - password
// - realm
// - nonce
// - ip address list
typedef struct {
				char transID[12];
				char username[128];
				char passowrd[128];
				char realm[128];
				char nonce[128];
				int  lifetime;
				char iplist[10][17];
} create_perm_req_t;
extern int stun_create_perm_req(char* buffer, const create_perm_req_t* param);

// Send indication
// - ip
// - port
// - data
// - size
typedef struct {
				char transID[12];
				char ip[17];
				int  port;
				char data[1500];
				int  size;
} send_ind_t;
extern int stun_send_ind(char* buffer, const send_ind_t* param);

// Channel-Bind request
// - username
// - password
// - realm
// - nonce
// - ip
// - port
// - channel number
typedef struct {
				char transID[12];
				char username[128];
				char passowrd[128];
				char realm[128];
				char nonce[128];
				char ip[17];
				int  port;
				int  channel;
} bind_chan_req_t;
extern int stun_bind_chan_req(char* buffer, const bind_chan_req_t* param);

// Channel-Data
// - channel
// - data
typedef struct {
				int  channel;
				char data[1500];
				int  size;
} channel_data_t;
extern int stun_channel_data(char* buffer, const channel_data_t* param);

// Attributes parser

// Error-Code
typedef struct {
				int  code;
				char reason[128];
				int  size;
} error_attr_t;
extern int stun_get_error_code(const char* buffer, int size, error_attr_t* err);

// XOR-Mapped-Address
typedef struct {
				char ip[17];
				int  port;
} xor_addr_attr_t, xor_peer_attr_t, xor_relay_attr_t;
extern int stun_get_xor_addr(const char* buffer, int size, xor_addr_attr_t* addr);
extern int stun_get_xor_peer(const char* buffer, int size, xor_peer_attr_t* peer);
extern int stun_get_xor_relay(const char* buffer, int size, xor_peer_attr_t* relay);

// Realm, Nonce, Username
typedef struct {
				char str[128];
} realm_attr_t, nonce_attr_t, username_attr_t;
extern int stun_get_realm(const char* buffer, int size, realm_attr_t* realm);
extern int stun_get_nonce(const char* buffer, int size, nonce_attr_t* nonce);
extern int stun_get_username(const char* buffer, int size, username_attr_t* username);

// Data
typedef struct {
				char data[1500];
				int  size;
} data_attr_t;
extern int stun_get_data(const char* buffer, int size, data_attr_t* data);

// Lifetime
extern int stun_get_lifetime(const char* buffer, int size, int* lifetime);

// Channel-Data
extern int stun_get_channel_data(const char* buffer, int size, channel_data_t* chdata);

#endif
