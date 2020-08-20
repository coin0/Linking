#include "stun.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>  
#include <unistd.h> 
#include <errno.h>
#include <time.h>
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  

#define DEFAULT_MTU                  1500

#define	STUN_MSG_HEADER_SIZE         20
#define	STUN_MSG_MAGIC_COOKIE        0x2112A442
#define	STUN_NONCE_LENGTH            32
#define STUN_MSG_INTEGRITY_LENGTH    20

#define	STUN_MSG_TYPE_METHOD_MASK    0x3eef
#define	STUN_MSG_TYPE_ENCODING_MASK  0x0110

#define	STUN_MSG_METHOD_BINDING      0x0001
#define STUN_MSG_METHOD_ALLOCATE     0x0003
#define STUN_MSG_METHOD_REFRESH      0x0004
#define STUN_MSG_METHOD_SEND         0x0006
#define STUN_MSG_METHOD_DATA         0x0007
#define STUN_MSG_METHOD_CREATE_PERM  0x0008
#define STUN_MSG_METHOD_CHANNEL_BIND 0x0009

#define	STUN_MSG_REQUEST             0x0000
#define	STUN_MSG_INDICATION          0x0010
#define	STUN_MSG_SUCCESS             0x0100
#define	STUN_MSG_ERROR               0x0110

// 5389
#define	STUN_ATTR_MAPPED_ADDR        0x0001
#define	STUN_ATTR_USERNAME           0x0006
#define	STUN_ATTR_MESSAGE_INTEGRITY  0x0008
#define	STUN_ATTR_ERROR_CODE         0x0009
#define	STUN_ATTR_UNKNOWN_ATTR       0x000a
#define	STUN_ATTR_REALM              0x0014
#define	STUN_ATTR_NONCE              0x0015
#define	STUN_ATTR_XOR_MAPPED_ADDR    0x0020
#define	STUN_ATTR_SOFTWARE           0x8022
#define	STUN_ATTR_ALTERNATE_SERVER   0x8023
#define	STUN_ATTR_FINGERPRINT        0x8028
// 5766
#define STUN_ATTR_CHANNEL_NUMBER     0x000c
#define STUN_ATTR_LIFETIME           0x000d
#define STUN_ATTR_XOR_PEER_ADDR      0x0012
#define STUN_ATTR_DATA               0x0013
#define STUN_ATTR_XOR_RELAYED_ADDR   0x0016
#define STUN_ATTR_EVENT_PORT         0x0018
#define STUN_ATTR_REQUESTED_TRAN     0x0019
#define STUN_ATTR_DONT_FRAGMENT      0x001a
#define STUN_ATTR_RESERVATION_TOKEN  0x0022

#define	STUN_ERR_TRY_ALTERNATE       300
#define	STUN_ERR_BAD_REQUEST         400
#define	STUN_ERR_UNAUTHORIZED        401
#define	STUN_ERR_UNKNOWN_ATTRIBUTE   420
#define	STUN_ERR_STALE_NONCE         438
#define	STUN_ERR_SERVER_ERROR        500

// -------------------------------------------------------------------------------------------------

#define __DEMO__
#ifdef __DEMO__

static int stun_connect(int* sock, char* addr, char* port);
static int stun_send(int sock, const char* buf, int size);
static int stun_tcp_connect(int* sock, char* addr, char* port);
static int stun_tcp_send(int sock, const char* buf, int size);
static int stun_udp_connect(int* sock, char* addr, char* port);
static int stun_udp_send(int sock, const char* buf, int size);

// -------------------------------------------------------------------------------------------------

int main(int argc, char** argv)
{
				char* buf = (char*)malloc(1500);
				int size;
				int sock;

				if (argc < 3) {
								printf("usage error\n");
				}

				if (stun_connect(&sock, argv[1], argv[2]) < 0) {
								printf("connect failed\n");
								exit(1);
				}

				// binding request
				binding_req_t bind_req;
				stun_gen_transactionID(bind_req.transID);
				size = stun_binding_req(buf, &bind_req);
				if (size < 0) {
								printf("binding req: failed");
								return 1;
				}
				stun_send(sock, buf, size);

				// allocate request
				alloc_req_t alloc_req;
				memset(&alloc_req, 0, sizeof(alloc_req_t));
				stun_gen_transactionID(alloc_req.transID);
				memcpy(alloc_req.username, "root", 4);
				memcpy(alloc_req.password, "aaa", 3);
				memcpy(alloc_req.realm, "link", 4);
				memcpy(alloc_req.nonce, "2Muxzhfh6vEboHsNX43pm59794gv67qO", 32);
				alloc_req.lifetime = 600;
				printf("aaa\n");
				size = stun_alloc_req(buf, &alloc_req);
				printf("bbb\n");
				if (size < 0) {
								printf("alloc req: failed: %d", size);
								return 1;	
				}
				printf("ccc\n");
				stun_send(sock, buf, size);
				printf("ddd\n");

				return 0;
}

// -------------------------------------------------------------------------------------------------

int stun_connect(int* _sock, char* _addr, char* _port)
{
				return stun_tcp_connect(_sock, _addr, _port);
}

int stun_send(int _sock, const char* _buf, int _size)
{
				return stun_tcp_send(_sock, _buf, _size);
}

int stun_tcp_connect(int* _sock, char* _addr, char* _port)
{
				struct sockaddr_in tcp_addr;

				*_sock = socket(AF_INET, SOCK_STREAM, 0);
				if (*_sock < 0) {
								return -1;
				}

				memset(&tcp_addr, 0, sizeof(tcp_addr));
				tcp_addr.sin_family = AF_INET;
				tcp_addr.sin_port = htons(atoi(_port));
				inet_pton(AF_INET, _addr, &tcp_addr.sin_addr.s_addr);

				if (connect(*_sock, (struct sockaddr*)&tcp_addr, sizeof(tcp_addr)) < 0) {
								return -2;
				}

				return 0;
}

int stun_tcp_send(int _sock, const char* _buf, int _size)
{
				if (send(_sock, _buf, _size, 0) < 0) {
								printf("tcp send error:%s", strerror(errno));
								return -1;
				}

				return 0;
}

struct sockaddr_in udp_addr;
int stun_udp_connect(int* _sock, char* _addr, char* _port)
{
				*_sock = socket(AF_INET, SOCK_DGRAM, 0);
				if (*_sock < 0) {
								return -1;
				}

				memset(&udp_addr, 0, sizeof(udp_addr));
				udp_addr.sin_family = AF_INET;
				udp_addr.sin_addr.s_addr = inet_addr(_addr);
				udp_addr.sin_port = htons(atoi(_port));

				return 0;
}

int stun_udp_send(int _sock, const char* _buf, int _size)
{
				if (sendto(_sock, _buf, _size, 0, (struct sockaddr*)&udp_addr, sizeof(udp_addr)) < 0) {
								printf("udp send error:%s", strerror(errno));
								return -1;
				}

				return 0;
}

#endif

// -------------------------------------------------------------------------------------------------

static inline char* put_byte(char* _output, uint8_t _val)
{
        _output[0] = _val;
        return _output + 1;
}

static inline char* put_be16(char* _output, uint16_t _val)
{
        _output[1] = _val & 0xff;
        _output[0] = _val >> 8;
        return _output + 2;
}

static inline char* put_be24(char* _output,uint32_t _val)
{
        _output[2] = _val & 0xff;
        _output[1] = _val >> 8;
        _output[0] = _val >> 16;
        return _output + 3;
}

static inline char* put_be32(char* _output, uint32_t _val)
{
        _output[3] = _val & 0xff;
        _output[2] = _val >> 8;
        _output[1] = _val >> 16;
        _output[0] = _val >> 24;
        return _output + 4;
}

static inline char* put_be64(char* _output, uint64_t _val)
{
        _output = put_be32(_output, _val >> 32);
        _output = put_be32(_output, _val );
        return _output;
}

// -------------------------------------------------------------------------------------------------

// MD5

typedef struct
{
				unsigned int count[2];
				unsigned int state[4];
				unsigned char buffer[64];
}MD5_CTX;


#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))
#define FF(a,b,c,d,x,s,ac)											\
				{																				\
								a += F(b,c,d) + x + ac;					\
								a = ROTATE_LEFT(a,s);						\
								a += b;													\
				}
#define GG(a,b,c,d,x,s,ac)											\
				{																				\
								a += G(b,c,d) + x + ac;					\
								a = ROTATE_LEFT(a,s);						\
								a += b;													\
				}
#define HH(a,b,c,d,x,s,ac)											\
				{																				\
								a += H(b,c,d) + x + ac;					\
								a = ROTATE_LEFT(a,s);						\
								a += b;													\
				}
#define II(a,b,c,d,x,s,ac)											\
				{																				\
								a += I(b,c,d) + x + ac;					\
								a = ROTATE_LEFT(a,s);						\
								a += b;													\
				}
void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen);
void MD5Final(MD5_CTX *context,unsigned char digest[16]);
void MD5Transform(unsigned int state[4],unsigned char block[64]);
void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len);
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len);

unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
                          
void MD5Init(MD5_CTX *context)
{
				context->count[0] = 0;
				context->count[1] = 0;
				context->state[0] = 0x67452301;
				context->state[1] = 0xEFCDAB89;
				context->state[2] = 0x98BADCFE;
				context->state[3] = 0x10325476;
}
void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen)
{
				unsigned int i = 0,index = 0,partlen = 0;
				index = (context->count[0] >> 3) & 0x3F;
				partlen = 64 - index;
				context->count[0] += inputlen << 3;
				if(context->count[0] < (inputlen << 3))
								context->count[1]++;
				context->count[1] += inputlen >> 29;
     
				if(inputlen >= partlen)
				{
								memcpy(&context->buffer[index],input,partlen);
								MD5Transform(context->state,context->buffer);
								for(i = partlen;i+64 <= inputlen;i+=64)
												MD5Transform(context->state,&input[i]);
								index = 0;       
				} 
				else
				{
								i = 0;
				}
				memcpy(&context->buffer[index],&input[i],inputlen-i);
}
void MD5Final(MD5_CTX *context,unsigned char digest[16])
{
				unsigned int index = 0,padlen = 0;
				unsigned char bits[8];
				index = (context->count[0] >> 3) & 0x3F;
				padlen = (index < 56)?(56-index):(120-index);
				MD5Encode(bits,context->count,8);
				MD5Update(context,PADDING,padlen);
				MD5Update(context,bits,8);
				MD5Encode(digest,context->state,16);
}
void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)
{
				unsigned int i = 0,j = 0;
				while(j < len)
				{
								output[j] = input[i] & 0xFF; 
								output[j+1] = (input[i] >> 8) & 0xFF;
								output[j+2] = (input[i] >> 16) & 0xFF;
								output[j+3] = (input[i] >> 24) & 0xFF;
								i++;
								j+=4;
				}
}
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len)
{
				unsigned int i = 0,j = 0;
				while(j < len)
				{
								output[i] = (input[j]) |
												(input[j+1] << 8) |
												(input[j+2] << 16) |
												(input[j+3] << 24);
								i++;
								j+=4;
				}
}
void MD5Transform(unsigned int state[4],unsigned char block[64])
{
				unsigned int a = state[0];
				unsigned int b = state[1];
				unsigned int c = state[2];
				unsigned int d = state[3];
				unsigned int x[64];
				MD5Decode(x,block,64);
				FF(a, b, c, d, x[ 0], 7, 0xd76aa478); /* 1 */
				FF(d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
				FF(c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
				FF(b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
				FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); /* 5 */
				FF(d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
				FF(c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
				FF(b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
				FF(a, b, c, d, x[ 8], 7, 0x698098d8); /* 9 */
				FF(d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
				FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
				FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
				FF(a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
				FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
				FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
				FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */
  
				/* Round 2 */
				GG(a, b, c, d, x[ 1], 5, 0xf61e2562); /* 17 */
				GG(d, a, b, c, x[ 6], 9, 0xc040b340); /* 18 */
				GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
				GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
				GG(a, b, c, d, x[ 5], 5, 0xd62f105d); /* 21 */
				GG(d, a, b, c, x[10], 9,  0x2441453); /* 22 */
				GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
				GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
				GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); /* 25 */
				GG(d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
				GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
				GG(b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
				GG(a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
				GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8); /* 30 */
				GG(c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
				GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */
  
				/* Round 3 */
				HH(a, b, c, d, x[ 5], 4, 0xfffa3942); /* 33 */
				HH(d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
				HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
				HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
				HH(a, b, c, d, x[ 1], 4, 0xa4beea44); /* 37 */
				HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
				HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
				HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
				HH(a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
				HH(d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
				HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
				HH(b, c, d, a, x[ 6], 23,  0x4881d05); /* 44 */
				HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); /* 45 */
				HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
				HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
				HH(b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */
  
				/* Round 4 */
				II(a, b, c, d, x[ 0], 6, 0xf4292244); /* 49 */
				II(d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
				II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
				II(b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
				II(a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
				II(d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
				II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
				II(b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
				II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); /* 57 */
				II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
				II(c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
				II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
				II(a, b, c, d, x[ 4], 6, 0xf7537e82); /* 61 */
				II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
				II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
				II(b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */
				state[0] += a;
				state[1] += b;
				state[2] += c;
				state[3] += d;
}


void compute_md5(const char* data, int size, char* digest)
{
				MD5_CTX md5;

				MD5Init(&md5);
				MD5Update(&md5, (unsigned char*)data, size);
				MD5Final(&md5, digest);
}

// -------------------------------------------------------------------------------------------------

// HMAC_SHA1

#define SHA1_MAC_LEN 20

#define os_memset memset
#define os_memcpy memcpy

typedef uint8_t u8;
typedef uint32_t u32;

struct SHA1Context {
				u32 state[5];
				u32 count[2];
				unsigned char buffer[64];
};
typedef struct SHA1Context SHA1_CTX;

// sha1
void SHA1Init(struct SHA1Context *context);
void SHA1Update(struct SHA1Context *context, const void *data, u32 len);
void SHA1Final(unsigned char digest[20], struct SHA1Context *context);
void SHA1Transform(u32 state[5], const unsigned char buffer[64]);

// hmac-sha1
int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
										 const u8 *addr[], const size_t *len, u8 *mac);
int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
							u8 *mac);
int sha1_prf(const u8 *key, size_t key_len, const char *label,
						 const u8 *data, size_t data_len, u8 *buf, size_t buf_len);
int sha1_t_prf(const u8 *key, size_t key_len, const char *label,
							 const u8 *seed, size_t seed_len, u8 *buf, size_t buf_len);
int tls_prf_sha1_md5(const u8 *secret, size_t secret_len,
										 const char *label, const u8 *seed,
										 size_t seed_len, u8 *out, size_t outlen);
int pbkdf2_sha1(const char *passphrase, const u8 *ssid, size_t ssid_len,
								int iterations, u8 *buf, size_t buflen);

// sha1 func

int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
				SHA1_CTX ctx;
				size_t i;

				SHA1Init(&ctx);
				for (i = 0; i < num_elem; i++)
								SHA1Update(&ctx, addr[i], len[i]);
				SHA1Final(mac, &ctx);
				return 0;
}

#define SHA1HANDSOFF

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#ifndef WORDS_BIGENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) |	\
								 (rol(block->l[i], 8) & 0x00FF00FF))
#else
#define blk0(i) block->l[i]
#endif
#define blk(i) (block->l[i & 15] = rol(block->l[(i + 13) & 15] ^				\
																			 block->l[(i + 8) & 15] ^ block->l[(i + 2) & 15] ^ block->l[i & 15], 1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i)																								\
				z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5);	\
				w = rol(w, 30);
#define R1(v,w,x,y,z,i)																							\
				z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); \
				w = rol(w, 30);
#define R2(v,w,x,y,z,i)																									\
				z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); w = rol(w, 30);
#define R3(v,w,x,y,z,i)																									\
				z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); \
				w = rol(w, 30);
#define R4(v,w,x,y,z,i)																			\
				z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); \
				w=rol(w, 30);


#ifdef VERBOSE  /* SAK */
void SHAPrintContext(SHA1_CTX *context, char *msg)
{
				printf("%s (%d,%d) %x %x %x %x %x\n",
							 msg,
							 context->count[0], context->count[1], 
							 context->state[0],
							 context->state[1],
							 context->state[2],
							 context->state[3],
							 context->state[4]);
}
#endif

/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(u32 state[5], const unsigned char buffer[64])
{
				u32 a, b, c, d, e;
				typedef union {
								unsigned char c[64];
								u32 l[16];
				} CHAR64LONG16;
				CHAR64LONG16* block;
#ifdef SHA1HANDSOFF
				CHAR64LONG16 workspace;
				block = &workspace;
				os_memcpy(block, buffer, 64);
#else
				block = (CHAR64LONG16 *) buffer;
#endif
				/* Copy context->state[] to working vars */
				a = state[0];
				b = state[1];
				c = state[2];
				d = state[3];
				e = state[4];
				/* 4 rounds of 20 operations each. Loop unrolled. */
				R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
				R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
				R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
				R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
				R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
				R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
				R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
				R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
				R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
				R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
				R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
				R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
				R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
				R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
				R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
				R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
				R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
				R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
				R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
				R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
				/* Add the working vars back into context.state[] */
				state[0] += a;
				state[1] += b;
				state[2] += c;
				state[3] += d;
				state[4] += e;
				/* Wipe variables */
				a = b = c = d = e = 0;
#ifdef SHA1HANDSOFF
				os_memset(block, 0, 64);
#endif
}


/* SHA1Init - Initialize new context */

void SHA1Init(SHA1_CTX* context)
{
				/* SHA1 initialization constants */
				context->state[0] = 0x67452301;
				context->state[1] = 0xEFCDAB89;
				context->state[2] = 0x98BADCFE;
				context->state[3] = 0x10325476;
				context->state[4] = 0xC3D2E1F0;
				context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(SHA1_CTX* context, const void *_data, u32 len)
{
				u32 i, j;
				const unsigned char *data = _data;

#ifdef VERBOSE
				SHAPrintContext(context, "before");
#endif
				j = (context->count[0] >> 3) & 63;
				if ((context->count[0] += len << 3) < (len << 3))
								context->count[1]++;
				context->count[1] += (len >> 29);
				if ((j + len) > 63) {
								os_memcpy(&context->buffer[j], data, (i = 64-j));
								SHA1Transform(context->state, context->buffer);
								for ( ; i + 63 < len; i += 64) {
												SHA1Transform(context->state, &data[i]);
								}
								j = 0;
				}
				else i = 0;
				os_memcpy(&context->buffer[j], &data[i], len - i);
#ifdef VERBOSE
				SHAPrintContext(context, "after ");
#endif
}


/* Add padding and return the message digest. */

void SHA1Final(unsigned char digest[20], SHA1_CTX* context)
{
				u32 i;
				unsigned char finalcount[8];

				for (i = 0; i < 8; i++) {
								finalcount[i] = (unsigned char)
												((context->count[(i >= 4 ? 0 : 1)] >>
													((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
				}
				SHA1Update(context, (unsigned char *) "\200", 1);
				while ((context->count[0] & 504) != 448) {
								SHA1Update(context, (unsigned char *) "\0", 1);
				}
				SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform()
																							*/
				for (i = 0; i < 20; i++) {
								digest[i] = (unsigned char)
												((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) &
												 255);
				}
				/* Wipe variables */
				i = 0;
				os_memset(context->buffer, 0, 64);
				os_memset(context->state, 0, 20);
				os_memset(context->count, 0, 8);
				os_memset(finalcount, 0, 8);
}

int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
										 const u8 *addr[], const size_t *len, u8 *mac)
{
				unsigned char k_pad[64]; /* padding - key XORd with ipad/opad */
				unsigned char tk[20];
				const u8 *_addr[6];
				size_t _len[6], i;

				if (num_elem > 5) {
								/*
								 * Fixed limit on the number of fragments to avoid having to
								 * allocate memory (which could fail).
								 */
								return -1;
				}

        /* if key is longer than 64 bytes reset it to key = SHA1(key) */
        if (key_len > 64) {
								if (sha1_vector(1, &key, &key_len, tk))
												return -1;
								key = tk;
								key_len = 20;
        }

				/* the HMAC_SHA1 transform looks like:
				 *
				 * SHA1(K XOR opad, SHA1(K XOR ipad, text))
				 *
				 * where K is an n byte key
				 * ipad is the byte 0x36 repeated 64 times
				 * opad is the byte 0x5c repeated 64 times
				 * and text is the data being protected */

				/* start out by storing key in ipad */
				os_memset(k_pad, 0, sizeof(k_pad));
				os_memcpy(k_pad, key, key_len);
				/* XOR key with ipad values */
				for (i = 0; i < 64; i++)
								k_pad[i] ^= 0x36;

				/* perform inner SHA1 */
				_addr[0] = k_pad;
				_len[0] = 64;
				for (i = 0; i < num_elem; i++) {
								_addr[i + 1] = addr[i];
								_len[i + 1] = len[i];
				}
				if (sha1_vector(1 + num_elem, _addr, _len, mac))
								return -1;

				os_memset(k_pad, 0, sizeof(k_pad));
				os_memcpy(k_pad, key, key_len);
				/* XOR key with opad values */
				for (i = 0; i < 64; i++)
								k_pad[i] ^= 0x5c;

				/* perform outer SHA1 */
				_addr[0] = k_pad;
				_len[0] = 64;
				_addr[1] = mac;
				_len[1] = SHA1_MAC_LEN;
				return sha1_vector(2, _addr, _len, mac);
}

int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
							u8 *mac)
{
				return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}

// -------------------------------------------------------------------------------------------------

int stun_gen_transactionID(char* _buffer)
{
				time_t t;
				int i;

				srand((unsigned)time(&t));
				for (i = 0; i < 12; i++) {
								_buffer[i] = rand() % 0xff;
				}

				return 12;
}

void stun_compute_integrity(const char* _key, int _keylen, const char* _buffer, int _bsize, char* _hash)
{
				hmac_sha1(_key, _keylen, _buffer, _bsize, _hash);
}

// -------------------------------------------------------------------------------------------------

void stun_message_put_type(char* _buffer, uint16_t _method, uint16_t _encoding)
{
				put_be16(&_buffer[0], (_method | _encoding));
}

void stun_message_put_length(char* _buffer, int _len)
{
				put_be16(&_buffer[2], (uint16_t)_len);
}

int stun_message_get_length(const char* _buffer)
{
				uint16_t len = _buffer[2];

				return (int)((len << 8) | _buffer[3]);
}

void stun_message_put_magic(char* _buffer)
{
				put_be32(&_buffer[4], STUN_MSG_MAGIC_COOKIE);
}

void stun_message_put_transaction_id(char* _buffer, const char* _id)
{
				memcpy(&_buffer[8], _id, 12);
}

// -------------------------------------------------------------------------------------------------

void stun_attr_put_type(char* _buffer, uint16_t _type)
{
				put_be16(&_buffer[0], _type);
}

void stun_attr_put_length(char* _buffer, uint16_t _len)
{
				put_be16(&_buffer[2], _len);
}

// -------------------------------------------------------------------------------------------------

int stun_put_string(char* buffer, uint16_t type, const char* string);

int stun_put_username(char* _buffer, const char* _username)
{
				return stun_put_string(_buffer, STUN_ATTR_USERNAME, _username);
}

int stun_put_realm(char* _buffer, const char* _realm)
{
				return stun_put_string(_buffer, STUN_ATTR_REALM, _realm);
}

int stun_put_nonce(char* _buffer, const char* _nonce)
{
				return stun_put_string(_buffer, STUN_ATTR_NONCE, _nonce);
}

int stun_put_string(char* _buffer, uint16_t _type, const char* _string)
{
				int mlen = stun_message_get_length(_buffer);
				int slen = strlen(_string);
				int padsize = 0;
				char paddings[] = {0, 0, 0};

				// calculate padding bytes
				if (slen % 4 != 0) {
								padsize = 4 - slen % 4;
				}

				// type + length
				stun_attr_put_type(&_buffer[STUN_MSG_HEADER_SIZE+mlen], _type);
				stun_attr_put_length(&_buffer[STUN_MSG_HEADER_SIZE+mlen], slen);
				// value
				memcpy(&_buffer[STUN_MSG_HEADER_SIZE+mlen+4], _string, slen);

				// put paddings
				if (padsize > 0) {
								memcpy(&_buffer[STUN_MSG_HEADER_SIZE+mlen+4+slen], paddings, padsize);
				}

				stun_message_put_length(_buffer, mlen + 4 + slen + padsize);
				return 4 + slen + padsize;
}

int stun_put_lifetime(char* _buffer, int _lifetime)
{
				int mlen = stun_message_get_length(_buffer);

				// type + length
				stun_attr_put_type(&_buffer[STUN_MSG_HEADER_SIZE+mlen], STUN_ATTR_LIFETIME);
				stun_attr_put_length(&_buffer[STUN_MSG_HEADER_SIZE+mlen], 4);
				// value
				put_be32(&_buffer[STUN_MSG_HEADER_SIZE+mlen+4], (uint32_t)_lifetime);

				stun_message_put_length(_buffer, mlen + 8);
				return 8;
}

int stun_put_integrity(char* _buffer, const char* _key)
{
				int mlen = stun_message_get_length(_buffer);
				char hash[STUN_MSG_INTEGRITY_LENGTH] = {0};

				// NOTICE: must add integrity length first
				stun_message_put_length(_buffer, mlen + 24);

				// type + length
				stun_attr_put_type(&_buffer[STUN_MSG_HEADER_SIZE+mlen], STUN_ATTR_MESSAGE_INTEGRITY);
				stun_attr_put_length(&_buffer[STUN_MSG_HEADER_SIZE+mlen], STUN_MSG_INTEGRITY_LENGTH);

				// compute hash
				stun_compute_integrity(_key, 16, _buffer, STUN_MSG_HEADER_SIZE + mlen, hash);
				memcpy(&_buffer[STUN_MSG_HEADER_SIZE+mlen+4], hash, STUN_MSG_INTEGRITY_LENGTH);

				return 24;
}

// -------------------------------------------------------------------------------------------------

int stun_binding_req(char* _buffer, const binding_req_t* _param)
{
				stun_message_put_type(_buffer, STUN_MSG_METHOD_BINDING, STUN_MSG_REQUEST);
				stun_message_put_magic(_buffer);
				stun_message_put_transaction_id(_buffer, _param->transID);
				stun_message_put_length(_buffer, 0);

				return STUN_MSG_HEADER_SIZE;
}

int stun_alloc_req(char* _buffer, const alloc_req_t* _param)
{
				int size = 0;
				char str[400] = {0};
				unsigned char key[20] = {0};

				stun_message_put_type(_buffer, STUN_MSG_METHOD_ALLOCATE, STUN_MSG_REQUEST);
				stun_message_put_magic(_buffer);
				stun_message_put_transaction_id(_buffer, _param->transID);
				stun_message_put_length(_buffer, 0);

				if (strlen(_param->realm) > 0) {
								size += stun_put_username(_buffer, _param->username);
								size += stun_put_realm(_buffer, _param->realm);
								size += stun_put_nonce(_buffer, _param->nonce);
								size += stun_put_lifetime(_buffer, _param->lifetime);
								sprintf(str, "%s:%s:%s", _param->username, _param->realm, _param->password);
								compute_md5(str, strlen(str), key);
								size += stun_put_integrity(_buffer, (char*)key);
				}

				printf("--%d\n", size + STUN_MSG_HEADER_SIZE);

				return size + STUN_MSG_HEADER_SIZE;
}
