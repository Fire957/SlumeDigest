/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.com
 */
//#include "tomcrypt.h"

/**
  @file sha1.c
  SHA1 code by Tom St Denis 
*/


#include <string.h>
#include <string>
#define SHA1 1


typedef unsigned long long ulong64;
typedef unsigned int ulong32;

#define CRYPT_OK 0


struct EncryptData
{
	unsigned int vt;
	unsigned int state[5];
	char code[0x40];
	unsigned int  curlen;
	unsigned int  count;
};

#ifdef SHA1
struct sha1_state {
	ulong64 length;
	ulong32 state[5], curlen;
	unsigned char buf[64];
};
#endif

#define CRYPT_INVALID_ARG -1
#define MIN(x, y) ( ((x)<(y))?(x):(y) )


#define STORE64H(x, y)                                                                     \
   { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); }

#define LOAD64H(x, y)                                                      \
   { x = (((ulong64)((y)[0] & 255))<<56)|(((ulong64)((y)[1] & 255))<<48) | \
         (((ulong64)((y)[2] & 255))<<40)|(((ulong64)((y)[3] & 255))<<32) | \
         (((ulong64)((y)[4] & 255))<<24)|(((ulong64)((y)[5] & 255))<<16) | \
         (((ulong64)((y)[6] & 255))<<8)|(((ulong64)((y)[7] & 255))); }


#define STORE32H(x, y)                                                                     \
     { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); }

void crypt_argchk(const char *v, const char *s, int d)
{
	return;
}
#define LTC_ARGCHK(x) if (!(x)) { crypt_argchk(#x, __FILE__, __LINE__); }

#define HASH_PROCESS(func_name, compress_name, state_var, block_size)                       \
int func_name (hash_state * md, const unsigned char *in, unsigned long inlen)               \
{                                                                                           \
    unsigned long n;                                                                        \
    int           err;                                                                      \
    LTC_ARGCHK(md != NULL);                                                                 \
    LTC_ARGCHK(in != NULL);                                                                 \
    if (md-> state_var .curlen > sizeof(md-> state_var .buf)) {                             \
       return CRYPT_INVALID_ARG;                                                            \
    }                                                                                       \
    while (inlen > 0) {                                                                     \
        if (md-> state_var .curlen == 0 && inlen >= block_size) {                           \
           if ((err = compress_name (md, (unsigned char *)in)) != CRYPT_OK) {               \
              return err;                                                                   \
           }                                                                                \
           md-> state_var .length += block_size * 8;                                        \
           in             += block_size;                                                    \
           inlen          -= block_size;                                                    \
        } else {                                                                            \
           n = MIN(inlen, (block_size - md-> state_var .curlen));                           \
           memcpy(md-> state_var .buf + md-> state_var.curlen, in, (size_t)n);              \
           md-> state_var .curlen += n;                                                     \
           in             += n;                                                             \
           inlen          -= n;                                                             \
           if (md-> state_var .curlen == block_size) {                                      \
              if ((err = compress_name (md, md-> state_var .buf)) != CRYPT_OK) {            \
                 return err;                                                                \
              }                                                                             \
              md-> state_var .length += 8*block_size;                                       \
              md-> state_var .curlen = 0;                                                   \
           }                                                                                \
       }                                                                                    \
    }                                                                                       \
    return CRYPT_OK;                                                                        \
}


typedef union Hash_state {
	char dummy[1];
#ifdef CHC_HASH
	struct chc_state chc;
#endif
#ifdef WHIRLPOOL
	struct whirlpool_state whirlpool;
#endif
#ifdef SHA512
	struct sha512_state sha512;
#endif
#ifdef SHA256
	struct sha256_state sha256;
#endif
#ifdef SHA1
	struct sha1_state   sha1;
#endif
#ifdef MD5
	struct md5_state    md5;
#endif
#ifdef MD4
	struct md4_state    md4;
#endif
#ifdef MD2
	struct md2_state    md2;
#endif
#ifdef TIGER
	struct tiger_state  tiger;
#endif
#ifdef RIPEMD128
	struct rmd128_state rmd128;
#endif
#ifdef RIPEMD160
	struct rmd160_state rmd160;
#endif
#ifdef RIPEMD256
	struct rmd256_state rmd256;
#endif
#ifdef RIPEMD320
	struct rmd320_state rmd320;
#endif
	void *data;
} hash_state;

#define LOAD32H(x, y)                            \
     { x = ((unsigned long)((y)[0] & 255)<<24) | \
           ((unsigned long)((y)[1] & 255)<<16) | \
           ((unsigned long)((y)[2] & 255)<<8)  | \
           ((unsigned long)((y)[3] & 255)); }

#define ROL(x, y) ( (((unsigned long)(x)<<(unsigned long)((y)&31)) | (((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROR(x, y) ( ((((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)((y)&31)) | ((unsigned long)(x)<<(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROLc(x, y) ( (((unsigned long)(x)<<(unsigned long)((y)&31)) | (((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define RORc(x, y) ( ((((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)((y)&31)) | ((unsigned long)(x)<<(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)


//const struct ltc_hash_descriptor sha1_desc =
//{
//    "sha1",
//    2,
//    20,
//    64,
//
//    /* OID */
//   { 1, 3, 14, 3, 2, 26,  },
//   6,
//
//    &sha1_init,
//    &sha1_process,
//    &sha1_done,
//    &sha1_test,
//    NULL
//};

#define F0(x,y,z)  (z ^ (x & (y ^ z)))
#define F1(x,y,z)  (x ^ y ^ z)
#define F2(x,y,z)  ((x & y) | (z & (x | y)))
#define F3(x,y,z)  (x ^ y ^ z)

#ifdef LTC_CLEAN_STACK
static int _sha1_compress(hash_state *md, unsigned char *buf)
#else
static int  sha1_compress(hash_state *md, unsigned char *buf)
#endif
{
    ulong32 a,b,c,d,e,W[80],i;
#ifdef LTC_SMALL_CODE
    ulong32 t;
#endif

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++) {
        LOAD32H(W[i], buf + (4*i));
    }

    /* copy state */
    a = md->sha1.state[0];
    b = md->sha1.state[1];
    c = md->sha1.state[2];
    d = md->sha1.state[3];
    e = md->sha1.state[4];

    /* expand it */
    for (i = 16; i < 80; i++) {
        W[i] = ROL(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1); 
    }

    /* compress */
    /* round one */
    #define FF0(a,b,c,d,e,i) e = (ROLc(a, 5) + F0(b,c,d) + e + W[i] + 0x5a827999UL); b = ROLc(b, 30);
    #define FF1(a,b,c,d,e,i) e = (ROLc(a, 5) + F1(b,c,d) + e + W[i] + 0x6ed9eba1UL); b = ROLc(b, 30);
    #define FF2(a,b,c,d,e,i) e = (ROLc(a, 5) + F2(b,c,d) + e + W[i] + 0x8f1bbcdcUL); b = ROLc(b, 30);
    #define FF3(a,b,c,d,e,i) e = (ROLc(a, 5) + F3(b,c,d) + e + W[i] + 0xca62c1d6UL); b = ROLc(b, 30);
 
#ifdef LTC_SMALL_CODE
 
    for (i = 0; i < 20; ) {
       FF0(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 40; ) {
       FF1(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 60; ) {
       FF2(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 80; ) {
       FF3(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

#else

    for (i = 0; i < 20; ) {
       FF0(a,b,c,d,e,i++);
       FF0(e,a,b,c,d,i++);
       FF0(d,e,a,b,c,i++);
       FF0(c,d,e,a,b,i++);
       FF0(b,c,d,e,a,i++);
    }

    /* round two */
    for (; i < 40; )  { 
       FF1(a,b,c,d,e,i++);
       FF1(e,a,b,c,d,i++);
       FF1(d,e,a,b,c,i++);
       FF1(c,d,e,a,b,i++);
       FF1(b,c,d,e,a,i++);
    }

    /* round three */
    for (; i < 60; )  { 
       FF2(a,b,c,d,e,i++);
       FF2(e,a,b,c,d,i++);
       FF2(d,e,a,b,c,i++);
       FF2(c,d,e,a,b,i++);
       FF2(b,c,d,e,a,i++);
    }

    /* round four */
    for (; i < 80; )  { 
       FF3(a,b,c,d,e,i++);
       FF3(e,a,b,c,d,i++);
       FF3(d,e,a,b,c,i++);
       FF3(c,d,e,a,b,i++);
       FF3(b,c,d,e,a,i++);
    }
#endif

    #undef FF0
    #undef FF1
    #undef FF2
    #undef FF3

    /* store */
    md->sha1.state[0] = md->sha1.state[0] + a;
    md->sha1.state[1] = md->sha1.state[1] + b;
    md->sha1.state[2] = md->sha1.state[2] + c;
    md->sha1.state[3] = md->sha1.state[3] + d;
    md->sha1.state[4] = md->sha1.state[4] + e;

    return CRYPT_OK;
}

#ifdef LTC_CLEAN_STACK
static int sha1_compress(hash_state *md, unsigned char *buf)
{
   int err;
   err = _sha1_compress(md, buf);
   burn_stack(sizeof(ulong32) * 87);
   return err;
}
#endif

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/

int sha1_init(hash_state * md)
{
   //LTC_ARGCHK(md != NULL);
   md->sha1.state[0] = 0x67452301UL;
   md->sha1.state[1] = 0xefcdab89UL;
   md->sha1.state[2] = 0x98badcfeUL;
   md->sha1.state[3] = 0x10325476UL;
   md->sha1.state[4] = 0xc3d2e1f0UL;
   md->sha1.curlen = 0;
   md->sha1.length = 0;
   return CRYPT_OK;
}

int Encrypt_init(EncryptData * md)
{
	//LTC_ARGCHK(md != NULL);
	md->state[0] = 0x67452301UL;
	md->state[1] = 0xefcdab89UL;
	md->state[2] = 0x98badcfeUL;
	md->state[3] = 0x10325476UL;
	md->state[4] = 0xc3d2e1f0UL;
	md->curlen = 0;
	md->count = 0;
	return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
HASH_PROCESS(sha1_process, sha1_compress, sha1, 64)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (20 bytes)
   @return CRYPT_OK if successful
*/
int sha1_done(hash_state * md, unsigned char *out)
{
    int i;

    LTC_ARGCHK(md  != NULL);
    LTC_ARGCHK(out != NULL);

    if (md->sha1.curlen >= sizeof(md->sha1.buf)) {
       return CRYPT_INVALID_ARG;
    }

    /* increase the length of the message */
    md->sha1.length += md->sha1.curlen * 8;

    /* append the '1' bit */
    md->sha1.buf[md->sha1.curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->sha1.curlen > 56) {
        while (md->sha1.curlen < 64) {
            md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
        }
        sha1_compress(md, md->sha1.buf);
        md->sha1.curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->sha1.curlen < 56) {
        md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64H(md->sha1.length, md->sha1.buf+56);
    sha1_compress(md, md->sha1.buf);

    /* copy output */
    for (i = 0; i < 5; i++) {
        STORE32H(md->sha1.state[i], out+(4*i));
    }
#ifdef LTC_CLEAN_STACK
    zeromem(md, sizeof(hash_state));
#endif
    return CRYPT_OK;
}

#define LTC_TEST 1
#define CRYPT_NOP -2


#define byte0(x) (x & 0xff)
#define byte1(x) ((x >> 8) & 0xff)
#define byte2(x) ((x >> 16) & 0xff)
#define byte3(x) ((x >> 24) & 0xff)



unsigned int _byteswap_ulong(unsigned int code) {
	

	unsigned int ret  = byte0(code) << 24 | byte1(code) << 16 | byte2(code) << 8 | byte3(code);


	return ret;
}


typedef unsigned int uint;


template<class T> T __ROL__(T value, int count)
{
	const uint nbits = sizeof(T) * 8;

	if (count > 0)
	{
		count %= nbits;
		T high = value >> (nbits - count);
		if (T(-1) < 0) // signed value
			high &= ~((T(-1) << count));
		value <<= count;
		value |= high;
	}
	else
	{
		count = -count % nbits;
		T low = value << (nbits - count);
		value >>= count;
		value |= low;
	}
	return value;
}

typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;
typedef unsigned long long uint64;


inline uint8  __ROL1__(uint8  value, int count) { return __ROL__((uint8)value, count); }
inline uint16 __ROL2__(uint16 value, int count) { return __ROL__((uint16)value, count); }
inline uint32 __ROL4__(uint32 value, int count) { return __ROL__((uint32)value, count); }
inline uint64 __ROL8__(uint64 value, int count) { return __ROL__((uint64)value, count); }
inline uint8  __ROR1__(uint8  value, int count) { return __ROL__((uint8)value, -count); }
inline uint16 __ROR2__(uint16 value, int count) { return __ROL__((uint16)value, -count); }
inline uint32 __ROR4__(uint32 value, int count) { return __ROL__((uint32)value, -count); }
inline uint64 __ROR8__(uint64 value, int count) { return __ROL__((uint64)value, -count); }



int Encrypt_sha1(EncryptData *thz)
{
	int i; 
	int j; 
	unsigned int *buf_Adr; 
	int bufValue; 
	unsigned int a; 
	unsigned int idx; 
	unsigned int b; 
	unsigned int c; 
	unsigned int d; 
	unsigned int e; 
	unsigned int HashCode1; 
	unsigned int HashCode2; 
	unsigned int HashCode3; 
	unsigned int HashCode4; 
	int HashCode5; 
	int HashCode6;
	unsigned int e1; 
	unsigned int d1; 
	unsigned int c1;
	unsigned int b1; 
	unsigned int dw_swapBuffer[80]; 


	for (i = 0; i != 16; ++i)
		dw_swapBuffer[i] = _byteswap_ulong(*(unsigned int *)&thz->code[i * 4]);
	for (j = 0; j != 64; ++j)
	{
		buf_Adr = &dw_swapBuffer[j];
		bufValue = dw_swapBuffer[j];               
		buf_Adr[16] = __ROR4__(buf_Adr[2] ^ buf_Adr[8] ^ buf_Adr[13] ^ bufValue, 31);
	}
	a = thz->state[0];
	idx = 0;
	b = thz->state[1];
	c = thz->state[2];
	d = thz->state[3];
	e = thz->state[4];
	b1 = b;
	c1 = c;
	d1 = d;
	e1 = e;
	do
	{
		HashCode1 = a;
		HashCode2 = c;
		HashCode3 = d;
		if (idx > 0x13)
		{
			if (idx > 0x27)
			{
				if (idx > 0x3B)
				{
					HashCode4 = 0xCA62C1D6;
					HashCode5 = c ^ b ^ d;
				}
				else
				{
					HashCode4 = 0x8F1BBCDC;
					HashCode5 = (d | c) & b | d & c;
				}
			}
			else
			{
				HashCode4 = 0x6ED9EBA1;
				HashCode5 = c ^ b ^ d;
			}
		}
		else
		{
			HashCode4 = 1518500249;
			HashCode5 = d & ~b | c & b;
		}
		HashCode6 = dw_swapBuffer[idx++];
		a = e + __ROR4__(a, 27) + HashCode5 + HashCode4 + HashCode6;
		c = __ROR4__(b, 2);
		e = d;
		d = HashCode2;
		b = HashCode1;
	} while (idx != 0x50);
	thz->state[0] += a;
	thz->state[1] = b1 + HashCode1;
	thz->state[2] = c + c1;
	thz->state[3] = d1 + HashCode2;
	thz->state[4] = e1 + HashCode3;

	return 0;
}


EncryptData * EncryptString(EncryptData *thz, char data)
{
	unsigned int idx; // r0

	idx = thz->curlen;
	thz->curlen = idx + 1;
	thz->code[idx] = data;
	++thz->count;
	if (thz->curlen == 0x40)
	{
		thz->curlen = 0;
		Encrypt_sha1(thz);
	}
	return thz;
}

unsigned int * Encrypt_Done(EncryptData *thz, unsigned int *outBuffer)
{
	unsigned int count; // r6
	unsigned int v5; // r0
	bool v6; // cf
	unsigned int *v7; // r0
	unsigned int v8; // r2
	unsigned int v9; // r3
	unsigned int v10; // r4
	unsigned int v11; // r5
	unsigned int v12; // r6
	unsigned int *result; // r0

	count = thz->count;
	EncryptString(thz, 128);
	v5 = thz->curlen;
	v6 = v5 >= 0x38;
	if (v5 <= 0x38)
	{
		while (!v6)
		{
			EncryptString(thz, 0);
			v6 = thz->curlen >= 0x38;
		}
	}
	else
	{
		do
			EncryptString(thz, 0);
		while (thz->curlen);
		do
			EncryptString(thz, 0);
		while (thz->curlen < 0x38);
	}
	EncryptString(thz, 0);
	EncryptString(thz, 0);
	EncryptString(thz, 0);
	EncryptString(thz, 0);
	EncryptString(thz, count >> 21);
	EncryptString(thz, count >> 13);
	EncryptString(thz, count >> 5);
	EncryptString(thz, 8 * count);
	v7 = thz->state;
	v8 = thz->state[0];
	v9 = thz->state[1];
	v10 = thz->state[2];
	v11 = thz->state[3];
	v12 = v7[4];
	result = outBuffer;
	*outBuffer = v8;
	outBuffer[1] = v9;
	outBuffer[2] = v10;
	outBuffer[3] = v11;
	outBuffer[4] = v12;

	return result;
}

int EncryptString(unsigned char* buffer, size_t length, std::string& outMigdest) {

	unsigned int outData[100];

	EncryptData curEncryptData;
	Encrypt_init(&curEncryptData);

	for (size_t i = 0; i < length; i++)
	{
		EncryptString(&curEncryptData, buffer[i]);
	}

	Encrypt_Done(&curEncryptData, (unsigned int *)&outData);

	char msg[0x100] = { 0 };
	sprintf_s(msg, "%08x%08x%08x%08x%08x", outData[0], outData[1], outData[2], outData[3], outData[4]);

	outMigdest = msg;

	return 0;
}

int DigestString(char* szSrc1, char* szSrc2, std::string& outMigdest) {

	std::string sigHashcode = "c2250918de500e32c37842f2d25d4d8210992a0ae96a7f36c4c9703cc675d02b92968bc4fa7feada";

	sigHashcode.append(szSrc1);
	sigHashcode.append(szSrc2);

	EncryptString((unsigned char*)sigHashcode.c_str(), sigHashcode.length(), outMigdest);

	return 0;
}
