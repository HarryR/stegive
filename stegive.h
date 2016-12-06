#ifndef STEGIVE_H_
#define STEGIVE_H_


#ifndef TWEETNACL_H_
#include "tweetnacl.h"
#endif

typedef unsigned char u8;
typedef unsigned int uint;
#ifdef __POCC__
#include <stdint.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t i64;
#else
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;
#endif


#ifdef __GNUC__
#define PACKED( class_to_pack ) class_to_pack __attribute__((__packed__))
#elif defined(_MSC_VER) && ! defined(__POCC__)
#define PACKED( class_to_pack ) __pragma( pack(push, 1) ) class_to_pack __pragma( pack(pop) )
#else
#define PACKED( class_to_pack ) class_to_pack
#endif

enum {
	STEGIVE_OUTER_SZ = 519,
	STEGIVE_FRAME_SZ = 503,
	STEGIVE_INNER_SZ = 499
};

PACKED(struct bhdr_s
{
	u32 nblocks : 32;
	u32 nbytes : 32;
	u32 magic : 32;
});
typedef struct bhdr_s bhdr_t;

PACKED(struct bfrm_s 
{
	u32 next : 32;
	union {
		bhdr_t hdr;
		u8 data[STEGIVE_INNER_SZ];
	};
});
typedef struct bfrm_s bfrm_t;

PACKED(struct bdat_s
{
	u8 prefix[crypto_secretbox_ZEROBYTES];
	union {
		u8 data[STEGIVE_FRAME_SZ];
		bfrm_t frame;
	};
	uint len;
	uint offset;
});
typedef struct bdat_s bdat_t;

PACKED(struct nonce_s {
	u8 secret[crypto_hash_BYTES];
	u32 innerno : 32;
	u32 offset : 32;
});
typedef struct nonce_s nonce_t;

PACKED(struct stegive_s {
	u32 innersz : 32;
	u32 enc_nblks : 32;
	u32 enc_outersz : 32;
	u32 enc_framesz : 32;
	u8 *data;
	uint data_sz;
});
typedef struct stegive_s stegive_t;

typedef struct {
	stegive_t *archive;

	nonce_t nonce;
	bhdr_t hdr;
	bdat_t dat;

	uint cur_outer;
	uint next_outer;
	uint cur_offset;
} filehdl_t;


u8* file_buf(filehdl_t *handle, u32 *len);
u8* file_read(filehdl_t *handle, u32 *len);
int file_hasnext(filehdl_t *handle);
u32 file_len(filehdl_t *handle);
u8* file_open(stegive_t *archive, const char *secret, filehdl_t *handle, u32 *out_len);


#endif
