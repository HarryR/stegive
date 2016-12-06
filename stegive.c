#ifndef STEGIVE_C_
#define STEGIVE_C_

#ifndef STEGIVE_H_
#include "stegive.h"
#endif

#ifndef TWEETNACL_H
#include "tweetnacl.h"
#endif

#include <string.h>

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif


const u8 *
block_ptr( filehdl_t *handle )
{
	uint blockno = handle->cur_outer;
	return (blockno >= handle->archive->enc_nblks) ? NULL : 
		&handle->archive->data[blockno * handle->archive->enc_outersz];
}


uint
block_start_outer( filehdl_t *handle )
{
	uint *first_uint = (uint*)(&handle->nonce.secret[0]);
	return *first_uint % handle->archive->enc_nblks;
}


static int
block_decrypt( filehdl_t *handle )
{
	u8 nonce[crypto_hash_BYTES];
	const u8 *encrypted_data;
	u8 inbuf[crypto_secretbox_BOXZEROBYTES + handle->archive->enc_outersz];
	crypto_hash(nonce, (u8*)(&handle->nonce), sizeof(nonce_t));

	encrypted_data = block_ptr(handle);
	memset(inbuf, 0, crypto_secretbox_BOXZEROBYTES);
	memcpy(&inbuf[crypto_secretbox_BOXZEROBYTES], encrypted_data,
		   handle->archive->enc_outersz);

	return 0 == crypto_secretbox_open(
		(u8*)&handle->dat, inbuf, sizeof(inbuf),
		nonce, handle->nonce.secret);
}


u8*
file_buf(filehdl_t *handle, u32 *len)
{
	if( len ) *len = handle->dat.len;
	return &handle->dat.frame.data[handle->dat.offset];
}


u8*
file_read(filehdl_t *handle, u32 *len)
{
	u32 nbytes;
	bdat_t *decrypted = &handle->dat;

	handle->cur_outer = handle->next_outer;
	memset(decrypted, 0, sizeof(decrypted->prefix));
	
	if( ! block_decrypt(handle) )
		return NULL;

	decrypted->offset = 0;

	if( handle->nonce.innerno == 0 ) {
		handle->hdr = decrypted->frame.hdr;
	}

	nbytes = decrypted->len = MIN(handle->archive->innersz,
								  handle->hdr.nbytes - handle->nonce.offset);

	if( ! handle->nonce.innerno ) {
		decrypted->len -= sizeof(bhdr_t);
		decrypted->offset += sizeof(bhdr_t);
	}

	handle->nonce.offset += nbytes;
	handle->nonce.innerno += 1;
	handle->next_outer = decrypted->frame.next;

	return file_buf(handle, len);
}


int
file_hasnext(filehdl_t *handle)
{
	return handle->next_outer < 0xFFFFFFFF ? 1 : 0;
}


u32
file_len( filehdl_t *handle )
{
	return handle->hdr.nbytes;
}


u8*
file_open(stegive_t *archive, 
		  const char *secret, filehdl_t *handle, u32 *out_len)
{
	memset(handle, 0, sizeof(*handle));
	handle->archive = archive;
	handle->nonce.innerno = 0;
	handle->nonce.offset = 0;

	crypto_hash(handle->nonce.secret, (u8*)secret, strlen(secret));
	handle->next_outer = block_start_outer(handle);

	return file_read(handle, out_len);
}


#endif
