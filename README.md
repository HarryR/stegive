# Encrypted Steganographic Archive

`stegive` lets you pack many datastreams into a single encrypted archive,
knowing the secret key to extract one datastream gives you no knowledge about 
the existence of others in the same archive - all that can be determined is 
that more blocks exist which weren't part of that stream.

Example:

    $ ./pack.py *.c > test.bin
    $ ./stegive test.bin tweetnacl.c

## Archive Format

Archive Header:

 * `nblks` - Total number of blocks in archive
 * `outer_sz` - Size, in bytes, of encrypted block
 * `frame_sz` - Size, in bytes, of decrypted packet / frame
 * `inner_sz` - Max number of data which can be stored per frame

Block Frame:

 * `next` - Next block ID, or 0xFFFFFFFF if EOF
 * ... datastream bytes

Stream Header (`bhdr_t`):

 * `nblocks` - Total number of blocks
 * `nbytes` - Total number of bytes, spread across blocks
 * `magic` - Equivalent to a mime-type or action identifier
 * ... datastream bytes follow

## Encryption & Decryption

NaCl secret boxes are used to encrypt and decrypt the contents of blocks. Each
block incurs a 16 byte overhead for the Poly1305 MAC.

The nonce used by the secret box is a SHA512 hash of the secret key for the 
data stream, concatenated with the current block sequence number and byte 
offset within the datastream. This hash is truncated to 24 bytes. See
`pack.py::calc_nonce`

To find the first block of a datastream the nonce is calculated for the secret 
key using 0 and 0 as the block sequence number and the byte offset. The first 
4 bytes of the nonce are converted to a 32bit unsigned int and modulous'd 
against the total number of blocks in the archive. While packing an archive
care must be taken that all of the start blocks can be looked up in this way.