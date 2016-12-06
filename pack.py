#!/usr/bin/env python
from __future__ import print_function
from struct import pack, unpack
import sys
import os.path
from os import urandom
from collections import namedtuple
from random import shuffle, randint
from binascii import hexlify
from nacl.secret import SecretBox
from nacl.hash import sha512
from nacl.encoding import RawEncoder


# XXX: outer len is fixed... but used to be flexible
MAX_OUTER_LEN = 519  # randint(512, 1024)
BLOCK_OVERHEAD = 16 + 4
FILE_HDR_LEN = 12
FRAME_LEN = MAX_OUTER_LEN - BLOCK_OVERHEAD + 4
MAX_INNER_LEN = MAX_OUTER_LEN - BLOCK_OVERHEAD
MAGIC_DEFAULT = 1234


Block = namedtuple('Block', [
	'fileno', 'N', 'offset', 'secret', 'data'
])


FileEntry = namedtuple('FileEntry', [
	'fileno', 'secret', 'filename',
])


def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)


def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]


def split_file(secret, infile):
	indata = open(infile, 'rb').read()
	indata_hdr = indata[:2]
	total_len = len(indata) + FILE_HDR_LEN
	output = []
	header_added = False
	while len(indata):
		bytecnt = MAX_INNER_LEN
		if not header_added:
			bytecnt -= FILE_HDR_LEN
			header_added = True
		if bytecnt > len(indata):
			bytecnt = len(indata)
		data, indata = indata[:bytecnt], indata[bytecnt:]
		assert len(data) <= MAX_INNER_LEN
		output.append(data)		
	extn = os.path.splitext(infile)[1]
	magic = MAGIC_DEFAULT
	header = pack('<III', len(output), total_len, magic)
	assert len(header) == FILE_HDR_LEN
	output[0] = header + output[0]
	assert len(output[0]) <= MAX_INNER_LEN
	return output


def pad_inner(block, max_len=MAX_INNER_LEN):
	if len(block) < max_len:
		return block + ("\0" * (max_len - len(block)))
	return block


def calc_start_block(secret, nblocks):
	return unpack('<I', sha512(secret, encoder=RawEncoder)[:4])[0] % nblocks


def verify_start_blocks(appendix, datablocks):
	for entry in appendix:
		expected = calc_start_block(entry.secret, len(datablocks))
		actual = datablocks[expected]		
		assert actual[0] == entry.fileno
		assert actual[1] == 0


def find_block_start(datablocks, fileno):
	for N, block in enumerate(datablocks):
		if block[0] == fileno and block[1] == 0:
			return N
	raise RuntimeError("NotFound")


def reposition_starts(appendix, data):
	for entry in appendix:
		A = find_block_start(data, entry.fileno)
		B = calc_start_block(entry.secret, len(data))
		data[B], data[A] = data[A], data[B]
	return data


def output_data_bin(encrypted_blocks):
	for block in encrypted_blocks:
		sys.stdout.write(block)


def output_data_c(filename, encrypted_blocks):
	with open(filename, "w") as fh:
		fh.write("""
#ifndef DATA_C_
#define DATA_C_
		%s
		static const unsigned char g_enc_data[] = {
		""" % ("\n".join([
			"#define %s (%s)" % (k, v)
			for k, v in {
				'g_enc_nblks': len(encrypted_blocks),
				'g_enc_outersz': MAX_OUTER_LEN,
				'g_enc_framesz': MAX_INNER_LEN + 4,
				'g_enc_innersz': MAX_INNER_LEN
			}.items()])))
		X = False
		for block in encrypted_blocks:
			X = fh.write(
				("\n," if X else " ") + 
				",".join(["0x%02X" % (ord(B),)
					  for B in block])
			) or True
		fh.write("};\n#endif\n\n")


def files_to_blocks(filenames):
	datablocks = []
	appendix = []
	for fileno, filename in enumerate(filenames):
		secret = filename
		if not os.path.exists(filename):
			eprint("Warning: file not found: " + filename)
			continue
		offset = 0
		for N, data in enumerate(split_file(secret, filename)):
			datablocks.append( Block(fileno, N, offset, secret, data) )
			offset += len(data)
		entry = FileEntry(fileno, secret, filename)
		appendix.append(entry)
	while True:
		starts = [calc_start_block(entry.secret, len(datablocks))
				  for entry in appendix]
		if len(set(starts)) == len(appendix):
			break
		datablocks.append(Block(randint(0x00FFFFFF, 0xFFFFFFFF), 0, 0, urandom(30), urandom(10)))
	return appendix, datablocks


def calc_nonce(key, innerno, offset):
	raw_nonce = key + pack("<I", innerno) + pack("<I", offset)
	return sha512(raw_nonce, encoder=RawEncoder)[:SecretBox.NONCE_SIZE]


def generate_blocks(filenames, debug):
	appendix, datablocks = files_to_blocks(filenames)
	if not appendix:
		eprint("Error: start confict")
		sys.exit(1)
	for X in range(1, 1000):
		shuffle(datablocks)
	datablocks = reposition_starts(appendix, datablocks)
	verify_start_blocks(appendix, datablocks)
	if debug:
		for filename in filenames:
			key = sha512(filename, encoder=RawEncoder)
			eprint("%4X %s  %02X %s %s" % (
				calc_start_block(filename, len(datablocks)),
				sha512(filename)[:8], len(key) + 8,
				hexlify(calc_nonce(key, 0, 0)[:4]),
				filename
			))
		eprint("")
	return datablocks


def block_encrypt(block, nextid):
	key = sha512(block.secret, encoder=RawEncoder)
	nonce = calc_nonce(key, block.N, block.offset)
	box = SecretBox(key[:SecretBox.KEY_SIZE])
	data_padded = pack("<I", nextid) + pad_inner(block.data)
	return nonce, box.encrypt(data_padded, nonce).ciphertext


def encrypt_blocks(datablocks, debug):
	blockid_to_chunk = {}
	for V, block in enumerate([datablocks[N] for N in range(0, len(datablocks))]):
		key = "%08x%08x" % (block.fileno, block.N)
		blockid_to_chunk[key] = V
	output = []
	phys_offs = 0
	for P, block in enumerate(datablocks):
		next_chunkid = blockid_to_chunk.get("%08x%08x" % (block[0], block[1] + 1), 0xFFFFFFFF)		
		nonce, encrypted_data = block_encrypt(block, nextid=next_chunkid)
		assert len(encrypted_data) == MAX_OUTER_LEN
		output.append(encrypted_data)
		if debug:
			key = sha512(block.secret, encoder=RawEncoder)
			box = SecretBox(key[:SecretBox.KEY_SIZE])
			data = box.decrypt(encrypted_data, nonce)
			assert len(data) == FRAME_LEN
			eprint("%4X %8X %s %4X %s %s %8X %s" % (
				P, phys_offs, hexlify(encrypted_data[:4]), block.N,
				sha512(block.secret)[:8], hexlify(nonce[:4]),
				block.offset, sha512(data)[:8]
			))
		phys_offs += len(encrypted_data)
	return output


def main(args):
	if not args:
		eprint("Usage: pack.py <filename> [filename ...]")
		return
	debug = (args[0] == '-d')
	if debug:
		args = args[1:]
	output_data_bin(encrypt_blocks(generate_blocks(args, debug), debug))


if __name__ == "__main__":
	main(sys.argv[1:])

