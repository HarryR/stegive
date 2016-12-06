#include "stegive.h"

#include <stdio.h>

// open
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// mmap
#include <sys/mman.h>

// memset
#include <string.h>


static void
file_fwrite(stegive_t *archive, FILE *output, const char *secret)
{
	filehdl_t handle;
	u8 *buf;
	u32 len;

	if( ! (buf = file_open(archive, secret, &handle, &len)) ) {
		fprintf(stderr, "Error: failed to open with secret: %s\n", secret);
		return;
	}

	fwrite(buf, len, 1, output);

	if( file_hasnext(&handle) )
	{
		do {
			if( ! (buf = file_read(&handle, &len)) )
			{
				fprintf(stderr, "Fail!\n");
				break;
			}
			fwrite(buf, len, 1, output);
		} while( file_hasnext(&handle) );
	}
}


static int
stegive_open( stegive_t *archive, const char *filename ) {
	int archive_fd = -1;
	struct stat archive_stat;
	void *archive_data;

	archive_fd = open(filename, O_RDONLY);
	if( archive_fd == -1 ) {
		perror("open");
		return 2;
	}

	if( -1 == fstat(archive_fd, &archive_stat) ) {
		perror("fstat");
		return 3;
	}

	archive_data = mmap(NULL, archive_stat.st_size, PROT_READ, MAP_SHARED, archive_fd, 0);
	if( MAP_FAILED == archive_data ) {
		perror("mmap");
	}

	memset(archive, 0, sizeof(*archive));
	archive->enc_nblks = archive_stat.st_size / STEGIVE_OUTER_SZ;
	archive->enc_outersz = STEGIVE_OUTER_SZ;
	archive->innersz = STEGIVE_INNER_SZ;
	archive->enc_framesz = STEGIVE_FRAME_SZ;
	archive->data = archive_data;
	archive->data_sz = archive_stat.st_size;

	return 0;
}


static void
stegive_close( stegive_t *archive ) {
	munmap(archive->data, archive->data_sz);
	memset(archive, 0, sizeof(*archive));
}


int
main(int argc, char **argv)
{
	int N = 2;
	stegive_t archive;

	if( argc < 3 ) {
		fprintf(stderr, "Usage: %s <file> <key> [key...]\n", argv[0]);
		return 1;
	}

	if( stegive_open(&archive, argv[1]) )
		return 2;

	for( N = N ; N < argc; N++ )
		file_fwrite(&archive, stdout, argv[N]);

	stegive_close(&archive);

	return 0;
}
