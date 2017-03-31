#ifndef ENVKEY_C_
#define ENVKEY_C_

#include <string.h>
#include <stdlib.h>

#include "tweetnacl.h"
#include "envkey.h"


void
envkey_add( envkey_t *env, const unsigned char *arg, unsigned arg_len )
{
	if( env && (env->args = realloc(env->args, (env->argc + 1) * crypto_hash_BYTES)) )
	{
		crypto_hash(&env->args[env->argc++ * crypto_hash_BYTES], arg, arg_len);
	}
}


void
envkey_addstr( envkey_t *env, const char *arg )
{
	envkey_add(env, (const unsigned char *)arg, strlen(arg));
}


void
envkey_init( envkey_t *env, unsigned argc, char **argv )
{
	unsigned i;
	memset(env, 0, sizeof(*env));

	if( argc && argv ) {		
		for( i = 0; i < argc; i++ ) {
			envkey_addstr(env, argv[i]);
		}
	}
}


struct
powerset_node
{
	unsigned char *ptr;
	struct powerset_node* prev;
};


static int
_envkey_powerset_impl(int K, unsigned char *data, struct powerset_node *up, envkey_cb_t cb_fn, void *cb_ctx)
{
	struct powerset_node me;
	unsigned char hashed[crypto_hash_BYTES];
	int ret = 0;
 
	if( ! K )
	{
		memset(hashed, 0, sizeof(hashed));
		while (up)
		{
			for( size_t N = 0; N < sizeof(hashed); N++ )
				hashed[N] ^= up->ptr[N];
			
			up = up->prev;
		}

		if( cb_fn && (ret = cb_fn(hashed, cb_ctx)) ) {
			return ret;
		}
	}
	else {
		me.ptr = data;
		me.prev = up;
		if( ! (ret = _envkey_powerset_impl(K - 1, data + crypto_hash_BYTES, up, cb_fn, cb_ctx)) ) {
			ret = _envkey_powerset_impl(K - 1, data + crypto_hash_BYTES, &me, cb_fn, cb_ctx);
		}		
	}
	return ret;
}


int
envkey_powerset( envkey_t *env, envkey_cb_t cb_fn, void *cb_ctx ) {
	return _envkey_powerset_impl(env->argc, env->args, NULL, cb_fn, cb_ctx);
}


void
envkey_combine( int argc, unsigned char **argv, unsigned char *out )
{
	unsigned char tmp[crypto_hash_BYTES];
	int N, K;

	for( N = 0; N < argc; N++ )
	{
		crypto_hash(tmp, argv[N], strlen((char*)argv[N]));

		for( K = 0; K < crypto_hash_BYTES; K++ )
			out[K] ^= tmp[K];
	}
}


#ifdef envkey_MAIN

#include <stdio.h>

static int
check_key( unsigned char *key, unsigned char *expected )
{
	return 0 == memcmp(key, expected, crypto_hash_BYTES);
}


int
main( int argc, char **argv )
{
	envkey_t env;
	unsigned char key[crypto_hash_BYTES];
	memset(key, 0, crypto_hash_BYTES);
	int i;

	if( argc < 2 )
	{
		printf("Usage: envkey.exe <arg> [arg ...]\n");
		printf("Example: envkey.exe Linux x86_64\n");
		printf("Example: envkey.exe x86_64 Linux\n");
		printf("Example: envkey.exe Oranges Apples Pears\n");
		return 1;
	}

	envkey_combine(argc - 1, (unsigned char **)&argv[1], key);

	for( i = 0; i < crypto_hash_BYTES; i++ ) {
		printf("%02X", key[i]);
	}
	printf("\n");

	envkey_init(&env, argc - 1, &argv[1]);
	envkey_powerset(&env, (envkey_cb_t)check_key, &key[0]);

	return 0;
}

#endif
/* envkey_MAIN */

#endif
/* ENVKEY_C_ */
