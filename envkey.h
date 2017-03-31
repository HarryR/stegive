#ifndef ENVKEY_H_
#define ENVKEY_H_


typedef struct {
	unsigned argc;
	unsigned char *args;
} envkey_t;

typedef int (*envkey_cb_t)(const unsigned char *keyhash, void *ctx);

void envkey_init( envkey_t *env, unsigned argc, char **argv );
void envkey_add( envkey_t *env, const unsigned char *arg, unsigned arg_len );
void envkey_addstr( envkey_t *env, const char *arg );
int envkey_powerset( envkey_t *env, envkey_cb_t cb_fn, void *cb_ctx );
void envkey_combine( int argc, unsigned char **argv, unsigned char *out );

#endif
/* ENVKEY_H_ */
