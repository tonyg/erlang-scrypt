#include <string.h>

#include "erl_nif.h"

#include "scrypt.h"

static ERL_NIF_TERM scrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    argc = argc; // for unused variable warning

    ErlNifBinary passwd;
    ErlNifBinary salt;
    ErlNifUInt64 N, buflen;
	uint32_t r, p;

    ErlNifBinary hash;

    if (!enif_inspect_binary(env, argv[0], &passwd))    return enif_make_badarg(env);
    if (!enif_inspect_binary(env, argv[1], &salt))      return enif_make_badarg(env);
    if (!enif_get_uint64	(env, argv[2], &N))         return enif_make_badarg(env);
    if (!enif_get_uint		(env, argv[3], &r))         return enif_make_badarg(env);
    if (!enif_get_uint		(env, argv[4], &p))         return enif_make_badarg(env);
    if (!enif_get_uint64	(env, argv[5], &buflen))    return enif_make_badarg(env);

    if(!enif_alloc_binary((size_t)buflen, &hash))       return enif_make_badarg(env);

    if (crypto_scrypt((const uint8_t*)passwd.data, passwd.size,
					  (const uint8_t*)salt.data,   salt.size,
					  N, r, p,
					  (uint8_t*)(hash.data), hash.size)) {
      return enif_make_badarg(env);
    }

    return enif_make_binary(env, &hash);
}

int upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

static ErlNifFunc nif_funcs[] = {
    {"scrypt", 6, scrypt}
};

ERL_NIF_INIT(scrypt_nif, nif_funcs, NULL, NULL, upgrade, NULL)
