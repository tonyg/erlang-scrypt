 #include <string.h>

#include "erl_nif.h"

#include "crypto_scrypt.h"

extern int crypto_scrypt(
        const uint8_t * passwd, size_t passwdlen,
        const uint8_t * salt, size_t saltlen,
        uint64_t N, uint32_t r, uint32_t p,
        uint8_t * buf, size_t buflen);

static ERL_NIF_TERM scrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    argc = argc; // for unused variable warning

    ErlNifBinary passwd;
    ErlNifBinary salt;
    ErlNifUInt64 N, r, p, buflen;

    ErlNifBinary hash;

    if (!enif_inspect_binary(env, argv[0], &passwd))    return enif_make_badarg(env);
    if (!enif_inspect_binary(env, argv[1], &salt))      return enif_make_badarg(env);
    if (!enif_get_uint64(env, argv[2], &N))             return enif_make_badarg(env);
    if (!enif_get_uint64(env, argv[3], &r))             return enif_make_badarg(env);
    if (!enif_get_uint64(env, argv[4], &p))             return enif_make_badarg(env);
    if (!enif_get_uint64(env, argv[5], &buflen))        return enif_make_badarg(env);

    if(!enif_alloc_binary((size_t)buflen, &hash))       return enif_make_badarg(env);

    if (crypto_scrypt((const uint8_t*)passwd.data, (size_t)passwd.size,
                (const uint8_t*)salt.data, (size_t)salt.size, (uint64_t)N, (uint64_t)r, (uint64_t)p,
                (uint8_t*)hash.data, (size_t)hash.size)) {
      return enif_make_badarg(env);
    }

    return enif_make_binary(env, &hash);
}

static ErlNifFunc nif_funcs[] = {
    {"scrypt", 6, scrypt}
};

ERL_NIF_INIT(scrypt_nif, nif_funcs, NULL, NULL, NULL, NULL)
