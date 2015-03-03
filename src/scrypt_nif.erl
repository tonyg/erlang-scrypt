-module(scrypt_nif).
-export([scrypt/6]).
-on_load(init/0).

init() ->
    ok = erlang:load_nif(erlscrypt:priv_dir() ++ "/scrypt_nif", 0).

scrypt(_Passwd, _Salt, _N, _R, _P, _Buflen) ->
    exit(nif_library_not_loaded).
