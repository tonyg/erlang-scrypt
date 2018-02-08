-module(erlscrypt).

-behaviour(application).
-behaviour(supervisor).

% application callbacks
-export([start/2, stop/1]).

% supervisor callbacks
-export([init/1]).

% shell interface
-export([start/0, stop/0]).

% External API
-export([scrypt/6, scrypt/7]).

% Internal library API
-export([priv_dir/0]).

start() -> application:start(?MODULE).
stop() -> application:stop(?MODULE).

scrypt(Passwd, Salt, N, R, P, Buflen) ->
    scrypt_port:scrypt(Passwd, Salt, N, R, P, Buflen).

scrypt(nif, Passwd, Salt, N, R, P, Buflen) ->
    scrypt_nif:scrypt(Passwd, Salt, N, R, P, Buflen).

priv_dir() ->
    case code:priv_dir(?MODULE) of
        {error, bad_name} ->
            filename:join(
              filename:dirname(
                filename:dirname(
                  code:which(?MODULE))), "priv");
        D -> D
    end.

%% ----------------------------------------------------------------------------
%% Applciation callbacks
%% ----------------------------------------------------------------------------
start(_StartType, _StartArgs) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

stop(_State) ->
    ok.
%% ----------------------------------------------------------------------------

%% ----------------------------------------------------------------------------
%% Supervisor callback
%% ----------------------------------------------------------------------------
init([]) ->
    {ok, { {one_for_one, 5, 10},
           [
            {scrypt, {scrypt_port, start_link, []},
             permanent, 5000, worker, [scrypt_port]}
           ]} }.
%% ----------------------------------------------------------------------------
