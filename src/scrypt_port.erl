-module(scrypt_port).

-behaviour(gen_server).

-export([start_link/0, scrypt/6]).
-export([init/1, terminate/2, code_change/3, handle_call/3, handle_cast/2, handle_info/2]).

%%---------------------------------------------------------------------------

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

scrypt(Passwd, Salt, N, R, P, Buflen) ->
    gen_server:call(?MODULE, {scrypt, Passwd, Salt, N, R, P, Buflen}).

%%---------------------------------------------------------------------------

-record(state, {port}).

-ifdef(TEST).
priv_dir() ->
    case code:priv_dir(scrypt) of
        {error, bad_name} -> "../priv"; %% relative to .../.eunit directory.
        D -> D
    end.
-else.
priv_dir() ->
    case code:priv_dir(scrypt) of
        {error, bad_name} -> "./priv";
        D -> D
    end.
-endif.

init([]) ->
    {ok, #state{port = open_port({spawn, priv_dir() ++ "/scrypt"},
                                 [{packet, 4}, binary, use_stdio])}}.

terminate(_Reason, _State = #state{port = Port}) ->
    catch port_command(Port, <<>>),
    catch port_close(Port),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

handle_call({scrypt, Passwd, Salt, N, R, P, Buflen}, _From, State = #state{port = Port}) ->
    port_command(Port, <<(size(Passwd)):32, (size(Salt)):32, N:32, R:32, P:32, Buflen:32,
                         Passwd/binary, Salt/binary>>),
    receive
        {Port, {data, Buf}} ->
            if
                size(Buf) =:= Buflen ->
                    {reply, Buf, State};
                true ->
                    exit(bad_scrypt_port_buflen)
            end
    end;
handle_call(_Request, _From, State) ->
    {stop, {bad_call, _Request}, State}.

handle_cast(_Request, State) ->
    {stop, {bad_cast, _Request}, State}.

handle_info(_Message, State) ->
    {stop, {bad_info, _Message}, State}.
