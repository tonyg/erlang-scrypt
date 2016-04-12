-module(erlscrypt_test).

-include_lib("eunit/include/eunit.hrl").

%%---------------------------------------------------------------------------
%% Test vectors from the scrypt paper:
%%
%% Colin Percival, "Stronger Key Derivation via Sequential Memory-Hard
%% Functions", presented at BSDCan'09, May 2009.
%%
%% http://www.tarsnap.com/scrypt/scrypt.pdf

-define(TESTS,
        % {[Passwd, Salt, N, R, P, Buflen], Result}
        [{[<<>>, <<>>, 16, 1, 1, 64],
          <<16#77, 16#d6, 16#57, 16#62, 16#38, 16#65, 16#7b, 16#20,
            16#3b, 16#19, 16#ca, 16#42, 16#c1, 16#8a, 16#04, 16#97,
            16#f1, 16#6b, 16#48, 16#44, 16#e3, 16#07, 16#4a, 16#e8,
            16#df, 16#df, 16#fa, 16#3f, 16#ed, 16#e2, 16#14, 16#42,
            16#fc, 16#d0, 16#06, 16#9d, 16#ed, 16#09, 16#48, 16#f8,
            16#32, 16#6a, 16#75, 16#3a, 16#0f, 16#c8, 16#1f, 16#17,
            16#e8, 16#d3, 16#e0, 16#fb, 16#2e, 16#0d, 16#36, 16#28,
            16#cf, 16#35, 16#e2, 16#0c, 16#38, 16#d1, 16#89, 16#06>>},
         {[<<"password">>, <<"NaCl">>, 1024, 8, 16, 64],
          <<16#fd, 16#ba, 16#be, 16#1c, 16#9d, 16#34, 16#72, 16#00,
            16#78, 16#56, 16#e7, 16#19, 16#0d, 16#01, 16#e9, 16#fe,
            16#7c, 16#6a, 16#d7, 16#cb, 16#c8, 16#23, 16#78, 16#30,
            16#e7, 16#73, 16#76, 16#63, 16#4b, 16#37, 16#31, 16#62,
            16#2e, 16#af, 16#30, 16#d9, 16#2e, 16#22, 16#a3, 16#88,
            16#6f, 16#f1, 16#09, 16#27, 16#9d, 16#98, 16#30, 16#da,
            16#c7, 16#27, 16#af, 16#b9, 16#4a, 16#83, 16#ee, 16#6d,
            16#83, 16#60, 16#cb, 16#df, 16#a2, 16#cc, 16#06, 16#40>>},
         {[<<"pleaseletmein">>, <<"SodiumChloride">>, 16384, 8, 1, 64],
          <<16#70, 16#23, 16#bd, 16#cb, 16#3a, 16#fd, 16#73, 16#48,
            16#46, 16#1c, 16#06, 16#cd, 16#81, 16#fd, 16#38, 16#eb,
            16#fd, 16#a8, 16#fb, 16#ba, 16#90, 16#4f, 16#8e, 16#3e,
            16#a9, 16#b5, 16#43, 16#f6, 16#54, 16#5d, 16#a1, 16#f2,
            16#d5, 16#43, 16#29, 16#55, 16#61, 16#3f, 16#0f, 16#cf,
            16#62, 16#d4, 16#97, 16#05, 16#24, 16#2a, 16#9a, 16#f9,
            16#e6, 16#1e, 16#85, 16#dc, 16#0d, 16#65, 16#1e, 16#40,
            16#df, 16#cf, 16#01, 16#7b, 16#45, 16#57, 16#58, 16#87>>},
         % Commented out because it's too slow for the default eunit timeout.
         {[<<"pleaseletmein">>, <<"SodiumChloride">>, 1048576, 8, 1, 64],
          <<16#21, 16#01, 16#cb, 16#9b, 16#6a, 16#51, 16#1a, 16#ae,
            16#ad, 16#db, 16#be, 16#09, 16#cf, 16#70, 16#f8, 16#81,
            16#ec, 16#56, 16#8d, 16#57, 16#4a, 16#2f, 16#fd, 16#4d,
            16#ab, 16#e5, 16#ee, 16#98, 16#20, 16#ad, 16#aa, 16#47,
            16#8e, 16#56, 16#fd, 16#8f, 16#4b, 16#a5, 16#d0, 16#9f,
            16#fa, 16#1c, 16#6d, 16#92, 16#7c, 16#40, 16#f4, 16#c3,
            16#37, 16#30, 16#40, 16#49, 16#e8, 16#a9, 16#52, 16#fb,
            16#cb, 16#f4, 16#5c, 16#6f, 16#a7, 16#7a, 16#41, 16#a4>>}
        ]).

startup_test() ->
    ok = application:start(erlscrypt),
    ?assertNot(undefined == whereis(erlscrypt)).

scrypt_test_() ->
    {timeout,
     20,
     {inparallel, test_internal(port) ++ test_internal(nif)}}.

test_internal(Type) ->
    [{list_to_binary(io_lib:format("[~p] ~p. '~s'/'~s'",
                                   [Type,Id,Passwd,Salt])),
      test_body_fun(Type, Id, Passwd, Salt,
                    if Type == nif -> [nif|Params]; true -> Params end,
                    Result)}
     || {Id,{[Passwd,Salt|_] = Params, Result}}
        <- lists:zip(lists:seq(1,length(?TESTS)),?TESTS)].

test_body_fun(Type, Id, Passwd, Salt, Params, Result) ->
    Test = list_to_binary(io_lib:format("[~p] ~p. '~s'/'~s'",
                                        [Type,Id,Passwd,Salt])),
    fun() ->
            ?debugFmt("> ~s", [Test]),
            {Time, Rslt} = timer:tc(erlscrypt, scrypt, Params),
            ?debugFmt("< ~s in ~.2f ms", [Test, Time / 1000]),
            ?assertEqual(Result, Rslt)
            % ?assert(Time < 2000000)
    end.
