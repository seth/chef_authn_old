-module(chef_authn).
%
% Author:: Seth Falcon (<seth@opscode.com>)
% Copyright:: Copyright 2010 Opscode, Inc.
% License:: Apache License, Version 2.0
%
% Licensed under the Apache License, Version 2.0 (the "License");
% you may not use this file except in compliance with the License.
% You may obtain a copy of the License at
% 
%     http://www.apache.org/licenses/LICENSE-2.0
% 
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS,
% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
% See the License for the specific language governing permissions and
% limitations under the License.
%

-define(buf_size, 16384).

-compile([export_all]).

-type(http_body() :: binary() | pid()).
-type(user_id() :: binary()).
-type(http_method() :: binary()).
-type(http_time() :: binary()).
-type(http_path() :: binary()).
-type(sha_hash64() :: binary()).
-type(erlang_time() :: {calendar:date(), calendar:time()}).
-type(private_key() :: binary()).
-type(public_key() :: binary()).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-spec(hash_string(string()|binary()) -> sha_hash64()).
%% @doc Base 64 encoded SHA1 of `Str'
hash_string(Str) ->
    base64:encode(crypto:sha(Str)).

-spec(hash_file(file:io_device()) -> sha_hash64()).
%% @doc Base 64 encoded SHA1 of contents of `F'
hash_file(F) ->
    hash_file(F, crypto:sha_init()).

hash_file(F, Ctx) ->
    case io:get_chars(F, "", ?buf_size) of
        eof ->
            base64:encode(crypto:sha_final(Ctx));
        Data ->
            hash_file(F, crypto:sha_update(Ctx, Data))
    end.



-spec(time_iso8601({calendar:date(), calendar:time()} | now) -> binary()).
%% @doc Converts Erlang time-tuple to iso8601 formatted date string.
%%
%% Example output looks like <<"2003-12-13T18:30:02Z">>
time_iso8601(now) ->
    time_iso8601(calendar:universal_time());
time_iso8601({{Year, Month, Day}, {Hour, Min, Sec}}) ->
    % Is there a way to build a binary straight away?
    Fmt = "~4B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ",
    list_to_binary(lists:flatten(io_lib:format(Fmt,
                                               [Year, Month, Day,
                                                Hour, Min, Sec]))).

-spec(time_iso8601_to_date_time(string()|binary()) -> erlang_time()).
%% @doc Convert an iso8601 time string to Erlang date time
%% representation.
time_iso8601_to_date_time(ATime) when is_binary(ATime) ->
    time_iso8601_to_date_time(binary_to_list(ATime));
time_iso8601_to_date_time(ATime) ->
    [Year, Month, Day, Hour, Min, Sec] =
        [ list_to_integer(S) || S <- string:tokens(ATime, "-T:Z") ],
    {{Year, Month, Day}, {Hour, Min, Sec}}.

-spec(canonical_time(string() | binary()) -> binary()).
%% @doc Convert a string or binary HTTP request time to iso8601 format
canonical_time(T) when is_binary(T) ->
    canonical_time(binary_to_list(T));
canonical_time(T) when is_list(T) ->
    time_iso8601(httpd_util:convert_request_date(T)).

%% @doc Canonicalize an HTTP request path by removing doubled slashes
%% and trailing slash (except for case of root path).
canonical_path(Path = <<"/">>) ->
    Path;
canonical_path(Path) ->
    NoDoubles = re:replace(Path, "/+/", <<"/">>, [{return, binary}, global]),
    re:replace(NoDoubles, "/$", % fix emacs erlang-mode: "
               "", [{return, binary}]).

%% @doc Canonicalize HTTP method as all uppercase binary
canonical_method(Method) ->
    list_to_binary(string:to_upper(binary_to_list(Method))).

-spec(hashed_body(binary() | pid()) -> binary()).
%% @doc Return the SHA1 hash of the body which can either be a binary
%% or the pid of a file.
hashed_body(Body) when is_pid(Body) ->
    hash_file(Body);
hashed_body(Body) when is_binary(Body) ->
    hash_string(Body);
hashed_body(Body) when is_list(Body) ->
    hashed_body(iolist_to_binary(Body)).

-spec(canonicalize_request(http_body(), user_id(), http_method(),
                           http_time(), http_path()) -> binary()).
%% @doc Canonicalize an HTTP request into a binary that can be signed
%% for verification.
canonicalize_request(Body, UserId, Method, Time, Path) ->
    Format = <<"Method:~s\nHashed Path:~s\nX-Ops-Content-Hash:~s\nX-Ops-Timestamp:~s\nX-Ops-UserId:~ts">>,
    iolist_to_binary(io_lib:format(Format, [canonical_method(Method),
                                            hash_string(canonical_path(Path)),
                                            hashed_body(Body),
                                            canonical_time(Time),
                                            UserId])).

-spec(sign_request(private_key(), http_body(), user_id(),
                   http_method(), http_time(),
                   http_path()) -> [{binary(), binary()}]).
%% @doc Sign an HTTP request so it can be sent to a Chef server.
%%
%% Returns a list of header tuples that should be included in the
%% final HTTP request.
sign_request(PrivateKey, Body, User, Method, Time, Path) ->
    {'RSAPrivateKey', Der, _} = hd(public_key:pem_decode(PrivateKey)),
    RSAKey = public_key:der_decode('RSAPrivateKey', Der),
    SignThis = canonicalize_request(Body, User, Method, Time, Path),
    Sig = base64:encode(public_key:encrypt_private(SignThis, RSAKey)),
    % FIXME: should only call hashed_body once
    [{<<"X-Ops-Content-Hash">>, hashed_body(Body)},
     {<<"X-Ops-Userid">>, User},
     {<<"X-Ops-Sign">>, <<"version=1.0">>},
     % FIXME: should only call canonical_time once
     {<<"X-Ops-Timestamp">>, canonical_time(Time)}]
       ++ sig_header_items(Sig).

xops_header(I) ->
    iolist_to_binary(io_lib:format(<<"X-Ops-Authorization-~B">>, [I])).

sig_header_items(Sig) ->
    % Ruby's Base64.encode64 method inserts line feeds every 60
    % encoded characters.
    Lines = sig_to_list(Sig, 60),
    [ {xops_header(I), L} ||
        {L, I} <- lists:zip(Lines, lists:seq(1, length(Lines))) ].

sig_to_list(Sig, N) ->
    lists:reverse(sig_to_list(Sig, N, [])).

sig_to_list(Sig, N, Acc) ->
    case iolist_size(Sig) =< N of
        true ->
            [Sig|Acc];
        false ->
            <<Line:N/binary, Rest/binary>> = Sig,
            sig_to_list(Rest, N, [Line|Acc])
    end.

-spec(authenticate_user_request(
        fun((binary()) -> binary()),
        http_method(),
        http_path(),
        http_body(),
        public_key(),
        integer()
       ) -> {name, user_id()} | no_authn).
%% @doc 
authenticate_user_request(GetHeader, Method, Path, Body, UserKey, TimeSkew) ->

    % GetHeader is a fun/1 such that GetHeader(binary(), Headers)
    % returns the value for the header or undefined.

    UserId = GetHeader(<<"X-Ops-UserId">>),
    ReqTime = GetHeader(<<"X-Ops-Timestamp">>),
    AuthSig = sig_from_headers(GetHeader, 1, []),
    Decrypted = decrypt_sig(AuthSig, UserKey),
    Plain = canonicalize_request(Body, UserId, Method, ReqTime, Path),
    SigMatched = try
                     Decrypted = Plain,
                     true
                 catch
                     error:{badmatch, _} ->
                         false
                 end,
    TimeInBounds = time_in_bounds(ReqTime, TimeSkew),
    case SigMatched andalso TimeInBounds of
        true ->
            {name, UserId};
        false ->
            no_authn
    end.

decrypt_sig(Sig, PublicKey) ->
    PK = read_rsa_public_key(PublicKey),
    public_key:decrypt_public(base64:decode(Sig), PK).

sig_from_headers(GetHeader, I, Acc) ->
    Header = xops_header(I),
    case GetHeader(Header) of
        undefined ->
            iolist_to_binary(lists:reverse(Acc));
        Part ->
            sig_from_headers(GetHeader, I+1, [Part|Acc])
    end.

time_in_bounds(ReqTime, Skew) ->
    Now = calendar:now_to_universal_time(erlang:now()),
    time_in_bounds(time_iso8601_to_date_time(ReqTime), Now, Skew).

time_in_bounds(T1, T2, Skew) ->
    S1 = calendar:datetime_to_gregorian_seconds(T1),
    S2 = calendar:datetime_to_gregorian_seconds(T2),
    (S2 - S1) < Skew.

read_rsa_public_key(Key) ->
    Bin = erlang:iolist_to_binary(public_key_lines(re:split(Key, "\n"), [])),
    Spki = public_key:der_decode('SubjectPublicKeyInfo', base64:mime_decode(Bin)),
    {_, _, {0, KeyDer}} = Spki,
    public_key:der_decode('RSAPublicKey', KeyDer).

public_key_lines([<<"-----BEGIN PUBLIC KEY-----">>|Rest], Acc) ->
    public_key_lines(Rest, Acc);
public_key_lines([<<"-----END PUBLIC KEY-----">>|_Rest], Acc) ->
    lists:reverse(Acc);
public_key_lines([Line|Rest], Acc) ->
    public_key_lines(Rest, [Line|Acc]).

-ifdef(TEST).

hashed_path_test() ->
    Path = "/organizations/clownco",
    Hashed_path = <<"YtBWDn1blGGuFIuKksdwXzHU9oE=">>,
    ?assertEqual(Hashed_path, hash_string(canonical_path(Path))).

hashed_body_test() ->
    Body = "Spec Body",
    Hashed_body = <<"DFteJZPVv6WKdQmMqZUQUumUyRs=">>,
    ?assertEqual(Hashed_body, hashed_body(Body)).

canonical_time_test() ->
    % This date format comes from Ruby's default printing,
    % but doesn't correspond to the HTTP rfc2616 format
    % Time = "Thu Jan 01 12:00:00 -0000 2009",
    Time = "Thu, 01 Jan 2009 12:00:00 GMT",
    Time8601 = <<"2009-01-01T12:00:00Z">>,
    ?assertEqual(Time8601, canonical_time(Time)).
    
canonicalize_request_test() ->
    Time = "Thu, 01 Jan 2009 12:00:00 GMT",
    Time8601 = "2009-01-01T12:00:00Z",
    User = "spec-user",
    Hashed_body = "DFteJZPVv6WKdQmMqZUQUumUyRs=",
    Hashed_path = "YtBWDn1blGGuFIuKksdwXzHU9oE=",
    Expected_sign_string = iolist_to_binary(io_lib:format(
                                              "Method:~s\nHashed Path:~s\n"
                                              "X-Ops-Content-Hash:~s\n"
                                              "X-Ops-Timestamp:~s\n"
                                              "X-Ops-UserId:~s",
                                              ["POST", Hashed_path, Hashed_body,
                                               Time8601, User])),
    Val = canonicalize_request(<<"Spec Body">>, <<"spec-user">>, <<"post">>,
                               Time, <<"/organizations/clownco">>),
    ?assertEqual(Expected_sign_string, Val).

sign_request_test() ->
    {ok, PRIVATE_KEY} = file:read_file("../test/private_key"),
    X_OPS_CONTENT_HASH = <<"DFteJZPVv6WKdQmMqZUQUumUyRs=">>,
    X_OPS_AUTHORIZATION_LINES =
        [
         <<"jVHrNniWzpbez/eGWjFnO6lINRIuKOg40ZTIQudcFe47Z9e/HvrszfVXlKG4">>,
         <<"NMzYZgyooSvU85qkIUmKuCqgG2AIlvYa2Q/2ctrMhoaHhLOCWWoqYNMaEqPc">>,
         <<"3tKHE+CfvP+WuPdWk4jv4wpIkAz6ZLxToxcGhXmZbXpk56YTmqgBW2cbbw4O">>,
         <<"IWPZDHSiPcw//AYNgW1CCDptt+UFuaFYbtqZegcBd2n/jzcWODA7zL4KWEUy">>,
         <<"9q4rlh/+1tBReg60QdsmDRsw/cdO1GZrKtuCwbuD4+nbRdVBKv72rqHX9cu0">>,
         <<"utju9jzczCyB+sSAQWrxSsXB/b8vV2qs0l4VD2ML+w==">>
        ],

    AuthLine = fun(I) -> lists:nth(I, X_OPS_AUTHORIZATION_LINES) end,
    EXPECTED_SIGN_RESULT =
        [
         {<<"X-Ops-Content-Hash">>, X_OPS_CONTENT_HASH},
         {<<"X-Ops-Userid">>, <<"spec-user">>},
         {<<"X-Ops-Sign">>, <<"version=1.0">>},
         {<<"X-Ops-Timestamp">>, <<"2009-01-01T12:00:00Z">>},
         {<<"X-Ops-Authorization-1">>, AuthLine(1)},
         {<<"X-Ops-Authorization-2">>, AuthLine(2)},
         {<<"X-Ops-Authorization-3">>, AuthLine(3)},
         {<<"X-Ops-Authorization-4">>, AuthLine(4)},
         {<<"X-Ops-Authorization-5">>, AuthLine(5)},
         {<<"X-Ops-Authorization-6">>, AuthLine(6)}
        ],
    Time = "Thu, 01 Jan 2009 12:00:00 GMT",
    Sig = sign_request(PRIVATE_KEY, <<"Spec Body">>, <<"spec-user">>, <<"post">>,
                       Time, <<"/organizations/clownco">>),
    ?assertEqual(EXPECTED_SIGN_RESULT, Sig),
    AuthSig = iolist_to_binary(X_OPS_AUTHORIZATION_LINES),
    {ok, PUBLIC_KEY} = file:read_file("../test/public_key"),
        Time = "Thu, 01 Jan 2009 12:00:00 GMT",
    Time8601 = "2009-01-01T12:00:00Z",
    User = "spec-user",
    Hashed_body = "DFteJZPVv6WKdQmMqZUQUumUyRs=",
    Hashed_path = "YtBWDn1blGGuFIuKksdwXzHU9oE=",

    Expected_sign_string = iolist_to_binary(io_lib:format(
                                              "Method:~s\nHashed Path:~s\n"
                                              "X-Ops-Content-Hash:~s\n"
                                              "X-Ops-Timestamp:~s\n"
                                              "X-Ops-UserId:~s",
                                              ["POST", Hashed_path, Hashed_body,
                                               Time8601, User])),
    ?assertEqual(Expected_sign_string, decrypt_sig(AuthSig, PUBLIC_KEY)).

-endif.
