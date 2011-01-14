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
% -export([hash_string/1,
%          hash_file/1
%         ]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-spec(hash_string(string()|binary()) -> binary()).
%% @doc Base 64 encoded SHA1 of `Str'
hash_string(Str) ->
    base64:encode(crypto:sha(Str)).

-spec(hash_file(file:io_device()) -> binary()).
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

-spec(time_iso8601_to_date_time(string()|binary()) -> {calendar:date(), calendar:time()}).

%% @doc Convert an iso8601 time string to Erlang date time
%% representation.
time_iso8601_to_date_time(ATime) when is_binary(ATime) ->
    time_iso8601_to_date_time(binary_to_list(ATime));
time_iso8601_to_date_time(ATime) ->
    [Year, Month, Day, Hour, Min, Sec] =
        [ list_to_integer(S) || S <- string:tokens(ATime, "-T:Z") ],
    {{Year, Month, Day}, {Hour, Min, Sec}}.

canonical_time(T) ->
    time_iso8601(httpd_util:convert_request_date(T)).


canonical_path(Path = <<"/">>) ->
    Path;
canonical_path(Path) ->
    NoDoubles = re:replace(Path, "/+/", <<"/">>, [{return, binary}, global]),
    re:replace(NoDoubles, "/$", % fix emacs erlang-mode: "
               <<"/">>, [{return, binary}]).

canonical_method(Method) ->
    list_to_binary(string:to_upper(binary_to_list(Method))).

hashed_body(Body) when is_pid(Body) ->
    hash_file(Body);
hashed_body(Body) when is_binary(Body) ->
    hash_string(Body);
hashed_body(Body) when is_list(Body) ->
    hashed_body(iolist_to_binary(Body)).

% so signedheaderauth seems to be implemented where you pass in an
% args hash with body, user_id, http_method, timestamp, file, and
% path.  These are then accessed as instance methods to do the
% authentication.  So we could either take a similar approach or just
% have a proplist be an input to the entry point functions.

canonicalize_request(Body, UserId, Method, Time, Path) ->
    Format = <<"Method:~s\nHashed Path:~s\nX-Ops-Content-Hash:~s\nX-Ops-Timestamp:~s\nX-Ops-UserId:~ts">>,
    iolist_to_binary(io_lib:format(Format, [canonical_method(Method),
                                            hash_string(canonical_path(Path)),
                                            hashed_body(Body),
                                            canonical_time(Time),
                                            UserId])).

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

    % # We expect Mixlib::Authentication::SignedHeaderAuth#sign to return this
    % # if passed the BODY above.
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
    ?assertEqual(EXPECTED_SIGN_RESULT, Sig).


-endif.
