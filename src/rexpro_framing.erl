%%%-------------------------------------------------------------------
%%% @author Algis Dumbris
%%% @copyright (C) 2014
%%% @doc
%%%
%%% @end
%%% Created : 2014-09-30 18:24:48.605172
%%%-------------------------------------------------------------------
-module(rexpro_framing).
-include_lib("eunit/include/eunit.hrl").
-include("rexpro.hrl").

-export([from_binary/3]).

%%=========================================================================
%Doc link https://github.com/tinkerpop/rexster/wiki/RexPro-Messages
%[protocol version][serializer type][reserved (4x)][message type][message size][message body]
%%=========================================================================
%Option 1 - Message fit to singe TCP fragment
-spec from_binary(Data::binary(), Fragmented :: boolean(), Frame :: #frame{}) -> tuple(ok, #frame{}, binary()) | tuple(fragment, #frame{}) | tuple(error, #frame{}).
from_binary( <<?PROTOCOL_VERSION:8, 
               Serializer:8, _Resrv:32, 
               Type:8, 
               Length:32, 
               Rest/binary>>, false, _Frame) when byte_size(Rest) >= Length ->

    <<Payload:Length/binary, Rest2/binary>> = Rest,
    {ok, #frame{ serializer = Serializer, type = Type, length = Length, payload = Payload, fragmented = false, expected_length = 0 }, Rest2};
%Option 2 - Message does not fit to singe TCP fragment, have to wait for continuation
from_binary( <<?PROTOCOL_VERSION:8, 
               Serializer:8, _Resrv:32, 
               Type:8, 
               Length:32, 
               Rest/binary>>, false, _Frame) when byte_size(Rest) < Length ->
    {fragment, #frame{ serializer = Serializer, 
                type = Type, 
                length = Length, 
                expected_length = Length - byte_size(Rest), 
                raw = Rest, 
                fragmented = true }};
%Handle continue 
from_binary( <<Rest/binary>>, true, 
            Frame = #frame{expected_length = Length, raw = RawData}) when byte_size(Rest) < Length ->
    RawData2 = <<RawData/binary, Rest/binary>>,
    {fragment, Frame#frame{ 
                expected_length = Length - byte_size(Rest), 
                raw = RawData2, 
                fragmented = true }};
%Handle final fragment 
from_binary( <<Rest/binary>>, true, 
            Frame = #frame{expected_length = Length, raw = RawData}) when byte_size(Rest) >= Length ->
    <<Payload:Length/binary, Rest2/binary>> = Rest,
    RawData2 = <<RawData/binary, Payload/binary>>,
    {ok, Frame#frame{ 
                expected_length = 0, 
                raw = <<>>,
                payload = RawData2, 
                fragmented = false }, Rest2};
%If rexpro header is fragmented, just pass througth data
from_binary( <<Data/binary>>, _Any, Frame ) when byte_size(Data) < 88 ->
    {fragmented, Frame, Data}

from_binary_script_response_test() ->
    ReplyScriptRaw = <<"        џ•°                °ТШ—)ІfCm°©PYЙуeЂ‘ѓЈ_idЈ512Ґ_type¦vertex«_properties†ЈuidҐuser1¤nameҐuser1Єcreated_atП  HХйіEЁusertype©anonymousҐlogin©testuser1¤type¤userЂ">>,
    {Res, Frame} = from_binary(ReplyScriptRaw, false, #frame{}),
    ?assertEqual(ok, Res),
    ?assertEqual(?MT_SCRIPT_RESPONSE, Frame#frame.type),
    ?assertEqual(false, Frame#frame.fragmented).
