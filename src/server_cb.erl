-module(server_cb).


-include_lib("diameter/include/diameter.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").
-include_lib("diameter_3gpp_ts29_272.hrl").
-include_lib("osmo_gsup/include/gsup_protocol.hrl").


%% diameter callbacks
-export([peer_up/3, peer_down/3, pick_peer/4, prepare_request/3, prepare_retransmit/3,
	 handle_answer/4, handle_error/4, handle_request/3]).

-define(UNEXPECTED, erlang:error({unexpected, ?MODULE, ?LINE})).

peer_up(_SvcName, {PeerRef, Caps}, State) ->
	lager:info("Peer up ~p - ~p~n", [PeerRef, lager:pr(Caps, ?MODULE)]),
	State.

peer_down(_SvcName, {PeerRef, Caps}, State) ->
	lager:info("Peer down ~p - ~p~n", [PeerRef, lager:pr(Caps, ?MODULE)]),
	State.

pick_peer(_, _, _SvcName, _State) ->
	?UNEXPECTED.

prepare_request(_, _SvcName, _Peer) ->
	?UNEXPECTED.

prepare_retransmit(_Packet, _SvcName, _Peer) ->
	?UNEXPECTED.

handle_answer(_Packet, _Request, _SvcName, _Peer) ->
	?UNEXPECTED.

handle_error(_Reason, _Request, _SvcName, _Peer) ->
	lager:error("Request error: ~p~n", [_Reason]),
	?UNEXPECTED.

% generate Diameter E-UTRAN / UTRAN / GERAN Vectors from GSUP tuple input
-spec gsup_tuple2dia_eutran('GSUPAuthTuple'(), binary(), integer()) -> #'E-UTRAN-Vector'{}.
gsup_tuple2dia_eutran(#{autn:=Autn, ck:=Ck, ik:=Ik, rand:=Rand, res:=Res}, Vplmn, Idx) ->
	#'E-UTRAN-Vector'{'Item-Number'=Idx, 'RAND'=Rand, 'XRES'=Res , 'AUTN'=Autn,
			  'KASME'=compute_kasme(Ck, Ik, Vplmn, Autn)}.

-spec gsup_tuple2dia_utran('GSUPAuthTuple'()) -> #'UTRAN-Vector'{}.
gsup_tuple2dia_utran(#{autn:=Autn, ck:=Ck, ik:=Ik, rand:=Rand, res:=Res}) ->
	#'UTRAN-Vector'{'RAND'=Rand, 'XRES'=Res, 'AUTN'=Autn, 'Confidentiality-Key'=Ck, 'Integrity-Key'=Ik}.

-spec gsup_tuple2dia_geran('GSUPAuthTuple'()) -> #'GERAN-Vector'{}.
gsup_tuple2dia_geran(#{rand:=Rand, sres:=Sres, kc:=Kc}) ->
	#'GERAN-Vector'{'RAND'=Rand, 'SRES'=Sres, 'Kc'=Kc}.

-spec gsup_tuples2dia_eutran(['GSUPAuthTuple'()], binary()) -> [#'E-UTRAN-Vector'{}].
gsup_tuples2dia_eutran(List, Vplmn) -> gsup_tuples2dia_eutran(List, Vplmn, [], 1).
gsup_tuples2dia_eutran([], _Vplmn, Out, _Idx) -> Out;
gsup_tuples2dia_eutran([Head|Tail], Vplmn, Out, Ctr) ->
	Dia = gsup_tuple2dia_eutran(Head, Vplmn, Ctr),
	gsup_tuples2dia_eutran(Tail, Vplmn, [Dia|Out], Ctr+1).

-type int_or_false() :: false | integer().
-spec gsup_tuples2dia(['GSUPAuthTuple'()], binary(), int_or_false(), int_or_false(), int_or_false()) -> #'Authentication-Info'{}.
gsup_tuples2dia(Tuples, Vplmn, NumEutran, NumUtran, NumGeran) ->
	case NumEutran of
		false -> EutranVecs = [];
		0 -> EutranVecs = [];
		_ -> EutranVecs = gsup_tuples2dia_eutran(lists:sublist(Tuples,NumEutran), Vplmn)
	end,
	case NumUtran of
		false -> UtranVecs = [];
		0 -> UtranVecs = [];
		_ -> UtranVecs = lists:map(fun gsup_tuple2dia_utran/1, lists:sublist(Tuples,NumUtran))
	end,
	case NumGeran of
		false -> GeranVecs = [];
		0 -> GeranVecs = [];
		_ -> GeranVecs = lists:map(fun gsup_tuple2dia_geran/1, lists:sublist(Tuples,NumGeran))
	end,
	#'Authentication-Info'{'E-UTRAN-Vector'=EutranVecs, 'UTRAN-Vector'=UtranVecs,
				'GERAN-Vector'=GeranVecs}.


-spec compute_kasme(<<_:16>>, <<_:16>>, <<_:3>>, <<_:16>>) -> <<_:32>>.
compute_kasme(Ck, Ik, VplmnId, Autn) ->
	Autn6 = binary_part(Autn, 0, 6),
	K = <<Ck:16/binary, Ik:16/binary>>,
	S = <<16, VplmnId:3/binary, 0, 3, Autn6:6/binary, 0, 6>>,
	crypto:hmac(sha256, K, S, 32).

-spec req_num_of_vec([tuple()]) -> int_or_false().
req_num_of_vec([#'Requested-EUTRAN-Authentication-Info'{'Number-Of-Requested-Vectors'=[]}]) -> false;
req_num_of_vec([#'Requested-EUTRAN-Authentication-Info'{'Number-Of-Requested-Vectors'=[Num]}]) -> Num;
req_num_of_vec([#'Requested-UTRAN-GERAN-Authentication-Info'{'Number-Of-Requested-Vectors'=[]}]) -> false;
req_num_of_vec([#'Requested-UTRAN-GERAN-Authentication-Info'{'Number-Of-Requested-Vectors'=[Num]}]) -> Num;
req_num_of_vec(_) -> false.

-define(PDP_TYPE_DEFAULT, <<0,0,0,16#21>>).	% IPv4
-define(PDP_QOS_DEFAULT, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0>>). % fixme

-spec gsup_pdp2dia('GSUPPdpInfo'()) -> #'PDP-Context'{}.
gsup_pdp2dia(GsupPdpInfo) ->
	#'PDP-Context'{'PDP-Type' = maps:get(pdp_type, GsupPdpInfo, ?PDP_TYPE_DEFAULT),
		       'Context-Identifier' = maps:get(pdp_context_id, GsupPdpInfo),
		       'Service-Selection' = maps:get(access_point_name, GsupPdpInfo),
		       'QoS-Subscribed' = maps:get(quality_of_service, GsupPdpInfo, ?PDP_QOS_DEFAULT)
		      }.

-define(PDN_TYPE_DEFAULT, 0).	% IPv4
-define(EPS_QOS_DEFAULT,
	#'EPS-Subscribed-QoS-Profile'{'QoS-Class-Identifier'=9,
				      'Allocation-Retention-Priority'=
		#'Allocation-Retention-Priority'{'Priority-Level'=8,
						 'Pre-emption-Capability'=1,
						 'Pre-emption-Vulnerability'=1}
	}).

-spec gsup_pdp2dia_apn('GSUPPdpInfo'()) -> #'APN-Configuration'{}.
gsup_pdp2dia_apn(GsupPdpInfo) ->
	#'APN-Configuration'{'Context-Identifier' = maps:get(pdp_context_id, GsupPdpInfo),
			     'PDN-Type' = maps:get(pdp_type, GsupPdpInfo, ?PDN_TYPE_DEFAULT),
			     % The EPS-Subscribed-QoS-Profile AVP and the AMBR AVP shall be present in the
			     % APN-Configuration AVP when the APN-Configuration AVP is sent in the
			     % APN-Configuration-Profile AVP and when the APN-Configuration-Profile AVP is
			     % sent within a ULA (as part of the Subscription-Data AVP).
			     'EPS-Subscribed-QoS-Profile' = ?EPS_QOS_DEFAULT,
			     'AMBR' = #'AMBR'{'Max-Requested-Bandwidth-UL' = 100000000,
					      'Max-Requested-Bandwidth-DL' = 100000000},
			     % The default APN Configuration shall not contain the Wildcard APN (see 3GPP TS
			     % 23.003 [3], clause 9.2); the default APN shall always contain an explicit APN
			     'Service-Selection' = "internet"%maps:get(access_point_name, GsupPdpInfo)
			    }.

% transient (only in Experimental-Result-Code)
-define(DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE,	4181).
-define(DIAMETER_ERROR_CAMEL_SUBSCRIPTION_PRESENT,	4182).
% permanent (only in Experimental-Result-Code)
-define(DIAMETER_ERROR_USER_UNKNOWN,			5001).
-define(DIAMETER_ERROR_ROAMING_NOT_ALLOWED,		5004).
-define(DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION,	5420).
-define(DIAMETER_ERROR_RAT_NOT_ALLOWED,			5421).
-define(DIAMETER_ERROR_EQUIPMENT_UNKNOWN,		5422).
-define(DIAMETER_ERROR_UNKOWN_SERVING_NODE,		5423).

% 10.5.5.14
-define(GMM_CAUSE_IMSI_UNKNOWN,		16#02).
-define(GMM_CAUSE_PLMN_NOTALLOWED,	16#0b).
-define(GMM_CAUSE_GPRS_NOTALLOWED,	16#07).
-define(GMM_CAUSE_INV_MAND_INFO,	16#60).
-define(GMM_CAUSE_NET_FAIL,		16#11).
% TODO: more values

-define(EXP_RES(Foo),	#'Experimental-Result'{'Vendor-Id'=fixme, 'Experimental-Result-Code'=Foo}).

-type empty_or_intl() :: [] | [integer()].
-spec gsup_cause2dia(integer()) -> {empty_or_intl(), empty_or_intl()}.
gsup_cause2dia(?GMM_CAUSE_IMSI_UNKNOWN) -> {[], [?EXP_RES(?DIAMETER_ERROR_USER_UNKNOWN)]};
gsup_cause2dia(?GMM_CAUSE_PLMN_NOTALLOWED) -> {[], [?DIAMETER_ERROR_ROAMING_NOT_ALLOWED]};
gsup_cause2dia(?GMM_CAUSE_GPRS_NOTALLOWED) -> {[], [?DIAMETER_ERROR_RAT_NOT_ALLOWED]};
%gsup_cause2dia(?GMM_CAUSE_INV_MAND_INFO) ->
%gsup_cause2dia(?GMM_CAUSE_NET_FAIL) -> 
% TODO: more values
gsup_cause2dia(_) -> {fixme, []}.

% get the value for a tiven key in Map1. If not found, try same key in Map2. If not found, return Default
-spec twomap_get(atom(), map(), map(), any()) -> any().
twomap_get(Key, Map1, Map2, Default) ->
	maps:get(Key, Map1, maps:get(Key, Map2, Default)).

handle_request(#diameter_packet{msg = Req, errors = []}, _SvcName, {_, Caps}) when is_record(Req, 'AIR') ->
	lager:info("AIR: ~p~n", [Req]),
	% extract relevant fields from DIAMETER AIR
	#diameter_caps{origin_host = {OH,_}, origin_realm = {OR,_}} = Caps,
	#'AIR'{'Session-Id' = SessionId,
	       'User-Name' = UserName,
	       'Visited-PLMN-Id' = VplmnId,
	       'Requested-EUTRAN-Authentication-Info' = ReqEU,
	       'Requested-UTRAN-GERAN-Authentication-Info' = ReqUG} = Req,
	VplmnIdBin = list_to_binary(VplmnId),
	NumEutran = req_num_of_vec(ReqEU),
	NumUgran = req_num_of_vec(ReqUG),
	lager:info("Num EUTRAN=~p, UTRAN=~p~n", [NumEutran, NumUgran]),
	% construct GSUP request to HLR and transceive it
	GsupTx1 = #{message_type => send_auth_info_req, imsi => list_to_binary(UserName),
		    supported_rat_types => [rat_eutran_sgs], current_rat_type => rat_eutran_sgs, num_vectors_req => 1},
	case ReqEU of
		#'Requested-EUTRAN-Authentication-Info'{'Re-Synchronization-Info' = ReSyncInfo}
		when is_binary(ReSyncInfo) ->
			GsupTx2 = #{rand => string:substr(ReSyncInfo, 1, 16),
				    auts => string:substr(ReSyncInfo, 17)};
		_ ->
			GsupTx2 = #{}
	end,
	GsupTx = maps:merge(GsupTx1, GsupTx2),
	GsupRx = gen_server:call(gsup_client, {transceive_gsup, GsupTx, send_auth_info_res, send_auth_info_err}),
	lager:info("GsupRx: ~p~n", [GsupRx]),
	% construct DIAMETER AIA response
	case GsupRx of
		#{message_type:=send_auth_info_res, auth_tuples:=GsupAuthTuples} ->
			AuthInfo = gsup_tuples2dia(GsupAuthTuples, VplmnIdBin, NumEutran, NumUgran, NumUgran),
			Resp = #'AIA'{'Session-Id'=SessionId, 'Origin-Host'=OH, 'Origin-Realm'=OR,
				      'Result-Code'=2001, 'Auth-Session-State'=1,
				      'Authentication-Info'=AuthInfo};
		#{message_type := send_auth_info_err} ->
			Resp = #'AIA'{'Session-Id'=SessionId, 'Origin-Host'=OH, 'Origin-Realm'=OR,
				      'Result-Code'=?DIAMETER_ERROR_USER_UNKNOWN,
				      'Auth-Session-State'=1};
		timeout ->
			Resp = #'AIA'{'Session-Id'=SessionId, 'Origin-Host'=OH, 'Origin-Realm'=OR,
				      'Result-Code'=4181, 'Auth-Session-State'=1}
	end,
	lager:info("Resp: ~p~n", [Resp]),
	{reply, Resp};

handle_request(#diameter_packet{msg = Req, errors = []}, _SvcName, {_, Caps}) when is_record(Req, 'ULR') ->
	% extract relevant fields from DIAMETER ULR
	#diameter_caps{origin_host = {OH,_}, origin_realm = {OR,_}} = Caps,
	#'ULR'{'Session-Id' = SessionId,
	       'RAT-Type' = RatType,
	       'ULR-Flags' = UlrFlags,
	       'User-Name' = UserName} = Req,

	% construct GSUP UpdateLocation request to HLR and transceive it; expect InsertSubscrDataReq
	GsupTxUlReq = #{message_type => location_upd_req, imsi => list_to_binary(UserName),
			cn_domain => 1},
	GsupRxIsdReq = gen_server:call(gsup_client,
				{transceive_gsup, GsupTxUlReq, insert_sub_data_req, location_upd_err}),
	lager:info("GsupRxIsdReq: ~p~n", [GsupRxIsdReq]),
	case GsupRxIsdReq of
		#{message_type:=location_upd_err, cause:=Cause} ->
			{Res, ExpRes} = gsup_cause2dia(Cause),
			Resp = #'ULA'{'Session-Id'= SessionId, 'Auth-Session-State'=1,
				      'Origin-Host'=OH, 'Origin-Realm'=OR,
				      'Result-Code'=Res, 'Experimental-Result'=ExpRes};
		#{message_type:=insert_sub_data_req} ->
			% construct GSUP InsertSubscrData response to HLR and transceive it; expect
			% UpdateLocationRes
			GsupTxIsdRes = #{message_type => insert_sub_data_res,
					 imsi => list_to_binary(UserName)},
			GsupRxUlRes = gen_server:call(gsup_client,
				{transceive_gsup, GsupTxIsdRes, location_upd_res, location_upd_err}),
			lager:info("GsupRxUlRes: ~p~n", [GsupRxUlRes]),

			case GsupRxUlRes of
				#{message_type:=location_upd_res} ->
					Msisdn = twomap_get(msisdn, GsupRxIsdReq, GsupRxUlRes, []),
					Compl = twomap_get(pdp_info_complete, GsupRxIsdReq, GsupRxUlRes, 0),

					% build the GPRS Subscription Data
					PdpInfoList = twomap_get(pdp_info_list, GsupRxIsdReq, GsupRxUlRes, []),
					PdpContexts = lists:map(fun gsup_pdp2dia/1, PdpInfoList),
					GSubD = #'GPRS-Subscription-Data'{'Complete-Data-List-Included-Indicator'=Compl,
									  'PDP-Context'=PdpContexts},

					% build the APN-Configuration-Profile
					ApnCfgList = lists:map(fun gsup_pdp2dia_apn/1, PdpInfoList),
					FirstApn = lists:nth(1, ApnCfgList),
					DefaultCtxId = FirstApn#'APN-Configuration'.'Context-Identifier',
					ApnCfgProf = #'APN-Configuration-Profile'{'Context-Identifier' = DefaultCtxId,
										  'All-APN-Configurations-Included-Indicator'=Compl,
										  'APN-Configuration' = ApnCfgList},

					% put together the Subscription-Data and finally the ULA response
					SubscrData = #'Subscription-Data'{'MSISDN' = Msisdn,

									  'Network-Access-Mode' = 0, % PACKET_AND_CIRCUIT
									  'GPRS-Subscription-Data' = GSubD,
									  % Subscriber-Status must be present in ULA
									  'Subscriber-Status' = 0,
									  % AMBR must be present if this is an ULA; let's permit 100MBps UL + DL
									  'AMBR' = #'AMBR'{'Max-Requested-Bandwidth-UL' = 100000000,
											   'Max-Requested-Bandwidth-DL' = 100000000},
									  'APN-Configuration-Profile' = ApnCfgProf},
					Resp = #'ULA'{'Session-Id' = SessionId, 'Auth-Session-State' = 1,
						      'Origin-Host' = OH, 'Origin-Realm' = OR,
						      'Result-Code' = 2001,
						      'Subscription-Data' = SubscrData, 'ULA-Flags' = 0};
				#{message_type:=location_upd_err, cause:=Cause} ->
					{Res, ExpRes} = gsup_cause2dia(Cause),
					Resp = #'ULA'{'Session-Id'= SessionId, 'Auth-Session-State'=1,
						      'Origin-Host'=OH, 'Origin-Realm'=OR,
						      'Result-Code'=Res, 'Experimental-Result'=ExpRes};
				_ ->
					Resp = #'ULA'{'Session-Id'= SessionId, 'Auth-Session-State'=1,
						      'Origin-Host'=OH, 'Origin-Realm'=OR,
						      'Result-Code'=fixme}
			end
	end,
	lager:info("ULR Resp: ~p~n", [Resp]),
	{reply, Resp};

handle_request(Packet, _SvcName, {_,_}) ->
	lager:error("Unsuppoerted message: ~p~n", [Packet]),
	discard.
