-module(osmo_dia2gsup).
-behavior(gen_server).

-include_lib("diameter/include/diameter.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").
%-include_lib("diameter_settings.hrl").

% API
-export([start_link/0]).
-export([start/0, stop/0]).

% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3, terminate/2]).

-define(SERVER, ?MODULE).

% Diameter application definitions

-define(DIA_STATS_TAB, iwf_stats).
-define(DIA_STATS_COUNTERS, [event_OK, event_ERR]).

-define(SVC_NAME, ?MODULE).
-define(APP_ALIAS, ?MODULE).
-define(CALLBACK_MOD, server_cb).
-define(DIAMETER_DICT_HSS, diameter_3gpp_ts29_272).

-define(APPID_S6, #'diameter_base_Vendor-Specific-Application-Id'{'Vendor-Id'=10515, 'Auth-Application-Id'=[16777251]}).
-define(SERVICE(Name), [{'Origin-Host', application:get_env(osmo_dia2gsup, origin_host, "hss.localdomain")},
			{'Origin-Realm', application:get_env(osmo_dia2gsup, origin_realm, "localdomain")},
			{'Vendor-Id', application:get_env(osmo_dia2gsup, vendor_id, 0)},
			{'Product-Name', "osmo_dia2gsup"},
			{'Auth-Application-Id', []},
			{'Vendor-Specific-Application-Id', [?APPID_S6]},
			{application,
			 	[{alias, ?APP_ALIAS},
				 {dictionary, ?DIAMETER_DICT_HSS},
				 {module, ?CALLBACK_MOD}]
			}]).



%% ------------------------------------------------------------------
%% API
%% ------------------------------------------------------------------

start_link() ->
	gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

start() ->
	application:ensure_all_started(?MODULE),
	start_link().

stop() ->
	gen_server:cast(?SERVER, stop).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

%% @callback gen_server
init(State) ->
	% DIAMETER side
	SvcName = ?MODULE,
	diameter:start_service(SvcName, ?SERVICE(SvcName)),
	Ip = application:get_env(osmo_dia2gsup, diameter_ip, "192.168.104.4"),
	Port = application:get_env(osmo_dia2gsup, diameter_port, 3868),
	Proto = application:get_env(osmo_dia2gsup, diameter_proto, sctp),
	listen({address, Proto, element(2,inet:parse_address(Ip)), Port}),
	lager:info("Diameter HSS Application started on IP ~s, ~p port ~p~n", [Ip, Proto, Port]),
	{ok, State}.

%% @callback gen_server
handle_call(_Req, _From, State) ->
	{noreply, State}.

%% @callback gen_server
handle_cast(stop, State) ->
	{stop, normal, State};
handle_cast(_req, State) ->
	{noreply, State}.


%% @callback gen_server
handle_info(_Info, State) ->
	{noreply, State}.

%% @callback gen_server
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

%% @callback gen_server
terminate(normal, _State) ->
	diameter:stop_service(?SVC_NAME),
	lager:info("Diameter HSS Application stopped.~n"),
	ok;
terminate(shutdown, _State) ->
	ok;
terminate({shutdown, _Reason}, _State) ->
	ok;
terminate(_Reason, _State) ->
	ok.



%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

listen(Name, {address, Protocol, IPAddr, Port}) ->
	TransOpts = [{transport_module, tmod(Protocol)},
		     {transport_config, [{reuseaddr, true},
		      			 {ip, IPAddr}, {port, Port}]}],
	{ok, _} = diameter:add_transport(Name, {listen, TransOpts}).

listen(Address) ->
	listen(?SVC_NAME, Address).

tmod(tcp) -> diameter_tcp;
tmod(sctp) -> diameter_sctp.
