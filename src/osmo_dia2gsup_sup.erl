-module(osmo_dia2gsup_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).
start_link() ->
	supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
	% GSUP side
	HlrIp = application:get_env(osmo_dia2gsup, hlr_ip, "10.70.0.3"),
	HlrPort = application:get_env(osmo_dia2gsup, hlr_port, 4222),
	Args = [{local, gsup_client}, gsup_client, [HlrIp, HlrPort, []], [{debug, [trace]}]],
	GsupChild = {gsup_client, {gen_server, start_link, Args}, permanent, 2000, worker, [gsup_client]},
	% DIAMETER side
        DiaServer = {osmo_dia2gsup,{osmo_dia2gsup,start_link,[]},
                     permanent,
                     5000,
                     worker,
                     [server_cb]},
        {ok, { {one_for_one, 5, 10}, [DiaServer, GsupChild]} }.
