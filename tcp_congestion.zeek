# Load necessary base scripts
@load base/protocols/tcp

# Log file for TCP congestion data
module TCPCongestion;
export {
    redef enum Log::ID += { LOG };
}

@load base/frameworks/logging

module TCPCongestion;

type Info: record {
    ts: time &log;                  # Timestamp of the event
    id: conn_id &log;               # Connection identifier
    orig_h: addr &log;              # Originating host
    resp_h: addr &log;              # Responding host
    orig_retrans: count &log;       # Retransmissions from origin
    resp_retrans: count &log;       # Retransmissions from responder
    reset_flag: bool &log;          # Was a reset (RST) flag observed?
    fin_flag: bool &log;            # Was a FIN flag observed?
    high_retrans: bool &log;        # High retransmission indicator
};

# Log output stream
redef Log::default_filters += {
    ["TCPCongestion::LOG"] = [$path="tcp_congestion", $include=set("id", "orig_retrans", "resp_retrans", "high_retrans")]
};

global tcp_congestion_log: log_info(TCPCongestion::Info) = Log::create_stream(TCPCongestion::LOG);

# Monitor packet-level congestion indicators
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) 
    {
    if (flags == "R") {
        print fmt("TCP RESET detected: %s -> %s", c$id$orig_h, c$id$resp_h);
    }
    if (flags == "F") {
        print fmt("TCP FIN detected: %s -> %s", c$id$orig_h, c$id$resp_h);
    }
    if (seq < ack) {
        print fmt("Possible retransmission: %s -> %s", c$id$orig_h, c$id$resp_h);
    }
}

# Connection-level summary and analysis
event connection_finished(c: connection)
    {
    local orig_retrans = c$tcp$retrans_orig;
    local resp_retrans = c$tcp$retrans_resp;
    local reset_flag = (c$tcp$rst_seen > 0);
    local fin_flag = (c$tcp$fin_seen > 0);
    local high_retrans = (orig_retrans > 10 || resp_retrans > 10);

    Log::write(tcp_congestion_log, [
        $ts = network_time(),
        $id = c$id,
        $orig_h = c$id$orig_h,
        $resp_h = c$id$resp_h,
        $orig_retrans = orig_retrans,
        $resp_retrans = resp_retrans,
        $reset_flag = reset_flag,
        $fin_flag = fin_flag,
        $high_retrans = high_retrans
    ]);

    if (high_retrans) {
        print fmt("High retransmissions detected: %s -> %s", c$id$orig_h, c$id$resp_h);
    }
}
