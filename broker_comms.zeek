module zeek_ml;

global content: event(orig_h:addr, orig_p:port, resp_h:addr, resp_p:port, content:string);

function output(c:connection, bytes:string)
    {
    Broker::publish("zeek_ml/content", content, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, bytes);
    }

event tcp_packet(c:connection, is_orig:bool, flags:string, seq:count, ack:count, len:count, payload:string)
    {
    if(is_orig && "S" in c$history && seq==1 && |payload| > 0)
        {
        output(c, string_to_ascii_hex(payload));
        }
    }

event zeek_init()
    {
    Broker::listen("0.0.0.0", 1337/tcp);
    }
