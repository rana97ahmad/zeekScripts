module XSS;
export {
    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { LOG };

    # Define a new type called Factor::Info.
    type Info: record {
        sourceIP:           addr &log;
        affected_url: string &log;
        };

    }
event zeek_init()
    {
    # Create the logging stream.
    Log::create_stream(XSS::LOG, [$columns=XSS::Info, $path="xss"]);
    }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    local res  = match_pattern(original_URI, /script/);
    if (res$matched){
     Log::write( XSS::LOG, [$sourceIP=c$id$orig_h,
                                  $affected_url=original_URI]);
                                  }
    #print original_URI;
    }
