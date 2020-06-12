@load base/frameworks/sumstats
@load base/utils/addrs.bro

redef enum Notice::Type += 
	{
    ExcessiveRequests
	};

const excessive_limit: double = 5  &redef;
global dns_key: string = "";

event bro_init()
    {
    local r1 = SumStats::Reducer($stream="dns.lookup", $apply=set(SumStats::SUM));
    SumStats::create([$name="dns.requests",
                      $epoch=6hrs,
                      $threshold = excessive_limit,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = 
                      	{
                        return result["dns.lookup"]$sum;
                      	},
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = 
                      	{
                        local r = result["dns.lookup"];
                        local var:string = addr_to_uri(key$host);
                        if (key?$str)
                        {
                            var = key$str;
                        }
                        NOTICE([
                            $note=ExcessiveRequests,
                            $src=key$host,
                            $msg=fmt("%s has made more than %.0f DNS requests.", dns_key, r$sum),
                            $sub=cat(r$sum),
                            $identifier=cat(key$host)
                          ]);
                      	}
                    ]);
    }

#Dns request event is called everytime a dns request is made.
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( c$id$resp_p == 53/udp && query != "" )
    {
        SumStats::observe("dns.lookup", [$host=c$id$orig_h], [$str=query]);
        if (query != "")
            dns_key = query;
    }
}