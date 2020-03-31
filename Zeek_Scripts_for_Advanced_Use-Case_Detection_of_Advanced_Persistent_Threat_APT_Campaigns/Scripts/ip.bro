@load base/frameworks/notice
@load base/frameworks/input

redef enum Notice::Type += 
{
    IPBlacklist
};

type IPrecord: record {
    ip: addr;
};

type ID: record {
    id: count;
};

type IP: record {
	group_name: string;
	intel_path: string;
	log_path: string;
};

global IP_filter: table[count] of IP = table();
global iptable: table[count] of set[addr] = table();

event ipentry(description: Input::TableDescription,
                     t: Input::Event, data: ID, data1: IP) {
    local i = 1;
    for (req in IP_filter)
    {
        iptable[i] = set();
        Input::add_table([$source=IP_filter[i]$intel_path, $name=IP_filter[i]$intel_path,
                            $idx=IPrecord, $destination=iptable[i]]);
        Input::remove(IP_filter[i]$intel_path);
        ++i;
    }
}

event bro_init()
{
	Input::add_table([$source="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Scripts/IP_filter.txt", $name="IP_filter",
                          $idx=ID,$val=IP, $destination=IP_filter, $ev = ipentry]);
	Input::remove("IP_filter");
}


#the event will call on every http request
event HTTP::log_http(rec: HTTP::Info)
{
    local i = 1;    #
    for (f in iptable)
    {
        for (req in iptable[i])
        {
            if (rec$id$resp_h == req)
            {
                NOTICE([
                        $note=IPBlacklist,
                        $msg=fmt("%s has been accessed while blacklisted for %s", rec$host, IP_filter[i]$group_name),
                        $src = rec$id$resp_h,
                        $identifier=cat(rec$ts)
                ]);
                #IoCToTTP::IoC_TTP_Mapping(URL_filter[i]$group_name,"URL",rec$host,rec$id$orig_h, URL_filter[i]$log_path);
            }
        }
        ++i;
    }
}