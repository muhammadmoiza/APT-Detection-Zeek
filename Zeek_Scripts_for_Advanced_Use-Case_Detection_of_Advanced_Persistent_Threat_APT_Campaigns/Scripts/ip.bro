@load base/frameworks/notice
@load base/frameworks/input
@load ./IoC_TTP
@load base/utils/addrs.bro

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
global ipx = 1;

event ipentry(description: Input::TableDescription,
                     t: Input::Event, data: ID, data1: IP) {
        iptable[ipx] = set();
        Input::add_table([$source=IP_filter[ipx]$intel_path, $name=IP_filter[ipx]$intel_path,
                            $idx=IPrecord, $destination=iptable[ipx]]);
        Input::remove(IP_filter[ipx]$intel_path);
        ++ipx;
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
                local format: string = "%F, %H:%M:%S";
                IoCToTTP::IoC_TTP_Mapping(strftime(format,rec$ts),IP_filter[i]$group_name,"IP",addr_to_uri(rec$id$resp_h),rec$id$orig_h, IP_filter[i]$log_path);
            }
        }
        ++i;
    }
}