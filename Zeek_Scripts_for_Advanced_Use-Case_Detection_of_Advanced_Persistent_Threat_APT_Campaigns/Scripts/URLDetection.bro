@load base/frameworks/notice
@load base/frameworks/input
@load ./IoC_TTP

redef enum Notice::Type += 
{
    UrlBlacklist
};

type Idx: record {
    host: string;
};

type ID: record {
    id: count;
};

type URL: record {
	group_name: string;
	intel_path: string;
	log_path: string;
};

# type Val: record {
# 	ts: time;
# 	uid: string;
# 	id: conn_id;
# 	proto: transport_proto;
# 	service: string &optional;
# 	duration: interval &optional;
# 	orig_bytes: count &optional;
# 	resp_bytes: count &optional;
# 	conn_state: string &optional;
# 	local_orig: bool &optional;
# 	local_resp: bool &optional;
# 	missed_bytes: count &optional;
# 	history: string &optional;
# 	orig_pkts: count &optional;
# 	orig_ip_bytes: count &optional;
# 	resp_pkts: count &optional;
# 	resp_ip_bytes: count &optional;
# 	tunnel_parents: set [string] &optional;
# 	orig_l2_addr: string &optional;
# 	resp_l2_addr: string &optional;
# 	vlan: int &optional;
# 	inner_vlan: int &optional;
# 	speculative_service: string &optional;
# };

global URL_filter: table[count] of URL = table();
global blacklist: table[count] of set[string] = table();
global url = 1;
# global Conn_logs: table[count] of Val = table();
# global conn = 1;

#This event will get URL's against each APT Group
event blacklistentry(description: Input::TableDescription,
                     t: Input::Event, data: ID, data1: URL) {
        blacklist[url] = set();
        Input::add_table([$source=URL_filter[url]$intel_path, $name=URL_filter[url]$intel_path,
                            $idx=Idx, $destination=blacklist[url]]);
        Input::remove(URL_filter[url]$intel_path);
        ++url;
}

event bro_init()
{
	Input::add_table([$source="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Scripts/URLSources.txt", $name="URLSources",
                          $idx=ID,$val=URL, $destination=URL_filter, $ev = blacklistentry]);
	Input::remove("URLSources");
}


#the event will call on every http request to check malicious URL
event HTTP::log_http(rec: HTTP::Info)
{
    local i = 1;    #
    for (f in blacklist)
    {
        for (req in blacklist[i])
        {
            local Url: string = string_cat(rec$host, rec$uri);
            if (string_cat("http://",Url) == req || string_cat("http://www.",Url) == req || string_cat("www.",Url) == req || Url == req || rec$host == req)
            {
                # local j = 1;
                # local orig_h: addr = 0.0.0.0;
                # local resp_h: addr = 0.0.0.0;
                # while (j <= |Conn_logs|)
                # {
                #     if (rec$uid == Conn_logs[j]$uid)
                #     {
                #         orig_h = Conn_logs[j]$id$orig_h;
                #         resp_h = Conn_logs[j]$id$resp_h;
                #         j = |Conn_logs|;
                #     }
                #     ++j;
                # }

                local format: string = "%F, %H:%M:%S";
                IoCToTTP::IoC_TTP_Mapping(strftime(format,rec$ts), URL_filter[i]$group_name,"URL",Url, rec$id$orig_h, rec$id$resp_h, URL_filter[i]$log_path);
            }
        }
        ++i;
    }
}

# event Conn::log_conn(rec: Conn::Info)
# {
#     Conn_logs[conn] = rec;
#     ++conn;
# }
