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

global URL_filter: table[count] of URL = table();
global blacklist: table[count] of set[string] = table();
global url = 1;

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
	Input::add_table([$source="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Scripts/URL_filter.txt", $name="URL_filter",
                          $idx=ID,$val=URL, $destination=URL_filter, $ev = blacklistentry]);
	Input::remove("URL_filter");
}


#the event will call on every http request
event HTTP::log_http(rec: HTTP::Info)
{
    local i = 1;    #
    for (f in blacklist)
    {
        for (req in blacklist[i])
        {
            if (rec$host == req)
            {
                local format: string = "%F, %H:%M:%S";
                IoCToTTP::IoC_TTP_Mapping(strftime(format,rec$ts), URL_filter[i]$group_name,"URL",rec$host,rec$id$orig_h, URL_filter[i]$log_path);
            }
        }
        ++i;
    }
}