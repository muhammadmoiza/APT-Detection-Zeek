@load base/frameworks/notice
@load base/frameworks/input

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

event blacklistentry(description: Input::TableDescription,
                     t: Input::Event, data: ID, data1: URL) {
    local i = 1;
    for (req in URL_filter)
    {
        blacklist[i] = set();
        Input::add_table([$source=URL_filter[i]$intel_path, $name=URL_filter[i]$intel_path,
                            $idx=Idx, $destination=blacklist[i]]);
        Input::remove(URL_filter[i]$intel_path);
        ++i;
    }
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
                NOTICE([
                        $note=UrlBlacklist,
                        $msg=fmt("%s has been accessed while blacklisted", rec$host),
                        $identifier=cat(rec$ts)
                ]);
            }
        }
        ++i;
    }
}