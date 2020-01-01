@load base/frameworks/notice
@load base/frameworks/input

redef enum Notice::Type += 
{
    UrlBlacklist
};

type Idx: record {
    host: string;
};

type URL: record {
	group_name: string;
	intel_path: string;
	log_path: string;
};

type entry: record {
	url: URL;
};

global blacklist: set[string] = set();
global URL_filter: set[URL] = set();

event bro_init()
{
	Input::add_table([$source="/nsm/bro/share/bro/policy/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Scripts/URL_filter.txt", $name="URL_filter",
                          $idx=entry,$val=URL, $destination=URL_filter]);
	Input::remove("URL_filter");
}

event HTTP::log_http(rec: HTTP::Info)
{
    for (f in URL_filter)
    {
        Input::add_table([$source=f$intel_path, $name=f$intel_path,
                          $idx=Idx, $destination=blacklist]);
        Input::remove(f$intel_path);
        for (req in blacklist)
        {
            if (rec$host == req)
            {
                NOTICE([
                        $note=UrlBlacklist,
                        $msg=fmt("%s has been accessed while blacklisted", rec$host),
                        $identifier=cat(rec$host)
                ]);
            }
        }
        blacklist = set();
    }
}
