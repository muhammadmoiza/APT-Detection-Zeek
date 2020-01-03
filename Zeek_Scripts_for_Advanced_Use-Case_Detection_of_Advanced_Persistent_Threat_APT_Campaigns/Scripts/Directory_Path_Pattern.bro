@load base/frameworks/notice
@load base/frameworks/input

redef enum Notice::Type += 
{
    DirectoryPath
};

type dpath: record {
    path: string;
};

type ID: record {
    id: count;
};

type directorypath: record {
	group_name: string;
	intel_path: string;
	log_path: string;
};

global DirectoryPath_filter: table[count] of directorypath = table();
global path: table[count] of set[string] = table();

event directorypathentry(description: Input::TableDescription,
                     t: Input::Event, data: ID, data1: directorypath) {
    local i = 1;
    for (req in DirectoryPath_filter)
    {
        path[i] = set();
        Input::add_table([$source=DirectoryPath_filter[i]$intel_path, $name=DirectoryPath_filter[i]$intel_path,
                            $idx=dpath, $destination=path[i]]);
        Input::remove(DirectoryPath_filter[i]$intel_path);
        ++i;
    }
}

event bro_init()
{
	Input::add_table([$source="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Scripts/Directory_Path_Pattern_filter.txt", $name="Directory_Path_filter",
                          $idx=ID,$val=directorypath, $destination=DirectoryPath_filter, $ev = directorypathentry]);
	Input::remove("Directory_Path_filter");
}


#the event will call on every http request
event HTTP::log_http(rec: HTTP::Info)
{
    local i = 1;    #
    for (f in path)
    {
        for (req in path[i])
        {
            if (rec$uri == req)
            {
                NOTICE([
                        $note=DirectoryPath,
                        $msg=fmt("%s has been accessed while blacklisted", rec$uri),
                        $identifier=cat(rec$ts)
                ]);
            }
        }
        ++i;
    }
}