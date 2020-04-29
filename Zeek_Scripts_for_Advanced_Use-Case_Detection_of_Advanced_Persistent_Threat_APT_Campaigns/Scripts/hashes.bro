@load base/frameworks/notice
@load base/frameworks/input
@load ./IoC_TTP

redef enum Notice::Type += 
{
    FilesBlacklist
};

type ID: record {
    id: count;
};

type MalHashes: record {
	group_name: string;
	intel_path: string;
	log_path: string;
};

type hash: record {
    malware: string;
};

global Hash_filter: table[count] of MalHashes = table();
global malwarehashes: table[count] of set[string] = table();
global hashx = 1;

event hashentry(description: Input::TableDescription,
                     t: Input::Event, data: ID, data1: MalHashes) {
        malwarehashes[hashx] = set();
        Input::add_table([$source=Hash_filter[hashx]$intel_path, $name=Hash_filter[hashx]$intel_path,
                            $idx=hash, $destination=malwarehashes[hashx]]);
        Input::remove(Hash_filter[hashx]$intel_path);
        ++hashx;
}

event bro_init()
{
    Input::add_table([$source="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Scripts/Hash_filter.txt", $name="Hash_filter",
                          $idx=ID,$val=MalHashes, $destination=Hash_filter, $ev=hashentry]);
    Input::remove("Hash_filter");
}

event Files::log_files(rec: Files::Info)
{
	local i = 1;
    for (f in malwarehashes)
    {
		for (req in malwarehashes[i])
		{
			if (rec?$sha256)
			{
				if (rec$sha256 == req)
				{
					local format: string = "%F, %H:%M:%S";
					NOTICE([
							$note=FilesBlacklist,
							$ts=rec$ts,
							$msg=fmt("%s file has entered the system while blacklisted", rec$sha256),
							$identifier=cat(rec$ts)
					]);
					#IoCToTTP::IoC_TTP_Mapping(strftime(format,rec$ts), Hash_filter[i]$group_name,"Malware",rec$sha256,rec$id$orig_h, Hash_filter[i]$log_path);
				}
			}
		}
		++i;
    }
}