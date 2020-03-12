@load base/utils/site
@load base/frameworks/notice
@load base/frameworks/input

module IoCToTTP;

redef enum Notice::Type += 
{
    MuhammadMoizArshad
};

type ID1: record {
    id: count;
};

type ID2: record {
    id: count;
};

type IoC_TTP: record {
	group_name: string;
	ioc_path: string;
};

type IoC_TTP_Map: record {
    IoC_Type: string;
    Traffic_Type: string;
    Tactics: string;
    Techniques: string;
};

global IoC_TTP_filter: table[count] of IoC_TTP = table();
global IoC_TTP_Map_List: table[count] of table[count] of IoC_TTP_Map = table();

export {
    global IoC_TTP_Mapping: function(group_name: string, IoC_type: string, IoC: any, orig_addr: addr, log_path: string): bool;

    redef enum Log::ID += { LOG };
    type Info: record {
        ts: time &log;
        group_name: string &log;
        ioc_type: string &log;
        ioc: string &log;
        traffic_type: string &log;
        tactic: string &log;
        technique: string &log;
    };
}

event IoC_TTP_Map_Event(description: Input::TableDescription,
                     t: Input::Event, data: ID1, data1: IoC_TTP) {
    local i = 1;
    for (req in IoC_TTP_filter)
    {
        IoC_TTP_Map_List[i] = table();
        Input::add_table([$source=IoC_TTP_filter[i]$ioc_path, $name=IoC_TTP_filter[i]$ioc_path,
                            $idx=ID2, $val = IoC_TTP_Map, $destination=IoC_TTP_Map_List[i]]);
        Input::remove(IoC_TTP_filter[i]$ioc_path);
        ++i;
    }
}

event bro_init()
{
	Input::add_table([$source="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Scripts/IoC_TTP_filter.txt", $name="IoC_TTP_filter",
                          $idx=ID1, $val=IoC_TTP, $destination=IoC_TTP_filter, $ev = IoC_TTP_Map_Event]);
	Input::remove("IoC_TTP_filter");
}

function IoC_TTP_Mapping (group_name: string, IoC_type: string, IoC: any, orig_addr: addr, log_path: string): bool
{
    local traffic_type: string = "Inbound";
    if(Site::is_private_addr(orig_addr))
        traffic_type = "Outbound";
    local flag: bool = T;
    local i = 1;
    local temp = 1;
    for(ttp_filter in IoC_TTP_filter)
    {
        if(IoC_TTP_filter[i]$group_name == group_name)
        {
            temp = i;
        }
        ++i;
    }
    i = 1;
    for (ttp in IoC_TTP_Map_List[temp])
    {
        if (IoC_TTP_Map_List[temp][i]$IoC_Type == IoC_type && IoC_TTP_Map_List[temp][i]$Traffic_Type == traffic_type)
        {
            # NOTICE([
            #             $note=MuhammadMoizArshad,
            #             $msg=fmt("tactics: %s, techniques: %s", IoC_TTP_Map_List[temp][i]$Tactics, IoC_TTP_Map_List[temp][i]$Techniques)
            #     ]);
            Log::create_stream(IoCToTTP::LOG, [$columns=Info, $path=log_path]);
            local rec: IoCToTTP::Info = [$ts=network_time(), $group_name=IoC_TTP_filter[temp]$group_name, $ioc_type=IoC_type, $ioc=IoC, $traffic_type=traffic_type, $tactic=IoC_TTP_Map_List[temp][i]$Tactics, $technique=IoC_TTP_Map_List[temp][i]$Techniques];
            Log::write(IoCToTTP::LOG, rec);
            Log::disable_stream(IoCToTTP::LOG);
        }
        ++i;
     }
     return T;
}