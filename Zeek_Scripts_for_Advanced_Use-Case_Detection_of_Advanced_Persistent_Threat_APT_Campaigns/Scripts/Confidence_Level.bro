@load base/utils/site
@load base/frameworks/notice
@load base/frameworks/input

module IoCToTTP;

global IoC_TTP_filter: table[count] of IoC_TTP = table();
global IoC_TTP_Map_List: table[count] of table[count] of IoC_TTP_Map = table();
global iocttpx = 1;

export {
    global IoC_TTP_Mapping: function(ts: string, group_name: string, IoC_type: string, IoC: any, orig_addr: addr, log_path: string): bool;

    redef enum Log::ID += { LOG };
    type Info: record {
        ts: string &log;
        group_name: string &log;
        ioc_type: string &log;
        ioc: string &log;
        confidence_level: double &log;
        scoring: count &log;
    };
}

event IoC_TTP_Map_Event(description: Input::TableDescription,
                     t: Input::Event, data: ID1, data1: IoC_TTP) {
        IoC_TTP_Map_List[iocttpx] = table();
        Input::add_table([$source=IoC_TTP_filter[iocttpx]$ioc_path, $name=IoC_TTP_filter[iocttpx]$ioc_path,
                            $idx=ID2, $val = IoC_TTP_Map, $destination=IoC_TTP_Map_List[iocttpx]]);
        Input::remove(IoC_TTP_filter[iocttpx]$ioc_path);
        ++iocttpx;
}

event bro_init()
{
	Input::add_table([$source="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Scripts/IoC_TTP_filter.txt", $name="IoC_TTP_filter",
                          $idx=ID1, $val=IoC_TTP, $destination=IoC_TTP_filter, $ev = IoC_TTP_Map_Event]);
	Input::remove("IoC_TTP_filter");

    Log::create_stream(IoCToTTP::LOG, [$columns=Info, $path="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Logs/"]);

    Log::remove_filter(IoCToTTP::LOG, "default");
}

function IoC_TTP_Mapping (ts: string, group_name: string, IoC_type: string, IoC: any, orig_addr: addr, log_path: string): bool
{
    local traffic_type: string = "Inbound";
    if(Site::is_private_addr(orig_addr))
        traffic_type = "Outbound";
    local flag: bool = F;
    local i = 1;
    local temp = 1;
    for(ttp_filter in IoC_TTP_filter)
    {
        if(IoC_TTP_filter[i]$group_name == group_name)
        {
            temp = i;
            flag = T;
        }
        ++i;
    }
    i = 1;
    if (flag == T)
    {
        for (ttp in IoC_TTP_Map_List[temp])
        {
            if (IoC_TTP_Map_List[temp][i]$IoC_Type == IoC_type && IoC_TTP_Map_List[temp][i]$Traffic_Type == traffic_type)
            {
                
                local rec: IoCToTTP::Info = [$ts=ts, $group_name=IoC_TTP_filter[temp]$group_name, $ioc_type=IoC_type, $ioc=IoC, $traffic_type=traffic_type, $tactic=IoC_TTP_Map_List[temp][i]$Tactics, $technique=IoC_TTP_Map_List[temp][i]$Techniques];
                local filter: Log::Filter = [$name=IoC_TTP_filter[temp]$group_name, $path=log_path];
                Log::add_filter(IoCToTTP::LOG, filter);
                Log::write(IoCToTTP::LOG, rec);

            }
            ++i;
        }
    }
     return T;
}

event bro_done()
{
    Log::remove_stream(IoCToTTP::LOG);
}