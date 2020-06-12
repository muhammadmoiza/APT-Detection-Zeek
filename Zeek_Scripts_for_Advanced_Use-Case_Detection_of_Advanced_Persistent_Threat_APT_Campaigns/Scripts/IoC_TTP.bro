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
    Weight: count &optional &default = 1;
    Frequency: count &optional &default = 0;
};

type Log_paths: record {
    group_name: string;
    log_path: string;
};

type TTP_Only_Map: record {
    tactic: string;
    technique: string;
    frequency: count &default = 0;
};

global IoC_TTP_filter: table[count] of IoC_TTP = table();
global IoC_TTP_Map_List: table[count] of table[count] of IoC_TTP_Map = table();
global TTP_Only_Filter: table[count] of table[count] of TTP_Only_Map = table();
global iocttpx = 1;

export {
    global IoC_TTP_Mapping: function(ts: string, group_name: string, IoC_type: string, IoC: any, source_ip: addr, dest_ip: addr, log_path: string): bool;

    redef enum Log::ID += { LOG };
    redef enum Log::ID += {APT};
    type Info: record {
        ts: string &log;
        group_name: string &log;
        ioc_type: string &log;
        ioc: string &log;
        traffic_type: string &log;
        source_ip: addr &log;
        dest_ip: addr &log;
        tactic: string &log;
        technique: string &log;
        freq: count &log;
    };

    type APT_Confidence_Level: record {
        ts: string &log;
        group_name: string &log;
        confidence_level: double &log;
        severity_score: count &log; 
    };
}

function TTP_Only_Event(#description: Input::TableDescription,
                     #t: Input::Event, data: ID2, data1: IoC_TTP_Map
                     ) {
    local i: count = 1;
    while (i < iocttpx)
    {
        TTP_Only_Filter[i] = table();
        local j = 1;
        local ttpcount = 1;
        while (j <= |IoC_TTP_Map_List[i]|)
        {
            local flag: bool = T;
            local k: count = 1;
            while ( k < ttpcount)
            {
                if (IoC_TTP_Map_List[i][j]$Tactics == TTP_Only_Filter[i][k]$tactic && IoC_TTP_Map_List[i][j]$Techniques == TTP_Only_Filter[i][k]$technique)
                {
                    flag = F;
                }
                ++k;
            }
            if (flag)
            {
                TTP_Only_Filter[i][ttpcount] = TTP_Only_Map($tactic = IoC_TTP_Map_List[i][j]$Tactics, $technique = IoC_TTP_Map_List[i][j]$Techniques, $frequency = 0);
                #TTP_Only_Filter[i][ttpcount]$tactic = IoC_TTP_Map_List[i][j]$Tactics;
                #TTP_Only_Filter[i][ttpcount]$technique = IoC_TTP_Map_List[i][j]$Techniques;
                #TTP_Only_Filter[i][ttpcount]$frequency = 0;
                ++ttpcount;
            }
            ++j;
        }            
        ++i;
    }
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
	Input::add_table([$source="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Scripts/IoC_TTP_Sources.txt", $name="IoC_TTP_Sources",
                          $idx=ID1, $val=IoC_TTP, $destination=IoC_TTP_filter, $ev = IoC_TTP_Map_Event]);
	Input::remove("IoC_TTP_Sources");

    Log::create_stream(IoCToTTP::LOG, [$columns=Info, $path="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Logs/"]);

    Log::create_stream(IoCToTTP::APT, [$columns=APT_Confidence_Level, $path="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Logs/"]);

    Log::remove_filter(IoCToTTP::LOG, "default");

    Log::remove_filter(IoCToTTP::APT, "default");
}

function IoC_TTP_Mapping (ts: string, group_name: string, IoC_type: string, IoC: any, source_ip: addr, dest_ip: addr, log_path: string): bool
{
    if (|TTP_Only_Filter| <= 0)
    {
        IoCToTTP::TTP_Only_Event();
    }

    #Traffic Type Checking
    local traffic_type: string = "Inbound";
    if(Site::is_private_addr(source_ip))
        traffic_type = "Outbound";
    
    #Group detection
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

    #Finding TTP of Detected Group
    i = 1;
    if (flag == T)
    {
        for (ttp in IoC_TTP_Map_List[temp])
        {

            #IoC to TTP Mapped
            if (IoC_TTP_Map_List[temp][i]$IoC_Type == IoC_type && IoC_TTP_Map_List[temp][i]$Traffic_Type == traffic_type)
            {
                #Check new TTP
                local new_ttp = T;
                local j = 1;
                while (j <= |TTP_Only_Filter[temp]|)
                {
                    if (TTP_Only_Filter[temp][j]$tactic == IoC_TTP_Map_List[temp][i]$Tactics && TTP_Only_Filter[temp][j]$technique == IoC_TTP_Map_List[temp][i]$Techniques)
                    {
                        if (TTP_Only_Filter[temp][j]$frequency>0)
                        {
                            new_ttp = F;
                        }
                        TTP_Only_Filter[temp][j]$frequency += 1;
                    }
                    j += 1;
                }

                #Increment TTP Frequency
                IoC_TTP_Map_List[temp][i]$Frequency += 1;
                local totalttps = |TTP_Only_Filter[temp]|;


                #Individual APT Log Write
                local rec: IoCToTTP::Info = [$ts=ts, $group_name=IoC_TTP_filter[temp]$group_name, $ioc_type=IoC_type, $ioc=IoC, $traffic_type=traffic_type, $source_ip=source_ip, $dest_ip=dest_ip, $tactic=IoC_TTP_Map_List[temp][i]$Tactics, $technique=IoC_TTP_Map_List[temp][i]$Techniques, $freq= IoC_TTP_Map_List[temp][i]$Frequency];
                local filter: Log::Filter = [$name=IoC_TTP_filter[temp]$group_name, $path=log_path];
                Log::add_filter(IoCToTTP::LOG, filter);
                Log::write(IoCToTTP::LOG, rec);

                Log::remove_filter(IoCToTTP::LOG, IoC_TTP_filter[temp]$group_name);

                #If TTP is new
                if (new_ttp == T)
                {
                    #APT Confidence level Calculation
                    local Score: count = 0;
                    local Confidence_Level: double = 0.0;
                    local matchedttps: double = 0.0;
                    local k: count = 1;
                    while (k <= totalttps)
                    {
                        if (TTP_Only_Filter[temp][k]$frequency > 0)
                        {
                            matchedttps += 1.0;
                        }
                        ++k;
                    }

                    #Score Calculation
                    j=1;
                    for (a in IoC_TTP_Map_List[temp])
                    {
                        Score += (IoC_TTP_Map_List[temp][j]$Weight * IoC_TTP_Map_List[temp][j]$Frequency);
                        ++j;
                    }
                    #Add value of Confidence level
                    #Confidence_Level = matchedttps;
                    Confidence_Level = (matchedttps/totalttps) * 100.0;
                    local rec1: IoCToTTP::APT_Confidence_Level = [$ts=ts, $group_name= IoC_TTP_filter[temp]$group_name, $confidence_level= Confidence_Level, $severity_score= Score];
                    local filter1: Log::Filter = [$name="Confidence_Level", $path="/nsm/bro/share/bro/policy/fyp/Zeek_Scripts_for_Advanced_Use-Case_Detection_of_Advanced_Persistent_Threat_APT_Campaigns/Logs/Confidence_Level"];
                    Log::add_filter(IoCToTTP::APT, filter1);
                    Log::write(IoCToTTP::APT, rec1);
                }
            }
            ++i;
        }
    }
     return T;
}

event bro_done()
{
    Log::remove_stream(IoCToTTP::LOG);
    Log::remove_stream(IoCToTTP::APT);
}