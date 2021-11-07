@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/logging
@load policy/protocols/http/header-names
@load policy/protocols/http/var-extraction-cookies
@load base/protocols/http/entities
@load policy/protocols/http/header-names

# 构造table，键为"http$uid,http$id,is_orig",值为"uid" ,"id.orig_h","id.orig_p":35750,"id.resp_h":"192.168.56.107","id.resp_p","trans_depth","

module  Message_extract;

export {
    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { LOG };

    # Define a new type called Factor::Info.
    # type Info: record {
    #     num:           count &log;
    #     factorial_num: count &log;
    #     };
    type http_message: record{
        uid:           string &log;
        ts:            time &log;
        six_tuple:     string &log; 
        request:       string &log;
        response:      string &log;
        orig_fuids:    string &log;
        resp_fuids:    string &log;
        orig_h:        string &log;
        resp_h:        string &log;
        orig_p:        string &log;
        resp_p:        string &log;
        proto:         string &log;
        user_agent:    string &log;
        host:          string &log;
        };
    }
type mime_rec: record{
    original_name: string;
    name: string;
    value: string;
};



global all_http_message: table[string] of http_message;
global response_table: table[string] of string;
global http_header_name: table[string] of table[count] of mime_rec;
global http_headers: table[string] of table[string] of string;
global http_uid : table[string] of string;
global temp_header : table[string] of string;
global header_names: table[count] of mime_rec;
global length : count;
# global exist_uids : set[string];
# event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
#     {
#     header_names = hlist;
#     }

# event http_header(C: connection, is_orig: bool, original_name: string, name: string, value: string) 
#     {
#     temp_header[name] = value;
#     # print C$http$uid+" "+cat(C$http$trans_depth) + cat(is_orig) + " http_header event";
#     }

event http_all_headers(C: connection, is_orig: bool, hlist: mime_header_list) 
    {
    header_names = hlist;

    # print "CCCCCC";
    # print C;
    local uid = C$http$uid+"-"+cat(C$http$trans_depth);
    # print C$http;
    local six_tuple = fmt("%s-%s-%s-%s-%s-%s",C$http$id$orig_h,C$http$id$resp_h,cat(port_to_count(C$http$id$resp_p)),get_port_transport_proto(C$http$id$resp_p),C$http$user_agent,C$http$host);
    local temp_entity = "";

    local temp_header_str = "";

    # length  =  1;
    # while (length <= |header_names|)
    #     {
    #     temp_header_str+=fmt("%s:%s\r\n",header_names[length]$original_name,temp_header[header_names[length]$name]);
    #     length += 1;
    #     }
    for (i in hlist)
        {
        temp_header_str += fmt("%s:%s\r\n",hlist[i]$original_name,hlist[i]$value);
        }
    # temp_header = table();

    if (is_orig)
        {
        # 如果是client发送的，构造header
        temp_entity = "";
        temp_entity = fmt("%s %s %s/%s\r\n",C$http$method,C$http$uri,"HTTP","1.1");
        temp_entity+= temp_header_str;
        if (uid !in all_http_message)
            {
            local ts = C$http$ts;
            local orig_h = cat(C$http$id$orig_h);
            local resp_h = cat(C$http$id$resp_h);
            local resp_p = cat(port_to_count(C$http$id$resp_p));
            local proto = cat(get_port_transport_proto(C$http$id$resp_p));
            local user_agent = C$http$user_agent;
            local host = cat(C$http$host);
            local orig_p = cat(port_to_count(C$http$id$orig_p));
            all_http_message[uid] = http_message($uid=uid,$ts=ts,$six_tuple=six_tuple,
                        $request = temp_entity,$response="",$orig_fuids="",$resp_fuids="",
                        $orig_h=orig_h,$resp_h=resp_h,$resp_p=resp_p,$proto=proto,
                        $user_agent=user_agent,$host=host,$orig_p=orig_p);
            # add exist_uids[uid];            
            }

        else
            {
            all_http_message[uid]$request = temp_entity;
            }
        }
    else
        {
        temp_entity = "";
        temp_entity+=fmt("%s/%s %s %s\r\n","HTTP",cat(C$http$version),cat(C$http$status_code),C$http$status_msg);
        temp_entity+= temp_header_str;
        if (uid !in all_http_message)
            {
            ts = C$http$ts;
            orig_h = cat(C$http$id$orig_h);
            resp_h = cat(C$http$id$resp_h);
            resp_p = cat(port_to_count(C$http$id$resp_p));
            proto = cat(get_port_transport_proto(C$http$id$resp_p));
            user_agent = C$http$user_agent;
            host = cat(C$http$host);
            orig_p = cat(port_to_count(C$http$id$orig_p));
            all_http_message[uid] = http_message($uid=uid,$ts=ts,$six_tuple=six_tuple,
                                    $response = temp_entity,$request="",$orig_fuids="",
                                    $resp_fuids="",$orig_h=orig_h,$resp_h=resp_h,$resp_p=resp_p,
                                    $proto=proto, $user_agent=user_agent,$host=host,$orig_p=orig_p);
            # add exist_uids[uid];
            }
        else
            {
            all_http_message[uid]$response = temp_entity;
            }
        }
    }

event http_entity_data(C: connection, is_orig: bool, length: count, data: string) 
    {
    # print C$http$uid+" "+cat(C$http$trans_depth) + cat(is_orig) +" http_entity_data event";
    # print "http_entity_data event";
    local uid = C$http$uid+"-"+cat(C$http$trans_depth);
    if (is_orig)
        {
        all_http_message[uid]$request+=fmt("\r\n\r\n%s",data);

        }
    else
        {
        all_http_message[uid]$response+=fmt("\r\n\r\n%s",data);
        # response_table[uid]+=fmt("\r\n\r\n%s",data);
        }
    }


event http_message_done(C: connection, is_orig: bool, stat: http_message_stat)
    {
    local uid = C$http$uid+"-"+cat(C$http$trans_depth);
    if (is_orig)
        {
        local orig_fuids = "";
        if (C$http ?$ orig_fuids)
            {
            for (i in C$http$orig_fuids)
                {
                orig_fuids += "--"+C$http$orig_fuids[i];
                }
            all_http_message[uid]$orig_fuids+=orig_fuids;
            }
        }
    else
        {
        local resp_fuids = "";
        if (C$http ?$ resp_fuids)
            {
            for (i in C$http$resp_fuids)
                {
                resp_fuids += "--"+C$http$resp_fuids[i];
                }
            all_http_message[uid]$resp_fuids+=resp_fuids;
            }
        }

    }

event zeek_init()  
    {
    Log::create_stream(LOG, [$columns=http_message, $path="./temp/message_extract"]);
    }

event zeek_done()
    {
    for (name,value in all_http_message)
        {
        Log::write(Message_extract::LOG, value);
        # if (name in response_table)
        #     Log::write(Message_extract::LOG, [$uid=name,$request=value$request,
        #                           $response=response_table[name],$ts=value$ts]);
        # else
        #     print name;
        }
    }
