# 提取request与response特征的第二个版本
# uid	ts	six_tuple	request	response	orig_fuids	resp_fuids	orig_h	resp_h	orig_p	resp_p	proto	user_agent	host
# 提取的特征包括
#     uid                                                 1
#     trans_depth                                         1
#     五元组:orig_h、resp_h、orig_p、resp_p、proto、
#     host                                                1
#     user_agent                                          1
#     content-type                                        1
#     referrer                                            1
#     status_code                                         1
#     request                                             1
#     response                                            1


#     request时间、                                       1
#     response时间、                                      1
#     response字节数、                                    1
#     request字节数                                       1




# 利用 http_reply event 的 code:count, 获取
#     status_code

# 利用 http_content_type event 的ty: string 获取
#     content-type

# 利用 http_all_headers event 获取
#     host、user_agent、referrer

# 利用 http_entity_data event 的 data: string 获取
#     request与response

# 利用 http_message_done event 的 http_message_stat: stat 获取 
#     request时间、response时间、 response字节数、 request字节数
#     uid 五元组 trans_depth


module HTTP_req_resp;
export {
    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { LOG };

    type http_message: record{
        uid:            string &log;
        trans_depth:    string &log;
        orig_h:         string &log;
        resp_h:         string &log;
        orig_p:         string &log;
        resp_p:         string &log;
        proto:          string &log;
        host:           string &log;
        user_agent:     string &log;
        content_type:   string &log;
        referrer:       string &log;
        status_code:    string &log;
        request:        string &log;
        response:       string &log;
        request_time:   string &log;
        response_time:  string &log;
        response_bytes: string &log;
        request_bytes:  string &log;
        };
    }

type request_response_pair: record{
    request:            string &log;
    response:           string &log;
};

type needed_headers: record{
    host:               string &log;
    user_agent:         string &log;
    referrer:           string &log;
};


global all_http_message: table[string] of http_message;
global temp_heades: table[string] of string;
global all_http_replies: table[string] of string;
global all_http_content_type: table[string] of string;
global all_needed_headers: table[string] of  table[string] of string;
global all_request_response_pair: table[string] of request_response_pair;


function get_my_uid(c: connection): string
    {
    local my_uid: string;
    my_uid = c$http$uid+"-"+cat(c$http$trans_depth);
    return my_uid;
    }


event http_reply(c: connection, version: string, code: count, reason: string)
    {
    local my_uid = get_my_uid(c);
    print "http_reply " + my_uid;
    }

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string)
    {
    local my_uid = get_my_uid(c);
    print "http_content_type " + my_uid;
        
    }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    local my_uid = get_my_uid(c);
    print "http_all_headers " + my_uid;
    
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    local my_uid = get_my_uid(c);
    print "http_entity_data " + my_uid;
    }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    {
    local my_uid = get_my_uid(c);
    print "http_message_done " + my_uid;

    }


# event zeek_init()  
#     {
#     Log::create_stream(LOG, [$columns=http_message, $path="./temp/message_extract_2"]);
#     }

# event zeek_done()
#     {
#     for (name,value in all_http_message)
#         {
#         print "my_uid"+name;
#         Log::write(HTTP_req_resp::LOG, value);
#         # if (name in response_table)
#         #     Log::write(Message_extract::LOG, [$uid=name,$request=value$request,
#         #                           $response=response_table[name],$ts=value$ts]);
#         # else
#         #     print name;
#         }
#     }


