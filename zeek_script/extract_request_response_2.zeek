
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
@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/logging
@load policy/protocols/http/header-names
@load policy/protocols/http/var-extraction-cookies
@load base/protocols/http/entities
@load policy/protocols/http/header-names

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
        uri:            string &log;
        cookie:        string &log;
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

# request_needed_headers[my_uid][header_name] = value;
global request_needed_headers: table[string] of  table[string] of string;
# response_needed_headers[my_uid][header_name] = value;
global response_needed_headers: table[string] of  table[string] of string;
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
    all_http_replies[my_uid] = cat(code);
    # print "http_reply " + my_uid;
    # print my_uid;
    # if (my_uid !in all_http_replies)
    #     {
    #     print "get code of "+ my_uid+"it is "+cat(code);
    #     all_http_replies[my_uid] = cat(code);
    #     }
    # else
    #     {
    #     print "Duplicated my_uid in http_reply";
    #     }
        
    }

# event http_content_type(c: connection, is_orig: bool, ty: string, subty: string)
#     {
#     local my_uid = get_my_uid(c);
#     # print "http_content_type " + my_uid;
#     # print "in http_content_type"+my_uid;
#     if (!is_orig)
#         {
#         if (my_uid !in all_http_content_type)
#             {
#             all_http_content_type[my_uid] = ty;
#             }
#         else
#             {
#             print "Duplicated my_uid in http_content_type";
#             print all_http_content_type[my_uid];
#             # print cat(ty)+"now";
#             # print my_uid+"http_content_type";
#             }
#         }
        
#     }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    local my_uid = get_my_uid(c);
    # print hlist;
    # print "http_all_headers " + my_uid;
    # print "http_all_headers"+my_uid;
    local temp_h = table(
                ["USER-AGENT"] = "",
                ["HOST"] = "",
                ["REFERER"] = "",
                ["CONTENT-TYPE"] = "",
                ["COOKIE"] = ""
            );
    local header_name = "";
    local header_value = "";
    if (is_orig)
        {
        if (my_uid !in request_needed_headers)
            {
            # local temp_h = table(
            #     ["USER-AGENT"] = "",
            #     ["HOST"] = "",
            #     ["REFERER"] = "",
            #     ["CONTENT-TYPE"] = ""
            # );
            for (i in hlist)
                {
                header_name = hlist[i]$name;
                header_value = hlist[i]$value;
                temp_h[header_name] = header_value;
                }
                request_needed_headers[my_uid] = temp_h;
            }
        else
            {
            print "Duplicated my_uid in http_all_headers";
            # print my_uid+"http_all_headers";
            }

        }
    else
        {
        if (my_uid !in response_needed_headers)
            {
            # local temp_h = table(
            #     ["USER-AGENT"] = "",
            #     ["HOST"] = "",
            #     ["REFERER"] = "",
            #     ["CONTENT-TYPE"] = ""
            # );
            for (i in hlist)
                {
                header_name = hlist[i]$name;
                header_value = hlist[i]$value;
                temp_h[header_name] = header_value;
                }
                response_needed_headers[my_uid] = temp_h;
            }
        else
            {
            print "Duplicated my_uid in http_all_headers";
            # print my_uid+"http_all_headers";
            }
        }
    
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    local my_uid = get_my_uid(c);
    print "http_entity_data " + my_uid;
    
    # print "is_orig is"+cat(is_orig);
    local temp_pair: request_response_pair = [$request = "", $response = ""];
    if (is_orig) #是request的entiry
        {
        # print "request message";
        if (my_uid in all_request_response_pair) # 不是首次接收到
            {
            all_request_response_pair[my_uid]$request += data;
            }
        else # 首次接收到
            {
            # local temp_pair: request_response_pair = [$request = "", $response = ""];
            # print "create request for "+ my_uid;
            all_request_response_pair[my_uid] = temp_pair;
            all_request_response_pair[my_uid]$request = data;
            }
        }
    else
        {
        if (my_uid !in all_request_response_pair) # 这个请求的request没有entiry data
            {
            # local temp_pair: request_response_pair = [$request = "", $response = ""];
            all_request_response_pair[my_uid] = temp_pair;
            all_request_response_pair[my_uid]$response = data;
            }
        else
            {
            if (all_request_response_pair[my_uid]$response != "")
                {
                all_request_response_pair[my_uid]$response += data;
                }
            else
                {
                all_request_response_pair[my_uid]$response = data;
                }
            }
        }
    }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    {
    local my_uid = get_my_uid(c);
    print "http_message_done " + cat(is_orig)+" " + my_uid ;

    if (is_orig) # 是request
        {
        if (my_uid !in all_http_message)
            {# 是request 且 之前没有记录,
            print "my_uid !in all_http_message " +my_uid;
            local temp_request = "";
            if (my_uid !in all_request_response_pair)
                {
                temp_request = "";
                }
            else 
                {
                temp_request = all_request_response_pair[my_uid]$request;
                }
            
            local temp_http_message = http_message($uid=c$uid,
                $trans_depth = cat(c$http$trans_depth),
                $orig_h = cat(c$http$id$orig_h),
                $resp_h = cat(c$http$id$resp_h),
                $orig_p = cat(port_to_count(c$http$id$orig_p)),
                $resp_p = cat(port_to_count(c$http$id$resp_p)),
                $proto = cat(get_port_transport_proto(c$http$id$resp_p)),
                # request的数据
                $uri = c$http$uri,
                $host = request_needed_headers[my_uid]["HOST"],
                $user_agent = request_needed_headers[my_uid]["USER-AGENT"],
                $referrer = request_needed_headers[my_uid]["REFERER"],
                $cookie = request_needed_headers[my_uid]["COOKIE"],
                $request = temp_request,
                $request_time = cat(stat$start),
                $request_bytes = cat(stat$header_length+stat$body_length),
                # response的数据
                $response = "",  
                $response_time = "",
                $content_type = "",
                $response_bytes = "",
                $status_code = "");
            all_http_message[my_uid] = temp_http_message;
            # print "in my_uid"+my_uid;
            }
        else
            {
            #这时 request是第一次出现 但是已经有了记录，说明有问题。
            print "Duplicated my_uid in http_message_done";
            
            }
        }
    else     # 是response
        {
        if (my_uid !in all_http_message) # 是response但是uid没有出现过，说明抓包的时候没有抓到response的包，丢弃掉这个请求与响应
            {
            print "lost request in http_message_done";
            # print "lost " + my_uid;
            }
        else # 是response且uid已经出现过，填充上对应的response
            {
            local temp_response = "";
            local temp_content_type = "";
            if (my_uid !in all_request_response_pair)
                {
                temp_response = "";
                }
            else
                {
                temp_response = all_request_response_pair[my_uid]$response;
                }
            if (my_uid in response_needed_headers && "CONTENT-TYPE" in response_needed_headers[my_uid])
                {
                temp_content_type = response_needed_headers[my_uid]["CONTENT-TYPE"];
                }
            all_http_message[my_uid]$response = temp_response;
            all_http_message[my_uid]$response_time = cat(stat$start);
            all_http_message[my_uid]$response_bytes = cat(stat$header_length+stat$body_length);
            all_http_message[my_uid]$content_type = temp_content_type;
            all_http_message[my_uid]$status_code = cat(all_http_replies[my_uid]);
            }
        }

    }

event zeek_init()  
    {
    Log::create_stream(LOG, [$columns=http_message, $path="./temp/message_extract_2"]);
    }

event zeek_done()
    {
    for (name,value in all_http_message)
        {
        # print "my_uid"+name
        Log::write(HTTP_req_resp::LOG, value);
        # if (name in response_table)
        #     Log::write(Message_extract::LOG, [$uid=name,$request=value$request,
        #                           $response=response_table[name],$ts=value$ts]);
        # else
        #     print name;
        }
    print response_needed_headers;
    }


