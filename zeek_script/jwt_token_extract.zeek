@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/logging
@load policy/protocols/http/header-names
@load policy/protocols/http/var-extraction-cookies
@load base/protocols/http/entities
@load policy/protocols/http/header-names

# 构造table，键为"http$uid,http$id,is_orig",值为"uid" ,"id.orig_h","id.orig_p":35750,"id.resp_h":"192.168.56.107","id.resp_p","trans_depth","

module  Url_cookie_extraction;

export {
    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { LOG };


    # 利用这个数据结构记录两个五元组的对应关系
    type url_with_cookie: record{
        # tls_client_ip:       string &log;
        # tls_client_port:     string &log;
        # tls_apisix_ip:       string &log;
        # tls_apisix_port:     string &log;
        # tls_protocol:        string &log;
        # http_apisix_ip:      string &log;
        # http_apisix_port:    string &log;
        # http_server_ip:      string &log;
        # http_server_port:    string &log;
        # http_protocol:       string &log;
        ts:              string &log;
        cookie:          string &log;
        url:             string &log;
        is_orig:         string &log;
        };
    }

global url_with_cookie_s: set[url_with_cookie];


global cookie = "";
global url = "";
global ts = "";
global is_orig_str = "";
global temp_header : table[string] of string;



event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
    {
    temp_header[name]=value;
    }


event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) 
    {
    ts = cat(c$http$ts);
    url = cat(c$http$uri);
    cookie = cat(temp_header["COOKIE"]);
    is_orig_str = cat(is_orig);
    # print ts;
    # print url;
    # print cookie;
    # print is_orig_str;
    local temp_url_with_cookie = url_with_cookie($cookie = cookie,
                                                    $url = url,
                                                    $ts = ts,
                                                    $is_orig = is_orig_str);
    add url_with_cookie_s[temp_url_with_cookie];
    }


event zeek_init()  
    {
    Log::create_stream(LOG, [$columns=url_with_cookie, $path="./output/url_with_cookie/output"]);
    }

event zeek_done()
    {
    for (value in url_with_cookie_s)
        {
        Log::write(Url_cookie_extraction::LOG, value);
        }
    }
