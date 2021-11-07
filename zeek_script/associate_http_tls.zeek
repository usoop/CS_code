@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/logging
@load policy/protocols/http/header-names
@load policy/protocols/http/var-extraction-cookies
@load base/protocols/http/entities
@load policy/protocols/http/header-names

# 构造table，键为"http$uid,http$id,is_orig",值为"uid" ,"id.orig_h","id.orig_p":35750,"id.resp_h":"192.168.56.107","id.resp_p","trans_depth","

module  Associate_http_tls;

export {
    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { LOG };


    # 利用这个数据结构记录两个五元组的对应关系
    type five_tuple_pair: record{
        tls_client_ip:       string &log;
        tls_client_port:     string &log;
        tls_apisix_ip:       string &log;
        tls_apisix_port:     string &log;
        tls_protocol:        string &log;
        http_apisix_ip:      string &log;
        http_apisix_port:    string &log;
        http_server_ip:      string &log;
        http_server_port:    string &log;
        http_protocol:       string &log;
        };
    }





global five_tuple_pairs: set[five_tuple_pair];

global tls_client_ip = "";
global tls_client_port = "";
global tls_apisix_ip = "";
global tls_apisix_port = "";
global tls_protocol = "";
global http_apisix_ip = "";
global http_apisix_port = "";
global http_server_ip = "";
global http_server_port = "";
global http_protocol = "";


global temp_headers : table[string] of string;

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
    {
    # print c;
    if (is_orig)
        {
        temp_headers[name]=value;
        }
    # else
    #     {
    #     temp_headers = ();
    #     }
    }


event http_all_headers(C: connection, is_orig: bool, hlist: mime_header_list) 
    {
    if (is_orig)
        {
        tls_client_ip = temp_headers["REMOTE_ADDR"];
        tls_client_port = temp_headers["REMOTE_PORT"];
        tls_apisix_ip = temp_headers["SERVER_ADDR"];
        tls_apisix_port = temp_headers["SERVER_PORT"];
        tls_protocol = "6";
        http_apisix_ip = cat(C$http$id$orig_h);
        http_apisix_port = cat(port_to_count(C$http$id$orig_p));
        http_server_ip = cat(C$http$id$resp_h);
        http_server_port = cat(port_to_count(C$http$id$resp_p));
        http_protocol = "6";
        local temp_tuple_pair = five_tuple_pair($tls_client_ip = tls_client_ip,
                                                $tls_client_port = tls_client_port,
                                                # 默认tls_apisix_ip是docker的ip，与apisix所在服务器网段不相同，所以改成centos的ip，实际情况下要改成apisix暴露给client的ip地址。
                                                $tls_apisix_ip = http_server_ip,
                                                $tls_apisix_port = tls_apisix_port,
                                                $tls_protocol = tls_protocol,
                                                $http_apisix_ip = http_apisix_ip,
                                                $http_apisix_port = http_apisix_port,
                                                $http_server_ip = http_server_ip,
                                                $http_server_port = http_server_port,
                                                $http_protocol = http_protocol);
        add five_tuple_pairs[temp_tuple_pair];
        }

    }


event zeek_init()  
    {
    Log::create_stream(LOG, [$columns=five_tuple_pair, $path="./output/associate_http_tls/output"]);
    }

event zeek_done()
    {
    for (pair in five_tuple_pairs)
        {
        Log::write(Associate_http_tls::LOG, pair);
        }
    }
