# 文件夹说明
- doc:存放相关说明文档
- extract_files：临时存放从HTTP流量中提取出的文件
- zeek_script：用于处理pcap的zeek脚本，通过python脚本发调用
- python_script:实现各种功能的python脚本，一般首先调用zeek脚本提取流量中的初级特征，然后利用python对初级特征进行处理
- output：python脚本提取结果的输出路径，包含多个子目录，与python_script
- pcaps：待处理的pcap文件，所有需要处理的pcap文件都要首先放到该文件夹下
- support_file：运行中所需的一些支撑文件
- temp：运行中产生的中间结果，一般是zeek的log日志
- temp_log_file: 运行中产生的中间结果，一般是zeek的log日志

# 使用说明
1. 把要提取的流量放到pcaps文件夹下
2. 打开进入python_scrit文件夹，各个python脚本的作用与输出路径与文件见python脚本功能表：

python脚本功能表
| 文件名                                                        | 作用                                                              | 输出路径                        | 输出文件                                                                            |
| ------------------------------------------------------------- | ----------------------------------------------------------------- | --------------------------- | ----------------------------------------------------------------------------------- |
| extract_features.py                                           | 提取http与https流量特征                                           | output/traffic_features     | \[pcap文件名\].csv                                                                  |
| extract_http_log.py(弃用)                                     | (7-8题，任务1)提取http明文根据元组分类得到的会话数据与文件        | output/request_response     | 以元组创建文件夹，文件夹中的daata.csv包含会话信息，其他文件为从该会话中提取出的文件 |
| extract_request.py                                            | 提取http request中的关键字段                                      | output/http_request         | \[pcap文件名\].csv                                                                  |
| extract_session_feature.py                                    | 提取根据jwt token划分的会话的特征                                 | output/session_feature      | data.csv 中包含了当前pcap文件提取出的所有session的特征                              |
| get_req_resp_proto.py                                         | (7-8题，任务1)提取http明文根据元组分类得到的会话数据与文件        | output/request_response     | 以元组创建文件夹，文件夹中的daata.csv包含会话信息，其他文件为从该会话中提取出的文件 |
| http_session_rebuild.py                                       | 重建http session并dag图                                           | output/http_session_rebuild | \[token\]\_access\_day.html为httpsession的dag图，\[token\].csv为session信息         |
| nfstream_wrapper.py                                           | 调用nfstream获取流量特征，nfstream在ndpi基础上开发,不直接使用     | temp/                       | nfs_feature.csv 来储存nfstream获取的特征                                            |
| ssl_session_rebuild.py                                        | 重建ssl session 还缺少画图功能                                    | output/ssl_session_rebuild  | \[三元组\].csv中包含了session信息，\[三元组\].html为对应的鱼骨图                    |
| zeek_associate_http_tls_wrapper.py                            | 获取http与ssl对应关系的zeek脚本的wrapper                          | output/associate_http_tls   | output.log 其中包含了http与ssl的五元组的对应关系                                    |
| zeek_get_message_wrapper.py (被get_req_resp_proto.py脚本调用) | 获取http消息的的zeek脚本的wrapper，被 get_req_resp_proto.py  调用 |         | /temp/message_extract.log                                          


zeek 脚本功能与解释表：
#TODO