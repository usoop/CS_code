# import nfstream
# from python_script.zeek_get_message_wrapper import run_zeek
# from python_script.nfstream_wrapper import run_nfstream
import json
import pandas as pd
import os
from tqdm import tqdm 
tqdm.pandas()
import shutil

# 特征：
#     来源：Bot recognition in a Web store: An approach based on unsupervised learning
#     来源：Analysis of Aggregated Bot and Human Traffic on E-Commerce Site
#     Session Length, Session Duration, Mean Time per Page, Image-to-Page Ratio, Volume of Data Transforred to Web Clients, Percentage of Pages with Unassigned Referrers, percentage of 4xx

#     来源：Web robot detection techniques Overview and limitations
#     robots.txt, batch arrival
#     来源：Classification of web robots: An empirical study based on over one billion requests
#     bytes sent from a client to the server and vice versa, time taken to serve the request, standard deviation computed on the number of bytes exchanged from clients to servers and vice versa, variation of time taken, variation of request frequency, Likelihood of receiving error status codes

# 提取特征：
#     1. session length:                                  统计统计request的个数
#     2. session duration:                                session的持续时间
#     3. Mean time per page:                              session duration / session length
#     4. Image-to-page ratio:                             统计content/type为image类型的response / session length
#     5. Volume of Data Transforred to web client:        所有response的字节数的和
#     6. Percentage of Pages with Unassigned Referrers:   没有referrer的请求
#     7. percentage of 4xx:                               4xx status code的占比
#     8. rebots.txt:                                      是否请求rebots.txt
#     9. batch arrival:                                   表示是否存在爆发性请求，浏览器访问的时候存在爆发性请求，用请求时间标准差代替

# 1. ok
# 2. 按照时间正序排序，用最后一个response的时间减去第一个request的时间|需要利用zeek获取请求时间
# 3. 2/1
# 4. |需要利用zeek获取content type
# 5. 把所有response的字节数加起来| 需要利用zeek获取response的字节数
# 6. 统计没有referrer的请求 | 需要用zeek获取referrer
# 7. 加和4xx的response数量/1  | 需要用zeek获取statuscode
# 8. 判断第一个request是否为rebots.txt
# 9. 获取到请求时间点，计算标准差 | 需要用zeek获取request time
# 需要用zeek获取的特征：request时间、response时间、response字节数、referrer、status code、

class Session_feature_extractor:
    def __init__(self,pcap_path):
        self._wrapper_for_zeek(pcap_path)
        self.df = self._read_log()

    def _wrapper_for_zeek(self,pcap_path):
        """
        调用构造的zeek脚本实现：
        1. 提取文件到./temp/message_extract_2.log文件
        """
        zeek_path = "/opt/zeek/bin/zeek"
        zeek_get_request_response_path = "./zeek_script/extract_request_response_2.zeek"
        cmd_get_request_response = f"{zeek_path} -b -C -r {pcap_path} {zeek_get_request_response_path} LogAscii::use_json=T > /dev/null"
        os.system(cmd_get_request_response)

    def _read_log(self):
        with open("./temp/message_extract_2.log") as f:
            data = [json.loads(i) for i in f.readlines()]
        df = pd.DataFrame(data)
        return df

    def get_token_from_cookie_once(self,cookie,token):
        cookie = cookie+";"
        for ck in cookie.split(";"):
            if "=" in ck:
                name = ck.strip().split("=")[0]
                if name==token:
                    value = ck.strip().split("=")[1]
                    return value
        return ""
    def get_token(self,token):
        token = self.df['cookie'].apply(lambda x:self.get_token_from_cookie_once(x,token=token))
        return token
    
    def _get_feature_session_length(self,sub_df):
        print("_get_feature_session_length")
        return sub_df.shape[0]
    def _get_feature_session_duration(self,sub_df):
        print("_get_feature_session_duration")
        sub_df.sort_values(by="request_time",ascending=True,axis="index") # 这里不要加inplace=True，不然会报错，不要利用inplace=True改变将要被apply的df
        duration = sub_df['response_time'].max()-sub_df['request_time'].min()
        # duration = sub_df.iloc[-1]['response_time']-sub_df.iloc[0]['request_time']
        return duration
    def _get_feature_mean_time_per_page(self,sub_df):
        pass  # 前两个函数相除

    def _get_feature_image2page_ratio(self,sub_df):
        print("_get_feature_image2page_ratio")
        image_flag = sub_df['content_type'].apply(lambda x:1 if "image/" in x else 0)
        ratio = image_flag.sum()/sub_df.shape[0]
        return ratio
    def _get_feature_data_volume_trans2client(self,sub_df):
        print("_get_feature_data_volume_trans2client")
        data_volumn = sub_df['response_bytes'].sum()
        return data_volumn
    def _get_feature_abnormal_referrer_ratio(self,sub_df):
        print("_get_feature_unreferrer_ratio")
        unreferrer_num = sub_df[~sub_df['referrer'].str.match("https?://[a-zA-Z0-9\.\?/%-_]*")].shape[0]
        ratio = unreferrer_num/sub_df.shape[0]
        return ratio
    def _get_feature_4xx_ratio(self,sub_df):
        print("_get_feature_4xx_ratio")
        four_xx_num = sub_df[(sub_df["status_code"]<500)&(sub_df["status_code"]>=400)].shape[0]
        ratio = four_xx_num/sub_df.shape[0]
        return ratio
    def _get_feature_3xx_ratio(self,sub_df):
        print("_get_feature_3xx_ratio")
        three_xx_num = sub_df[(sub_df["status_code"]<400) & (sub_df["status_code"]>=300) ].shape[0]
        ratio = three_xx_num/sub_df.shape[0]
        return ratio        
    def _get_feature_2xx_ratio(self,sub_df):
        print("_get_feature_2xx_ratio")
        two_xx_num = sub_df[(sub_df["status_code"]<300) & (sub_df["status_code"]>=200) ].shape[0]
        ratio = two_xx_num/sub_df.shape[0]
        return ratio    
    def _get_feature_text2page_ratio(self,sub_df):
        print("_get_feature_text2page_ratio")
        text_flag = sub_df['content_type'].apply(lambda x:1 if "text/" in x else 0)
        ratio = text_flag.sum()/sub_df.shape[0]
        return ratio
    def _get_feature_robots_accessed(self,sub_df):
        print("_get_feature_robots_accessed")
        robots_txt_num = sub_df[sub_df['uri'].str.contains("robots.txt")].shape[0]
        if robots_txt_num>0:
            flag = 1
        else:
            flag = 0
        return flag
    def _get_feature_batch_arrival_std(self,sub_df):
        # print(sub_df.dtypes)
        request_interval = sub_df['request_time'].diff().std()
        return request_interval
    def _check_useragent(sllf,useragent):
        browsers = ['Chrome',"Gecko","Trident","Safari","Micro","WinHttpClient","SimpleHttpFetch","compatible"]
        attackers = ["Nikto","HTTrack"]
        flag = False

        for i in browsers:
            if i in useragent:
                flag = True
        for i in attackers:
            if i in useragent:
                flag = False
        # if flag==False:
        #     print(useragent)
        return flag
    def _get_feature_abnormal_useragent_ratio(self,sub_df):
        # sub_df["user_agent"].apply(lambda useragent:self._check_useragent(useragent))
        normal_useragent_num = sub_df[
                                    ~sub_df["user_agent"].apply(lambda useragent:
                                                                self._check_useragent(useragent)
                                                                )
                                                                ].shape[0]
        ratio = normal_useragent_num/sub_df.shape[0]
        return ratio
    def get_all_features(self,sub_df):
        print("--")
        print(sub_df)
        print("columns")
        print(sub_df.columns)
        # print(sub_df['token'])
        # token = sub_df.iloc[0]['token']
        feature_functions = [i for i in dir(self) if i.startswith("_get_feature")]
        line = dict()
        for feature_function in feature_functions:
            name = feature_function.replace("_get_feature_", "")
            value = [getattr(self, feature_function)(sub_df)]
            line[name] = value
        # line["token"] = [token]
        line["mean_time_per_page"] = line["session_duration"][0]/line["session_length"][0]
        return_df = pd.DataFrame(data=line)
        return return_df
        

    def preprocess(self,token):
        """
        对数据进行预处理
        """
        self.df['token'] = self.get_token(token=token)
        self.df = self.df[(self.df["request_time"]!="")&(self.df["response_time"]!="")&(self.df["request_bytes"]!="")&(self.df["response_bytes"]!="")&(self.df["status_code"]!="")]
        self.df = self.df.astype({"request_time":float,"response_time":float,"request_bytes":int,"response_bytes":int,"status_code":int})
        self.df.sort_values(by="request_time",ascending=True,axis="index",inplace=True)
        self.df['content_type'].apply(lambda x:"text/" if x=="" else x)


    def run(self,token="PHPSESSID"):
        self.preprocess(token)
        session_features = self.df.groupby("token").progress_apply(lambda sub_df:self.get_all_features(sub_df))
        session_features =session_features.reset_index()
        session_features.to_csv("./output/session_feature/data.csv")
        print(session_features)





if __name__== "__main__":
    # se = Session_feature_extractor("./pcaps/test_20211031_v6.pcap")
    se = Session_feature_extractor("./pcaps/httrack.pcap")
    # H:\BaiduNetdiskDownload\jingdong.pcap
    
    se.run()
    # merge_result()