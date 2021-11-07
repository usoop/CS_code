import json
import matplotlib.pyplot as plt
import pandas as pd
import os
from datetime import datetime
class SSL_session_rebuilder:
    def __init__(self,filename):
        pcap_path = os.path.join("./pcaps",filename)
        self._wrapper_for_zeek(pcap_path)
        self.read_log_file()
        pass

    def _wrapper_for_zeek(self,pcap_path):
        """
        调用构造的zeek脚本实现：
        1. 提取文件到./temp/message_extract_2.log文件
        """
        zeek_path = "/opt/zeek/bin/zeek"
        cmd_get_request_response = f"{zeek_path} -C -r {pcap_path}  LogAscii::use_json=T > /dev/null"
        os.system(cmd_get_request_response)
    def _read_log_once(self,filename)->pd.DataFrame:
        """
        读取项目根目录下的log文件
        """
        with open(filename,) as f:
            data = [json.loads(i) for i in f.readlines()]
        df = pd.DataFrame(data)
        return df 

    def read_log_file(self):
        """
        读取生成的logfile，包括ssl.log conn.log 以及 x509.log
        """
        self.conn_df = self._read_log_once("conn.log")
        self.ssl_df = self._read_log_once("ssl.log")
        self.x509_df = self._read_log_once("x509.log")

    def draw(self,sub_df,filepath):
        """
        画图
        """
        print(sub_df.shape)
        if sub_df.shape[0]<3:
            return 
        df = sub_df
        x = [datetime.fromtimestamp(int(i)) for i in df['ts']]
        req_y = [i for i in df['orig_pkts']]
        resp_y = [-i for i in df['resp_pkts']]
        plt.plot(x,req_y)
        plt.plot(x,resp_y)
        plt.xticks(rotation=15) 
        print("to show")
        plt.savefig(filepath+".png")
        plt.close()
        # plt.save(os.path.join("./output/ssl_session_rebuild",filename+".png"))
    def _save_and_draw(self,sub_df):
        """
        保存session并且画图
        """
        sorted_df = sub_df.sort_values(by="ts")
        first_line = sub_df.iloc[0]

        filename = "{}_{}_{}.csv".format(first_line["orig_h"],first_line["resp_h"],first_line["resp_p"])
        filepath = os.path.join("./output/ssl_session_rebuild/",filename)
        # orig_h,resp_h,resp_p,orig_p,proto 即为五元组
        sorted_df.to_csv(filepath)
        self.draw(sorted_df,filepath)
        

    def generate_session(self):
        """
        生成session，保存到output/ssl_session_rebuild目录，命名方式为"三元组.csv"
        """
        conn_df = self.conn_df
        ssl_df = self.ssl_df
        ssl_uids = set(ssl_df['uid'].tolist())
        conn_uids = set(conn_df['uid'].tolist())
        t = list(conn_uids&ssl_uids)
        conn_df = conn_df[conn_df['uid'].apply(lambda x: x in t)]
        conn_df['orig_h'] = conn_df['id.orig_h']
        conn_df['resp_h'] = conn_df['id.resp_h']
        conn_df['resp_p'] = conn_df['id.resp_p']
        conn_df['orig_p'] = conn_df['id.orig_p']
        conn_df.groupby(['id.orig_h','id.resp_h','id.resp_p']).apply(lambda sub_df:self._save_and_draw(sub_df))



if __name__ == "__main__":
    ssl_session_rebuilder = SSL_session_rebuilder("doubai.pcap")
    ssl_session_rebuilder.generate_session()
