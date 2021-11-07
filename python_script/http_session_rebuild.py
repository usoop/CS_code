import json
import pandas as pd
import os
from tqdm import tqdm 
tqdm.pandas()
import shutil
from pyecharts import options as opts
from pyecharts.charts import Graph

class HTTP_session_rebuilder:
    def __init__(self,filename):
        pcap_path = os.path.join("./pcaps",filename)
        self._wrapper_for_zeek(pcap_path)
        pass

    def _wrapper_for_zeek(self,pcap_path):
        """
        调用构造的zeek脚本实现：
        1. 提取文件到./temp/message_extract_2.log文件
        """
        zeek_path = "/opt/zeek/bin/zeek"
        zeek_get_request_response_path = "./zeek_script/extract_request_response_2.zeek"
        cmd_get_request_response = f"{zeek_path} -b -C -r {pcap_path} {zeek_get_request_response_path} LogAscii::use_json=T > /dev/null"
        print("command",cmd_get_request_response)
        s = os.system(cmd_get_request_response)
        print(s)

    def read_http_log(self,):
        with open("./temp/message_extract_2.log") as f:
            data = [json.loads(i) for i in f.readlines()]
        df = pd.DataFrame(data)
        return df


    def _get_token_from_cookie_once(self,cookie,token):
        cookie = cookie+";"
        for ck in cookie.split(";"):
            if "=" in ck:
                name = ck.strip().split("=")[0]
                if name==token:
                    value = ck.strip().split("=")[1]
                    return value
        return ""

    def draw_session(self,sub_df,token):
        """
        session 
        """
        df = sub_df.sort_values("request_time")
        token = self._get_token_from_cookie_once(sub_df.iloc[0]['cookie'],token)
        df['response'] = df['response'].apply(lambda x:json.dumps(x))
        df['request'] = df['request'].apply(lambda x:json.dumps(x))        
        df.to_csv("./output/http_session_rebuild/"+token+".csv")
        # 构建 画图需要的数据

        df.reset_index(inplace=True)
        nodes_ = set()
        links_ = set()
        browsered_html = []
        for _, row in df.iterrows():                            # 遍历每一个http request与response对
            if row.get("content_type").startswith("text/html") and row.get("status_code")=="200":
                this_uri = row.get("uri")
                this_uri_without_prefix = this_uri.replace("/mutillidae/","",1)  # 获取去掉"\mutillidae\"的路径
                nodes_.add(this_uri_without_prefix)
                href = f"href=\"{this_uri_without_prefix}\">"
                for html in browsered_html[::-1]:                   # 倒序遍历之前的html页面
                    if this_uri_without_prefix in html.get("response"):            # 如果当前uri在之前的html页面中，就添加一条边
                        links_.add((html.get("uri").replace("/mutillidae/","",1),this_uri_without_prefix))
                        break                                       # 找到最相邻的HTML后，就退出
            # if row.get("content_type").startswith("text/html") and row.get("status_code")=="200": # 如果类型是html且状态为200，就添加到已访问的列表 browsered_html中，让其他的request response对使用
                browsered_html.append(row)
        # 画图
        # nodes = [{"name":node,"LabelOpts":{"is_show":False}} for node in nodes_]
        nodes = [opts.GraphNode(name=node,label_opts=opts.LabelOpts(is_show=False)) for node in nodes_]
        links = [{"source":i[0],"target":i[1]} for i in links_]
        c = (
            Graph(init_opts=opts.InitOpts(width="1920px",height="1080px"))
            .add("", 
                nodes, 
                links, 
                repulsion=8000,
                edge_symbol= ['circle', 'arrow']
                    )
            .set_global_opts(title_opts=opts.TitleOpts(title="访问DAG"))
            .render("./output/http_session_rebuild/"+token+"_access_dag.html")
        )
                


    def run(self,token="jwt"):
        df = self.read_http_log()
        df['token'] = df['cookie'].apply(lambda x: self._get_token_from_cookie_once(x, token))
        # df = df[df['token']!=""]
        df.groupby("token").apply(lambda sub_df:self.draw_session(sub_df,token))

if __name__ == "__main__":
    session_rebuilder = HTTP_session_rebuilder(filename="active_scan.pcap")
    session_rebuilder.run("jwt")