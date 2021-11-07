import os
import sys
import pandas as pd
# import matplotlib.pyplot as plt
# import cicflowmeter
import json
from functools import reduce
from datetime import datetime
from nfstream import NFStreamer

# plt.rcParams['axes.unicode_minus'] = False    # matplotlib显示负号




class Extractor:
    def __init__(self):
        """
        :param path:绝对路径
        """
        pass
        # self.path = path
        self.output_path = "./output/traffic_features"

    def file_or_dir(self):
        """
        判断path是文件夹还是路径
        :return:
        """
        if os.path.isdir(self.path):
            path_type = "dir"
        else:
            path_type = "file"
        return path_type


    def run_traffic_extract(self):
        """
        提取文件的特征保存到output下 pcap文件与对应特征csv文件的文件名关系：xxx.pcap -->xxx.pcap.csv
        :return:
        """
        abs_filepaths = []
        if self.file_or_dir() == "dir":
            files = os.listdir(self.path)
            for file in files:
                if os.path.split(file)[-1].endswith('.pcap'):
                    abs_filenpath = os.path.join(self.path,file)
                    abs_filepaths.append(abs_filenpath)
        elif self.file_or_dir() == "file":
            abs_filepaths.append(self.path)
        else:
            raise Exception("文件类型错误")
        for abs_filepath in abs_filepaths:
            self.extract_traffic_integration(abs_filepath)

    def exact_message(self,src_ip,dst_ip):
        """
        提取特征点
        1. 利用tshark转换通过 src ip 和 dst ip （双向流量）过滤数据并提取 tcp len，时间戳，储存到csv文件中
        2. 以最早的一条数据为上行，方向相反则为下行，添加方向列，上行为1，下行为-1
        3. 在df中添加一列 tcp.len * 方向

        :return:
        """
        filename =  os.path.split(self.path)[-1]
        temp_file_path = os.path.join(self.output_path,
                                      "temp_"+filename
                                      )+".csv"
        filter = f"\"(ip.src == {src_ip} and ip.dst == {dst_ip}) or (ip.dst == {src_ip} and ip.src == {dst_ip})\""
        fields = "-e ip.src -e ip.dst -e ip.len -e tcp.len -e frame.number -e frame.time_relative"
        command = fr"tshark -r {self.path} -Y {filter} -T fields {fields} -E header=y -E separator=, > {temp_file_path}"
        print("command",command)
        os.system(command)
        df = pd.read_csv(temp_file_path)
        if df.shape[0]>0:
            src_ip = df.loc[0,'ip.src']
            # 判断方向
            df['direct'] = df['ip.src'].apply(lambda x:1 if x==src_ip else -1)
            # 计算特征值
            df['size'] = df['direct']*df['ip.len']
            fig_filename = os.path.join(self.output_path,filename+"_"+str(src_ip)+"_"+str(dst_ip)+".png")
            x = list(range(1,df['size'].shape[0]+1))
            y = df['size'].to_list()
            # 将x，y输入的draw_bar生成图片
            self.draw_bar(x,y, fig_filename)

        os.remove(temp_file_path)


    def run_message_exactor(self):

        if self.file_or_dir() == "file" and os.path.splitext(self.path)=='.pcap':
            self.exact_message()


    def draw_bar(self,x,y,filename):
        """
        利用matplotlib绘图
        :param x: x轴坐标
        :param y: y轴坐标
        :param filepath: 保存到output文件夹
        :return:
        """

        plt.figure(figsize=(40,10),dpi=300)
        ax = plt.gca()
        plt.bar(x, y,width=1,color=['g' if i > 0 else 'r'  for i in y])
        # 调节字体大小
        plt.xlabel("sequence number",fontsize=20)
        plt.ylabel("length",fontsize=20)
        plt.xticks(fontsize=20)
        plt.yticks(fontsize=20)
        plt.savefig(filename)


    def extract_one_traffic_by_cicflowmeter(self,filename):
        """
        利用cicflowmeter提取一个文件的特征
        filepath:文件绝对路径
        :return:
        提取filepath的pcap文件的特征保存到output/filename+".csv"文件夹下

        """
        output_path = os.path.join(self.output_path,
                                   "temp_cicflow_"+filename+".csv"
                                   )
        pcap_path = os.path.join("./pcaps",filename)
        command = fr"cicflowmeter -f {pcap_path} -c {output_path} > /dev/null"
        
        print("cicflowmeter command:",command)
        os.system(command)
        # 原来保存的csv文件存在空行 通过重新读取去除空行
        df = pd.read_csv(output_path)
        
        df['timestamp'] = df['timestamp'].apply(lambda x:int(
            datetime.timestamp(
                datetime.strptime(x,"%Y-%m-%d %H:%M:%S")
                )
            )
        )
        df.to_csv(output_path,index=False)
        return output_path

    def extract_by_nfstream(self,filename):
        output_path = os.path.join("./output","temp_nfstream_"+filename+".csv")
        columns_prereserve = ["src_ip","src_port","dst_ip","dst_port","protocol",
            "ip_version","bidirectional_first_seen_ms","bidirectional_last_seen_ms","src2dst_first_seen_ms",
            "src2dst_last_seen_ms","src2dst_duration_ms","dst2src_first_seen_ms","dst2src_last_seen_ms",
            "dst2src_duration_ms","application_name", "application_category_name",]
        filepath = os.path.join("./pcaps",filename)
        df = NFStreamer(source=filepath,statistical_analysis=True).to_pandas()[columns_prereserve]
        # 计算时间戳
        # df["timestamp"] = df["bidirectional_first_seen_ms"].apply(lambda x:int(x/1000))
        df.to_csv(output_path,index=False)
        # print("nfstream over")
        return output_path


    def extract_l7_prototol_by_ndpi(self,abs_filepath):

        """
        被nfstream代替

        利用ndpi提取流量特征

        filepath:文件绝对路径

        abs_path:
        """
        raise Exception("该方法已不再使用，被extract_by_nfstream替代")
        output_path = os.path.join(self.output_path,
                                   "temp_ndpi"+os.path.split(abs_filepath)[-1]+".csv"
                                   )
        
        command = command = fr"./nDPI/example/ndpiReader -i {abs_filepath}  -C {output_path} > /dev/null"
        print("ndpi command:",command)
        os.system(command)
        return output_path
    def _zeek_merge(self,x:pd.DataFrame,y:pd.DataFrame):
            """
            merge zeek得到的结果 如果双方都有uid 按照uidmerge 否则按照列的交集merge
            """
            if "uid" in x.columns and "uid" in y.columns:
                # 以uid为键进行合并，去除y里面与x重复的键 防止因为键同名导致出现_x与_y后缀
                on = ["uid"]
                shared_column = list(set(y.columns.tolist())&set(x.columns.tolist()))
                shared_column.remove("uid")
                y.drop(columns=shared_column,inplace=True)
                x = pd.merge(x,y,on=on,how='left')
            elif "id" in y.columns:
                # print("id read==========")
                # 当列中有id时 说明已经读取到了x509.log对应的dataframe
                # ssl.log中cert_chain_fuids和client_cert_chain_fuids的值都为列表，且列表中每个元素都对应x509.log中的一条数据所以需要把ssl展开然后，与x509.log合并
                y.drop(columns=['ts'],inplace=True)
                server_x509 = y.copy(deep=True)
                client_x509 = y.copy(deep=True)
                server_x509['cert_chain_fuids'] = server_x509['id']
                client_x509['client_cert_chain_fuids'] = client_x509['id']
                server_x509.drop(columns=['id'],inplace=True)
                client_x509.drop(columns=['id'],inplace=True)
                for column in server_x509.columns:
                    if column.startswith("san") or column.startswith("basic_constraints") or column.startswith("certificate"):
                        server_x509["server_"+column] = y[column]
                        server_x509.drop(columns=[column],inplace=True)
                for column in client_x509.columns:
                    if column.startswith("san") or column.startswith("basic_constraints") or column.startswith("certificate"):
                        client_x509["client_"+column] = y[column]
                        client_x509.drop(columns=[column],inplace=True)
                # x.to_csv("before_ssl_merge.csv")
                x = pd.merge(x,server_x509,on=["cert_chain_fuids"],how="left")
                x = pd.merge(x,client_x509,on=["client_cert_chain_fuids"],how="left")
                # print("x.columns",x.columns)
                # x.to_csv("after_ssl_merge.csv")
            else:
                x = pd.merge(x,y,how='left')
            return x

    def extract_traffic_by_zeek(self,filename,is_http:bool=False):
        """
        利用zeek提取流量特征

        """
        # zeek输出路径为当前路径下的conn.log
        # output_path = os.path.join(self.output_path,
        #                            "temp_zeek"+os.path.split(abs_filepath)[-1]+".csv"
        #                            )
        output_path = os.path.join("./output","temp_zeek_"+filename+".csv")
        # 直接从默认安装路径调用                           
        zeek_path_1 = "/usr/local/zeek/bin/zeek"
        zeek_path_2 = "/opt/zeek/bin/zeek"
        # 查看zeek的两个默认安装路径
        if os.path.exists(zeek_path_1):
            zeek_path = zeek_path_1
        elif os.path.exists(zeek_path_2):
            zeek_path = zeek_path_2
        else:
            raise Exception("找不到zeek路径（默认位于：/usr/local/zeek/bin/zeek 与 /opt/zeek/bin/zeek）")
        file_path = os.path.join("./pcaps",filename)
        command = command = fr"{zeek_path} -C -r {file_path} LogAscii::use_json=T > /dev/null"
        print("zeek command:",command)
        os.system(command)
        # 读取json文件 合并成dataframe # x509.log 一定要在最后一个 因为需要与之前的fuid合并
        logfiles = ['conn.log', 'http.log','dns.log','dec_rpc.log', 'ftp.log', 'irc.log', 'packet_filter.log', 'tunnel.log',  'weird.log', 'ssh.log', 'smb_mapping.log', 'weired.log', 'ntlm.log', 'kerberos.log', 'mysql.log', 'radius.log', 'dpd.log', 'sbm_files.log',  'rdp.log', 'syslog.log', 'smtp.log', 'sip.log','ssl.log', 'x509.log']

        dfs = []
        if not is_http:
            logfiles.remove("http.log")
        for logfile in logfiles:
            if not os.path.exists(logfile):
                continue
            data = []
            with open(logfile) as f:
                while True:
                    line = f.readline()
                    if line:
                        data.append(json.loads(line))
                    else:
                        break
            _df = pd.DataFrame(data)
            # cert_chain_fuids中是列表，为其中每个元素都生成一行 用于与x509.log文件合并
            # print(_df.dtypes)
            if logfile.endswith("ssl.log"):
                # ssl.log中cert_chain_fuids和client_cert_chain_fuids的值都为列表，且列表中每个元素都对应x509.log中的一条数据所以需要把ssl展开然后，与x509.log合并
                _df = _df.explode(["cert_chain_fuids",])
                _df.to_csv('test_ssl.csv')
            
            _df = _df.astype(str)

            # 处理重复字段
            if logfile.endswith("http.log"):
                _df.rename(columns={"username":"http_username","password":"http_password"},inplace=True) 
            if logfile.endswith("radius.log"):
                _df.rename(columns={"username":"radius_username"},inplace=True)                   
            if logfile.endswith("ntlm.log"):
                _df.rename(columns={"username":"ntlm_username","success":"ntlm_success"},inplace=True)                      
            if logfile.endswith("weird.log"):
                _df.rename(columns={"name":"weird_name"},inplace=True)
            if logfile.endswith("dns.log"):
                _df.rename(columns={"rtt":"dns_rtt"},inplace=True)
            if logfile.endswith("dce_rpc.log"):
                _df.rename(columns={"rtt":"dce_rpc_rtt"},inplace=True)
            if logfile.endswith("kerberos.log"):
                _df.rename(columns={"success":"kerberos_success"},inplace=True)      
            if logfile.endswith("mysql.log"):
                _df.rename(columns={"success":"mysql_success"},inplace=True)                                
            # print("df_len",_df.shape[0])
            # print("df columns",_df.columns)
            dfs.append(_df)
        # print("dfs",dfs)

        # 删除日志文件
        logfile = ['conn.log', 'http.log','dns.log','dec_rpc.log', 'ftp.log', 'irc.log', 'packet_filter.log', 'tunnel.log',  'weird.log', 'ssh.log', 'smb_mapping.log', 'weired.log', 'ntlm.log', 'kerberos.log', 'mysql.log', 'radius.log', 'dpd.log', 'sbm_files.log',  'rdp.log', 'syslog.log', 'smtp.log', 'sip.log','ssl.log', 'x509.log']
        for file in os.listdir():
            if file in logfile and os.path.exists(file):
                # pass
                # os.remove(file)
                pass
        # 将各个dataframe合并起来

        df = reduce(lambda x,y:self._zeek_merge(x,y),dfs)
        # print("df.columns",df.columns)

        # 统一dataframe列名
        df.rename(
            columns={"id.orig_h":"src_ip","id.orig_p":"src_port","id.resp_h":"dst_ip","id.resp_p":"dst_port","proto":"protocol"},
            inplace=True
            )
        df['timestamp'] = pd.to_numeric(df['ts']).apply(lambda x:int(x))
        # zeek 输出的协议是字符串形式 为了与cicflowmeter与nfstream保持统一 将其转换成对应协议号 
        protocol_number = pd.read_csv(os.path.join("./support_file","协议号.txt"),sep='\t')
        protocol_map = dict(zip(protocol_number['协议'],protocol_number['协议号']))
        df['protocol'] = df['protocol'].map(protocol_map)
        columns_to_drop = ["duration","orig_bytes","resp_bytes","orig_pkts","orig_ip_bytes","resp_pkts","resp_ip_bytes","filter","init","node"]
        df.drop(columns=columns_to_drop,axis=1,inplace=True)
        df.to_csv(output_path,index=False)
        return output_path

    def extract_traffic_integration(self,filename,is_http:bool=False):
        """
        把利用不同方式生成的csv文件中的特征合并到一起 合并的键为 src_ip,dst_ip,src_port,dst_port,protocol,
        filename:文件名 事先放到pcaps目录里面
        is_http：是否分析http特征
        """
        # 调用各种方法获取流量特征输出到csv文件
        cicflowmeter_csv_path = self.extract_one_traffic_by_cicflowmeter(filename)
        ndpi_csv_path = self.extract_by_nfstream(filename)
        zeek_csv_path = self.extract_traffic_by_zeek(filename,is_http=is_http)

        csv_file_paths = [
            cicflowmeter_csv_path,
            ndpi_csv_path,
            zeek_csv_path]
        # print(csv_file_paths)
        dfs = [pd.read_csv(filepath,dtype='str') for filepath in csv_file_paths]
        

        # 合并csv文件
        df = reduce(lambda x,y:pd.merge(x,y,how="outer"),dfs)
        # 删除字段中不包含5元祖的行
        df.dropna(subset=["src_ip","dst_ip","src_port","dst_port","protocol"],inplace=True)
        df = df.applymap(lambda x:pd.NA if x=='[]' else x)
        df.dropna(axis=1,how='all',inplace=True)
        # 删除已合并的临时文件
        for file_path in csv_file_paths:
            os.remove(file_path)
        output_path = os.path.join(self.output_path,
                            filename+".csv"
                            )
        df.to_csv(output_path,index=False)


        

    

if __name__ == "__main__":
    ex = Extractor()
    # 如果提取http特征，is_http为True，如果提取ssl特征 is_http为False
    ex.extract_traffic_integration("httrack.pcap",is_http=False)
