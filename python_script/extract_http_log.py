import os
import pandas as pd
import json
import shutil

def extract_log(pcap_path):
    """
    利用zeek提取pcap文件的各种log
    """
    zeek_path_1 = "/usr/local/zeek/bin/zeek"
    zeek_path_2 = "/opt/zeek/bin/zeek"
    # 查看zeek的两个默认安装路径
    if os.path.exists(zeek_path_1):
        zeek_path = zeek_path_1
    elif os.path.exists(zeek_path_2):
        zeek_path = zeek_path_2
    else:
        raise Exception("找不到zeek路径（默认位于：/usr/local/zeek/bin/zeek 与 /opt/zeek/bin/zeek）")
    # 将zeek产生的log文件储存在temp_log_files文件夹
    pcap_abs_path = os.path.abspath(pcap_path)
    command = fr"cd ./temp_log_files; {zeek_path} -C -r {pcap_abs_path} LogAscii::use_json=T > /dev/null;cd ..;"
    os.system(command)
    

def _log2df(file_path:str)->pd.DataFrame:
    """
    读取file_path的文件，转成pandas的dataframe类型
    """
    with open(file_path,'r') as f:
        data = [json.loads(item) for item in f.readlines()]
    df = pd.DataFrame(data)
    return df
        # pass
        # print(f.read()




def _save_sub_df(sub_df:pd.DataFrame)->str:
    """
    利用会话标识储存对应的会话数据，包括提取出的文件
    """
    banned_chars = '* " / \ : |'.split()
    # 定义用于标识会话的列名
    lable_columns = ["client_ip","server_ip","server_port","ip_header_protocol","client_ip","user_agent","server_host"]
    line = sub_df.iloc[0][lable_columns]
    dir_name = "".join(i for i in 
                        "-".join([str(i) for i in line]) 
                        if i not in banned_chars)
    print(f"mkdir -p ./output/'{dir_name}'")
    os.system(f"mkdir -p ./output/'{dir_name}'")

    # 通过fuid提取文件到对应目录
    extracted_files = set(os.listdir("./extract_files"))
    fuids = sub_df['fuid'].to_list()
    for fuid in fuids:
        for file in extracted_files:
            if fuid in file:
                shutil.copy(
                    os.path.join("./extract_files",file),
                    os.path.join(f"./output/{dir_name}",file)
                    )
    

    # 储存提取出的会话到对应文件夹下的data.csv
    file_path = os.path.join("./output/http_log",dir_name,"data.csv")
    sub_df.to_csv(file_path,index=False)


def integrate_log():
    """
    将conn.log http.log file.log根据uid融合到一起
    """
    log_files_path = "./temp_log_files"
    conn_log_path = os.path.join(log_files_path,"conn.log")
    http_log_path = os.path.join(log_files_path,"http.log")
    files_log_path = os.path.join(log_files_path,"files.log")
    _conn_df = _log2df(conn_log_path)
    print(_conn_df)

    # conn_df只保留uid与proto列
    print(_conn_df.columns)
    conn_df = _conn_df[['uid',"proto"]]
    http_df = _log2df(http_log_path)
    _files_df = _log2df(files_log_path)

    # 把files_df中的conn_uids重命名为uid，然后将uid列的列表展开，利于与http.log合并
    _files_df = _files_df \
                    .rename(columns={"conn_uids":"uid"})\
                    .dropna(subset=["uid"]) \
                    .explode("uid")
    # 留下uid与fuid两列，uid用于与其他log合并，fuid用于标识文件
    files_df = _files_df[["uid","fuid"]]

    df = pd.merge(http_df,conn_df,on="uid",how='left')
    df = pd.merge(df,files_df,on="uid",how='left')

    # 定义需要重命名的列名并重命名列名
    column_name_mapping = {"id.orig_h":"client_ip","id.resp_h":"server_ip","id.resp_p":"server_port","proto":"ip_header_protocol","host":"server_host"}
    df.rename(columns=column_name_mapping,inplace=True)
    
    # 定义groupby的列名并进行groupby 
    groupby_key = ["client_ip","server_ip","server_port","ip_header_protocol","client_ip","user_agent","server_host"]
    # 利用_save_sub_df处理每个通过groupby得到的dataframe
    df.groupby(groupby_key).apply(lambda x:_save_sub_df(x))

def extract_files(pcap_path):
    """
    利用zeek脚本提取文件
    """
    command = f"/opt/zeek/bin/zeek -C -r {pcap_path} ./zeek_script/file_extraction.zeek"
    os.system(command)

def run(pcap_file_name):
    """
    提取文件，提取log，然后根据log获取会话标识并创建对应文件夹，最后将提取的文件与会话信息保存到对应文件夹
    """
    pcap_path = os.path.join("./pcaps",pcap_file_name)
    extract_files(pcap_path)
    extract_log(pcap_path)
    integrate_log()


if __name__ == "__main__":
    # 使用：把pcap放入pcaps文件夹中，运行然后运行run(文件名)
    run("selenium.pcap")