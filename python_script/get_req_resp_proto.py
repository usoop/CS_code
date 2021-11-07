import nfstream
from python_script.zeek_get_message_wrapper import run_zeek
from python_script.nfstream_wrapper import run_nfstream
import json
import pandas as pd
import os
from tqdm import tqdm 
tqdm.pandas()
import shutil



def _save_sub_df(df):
    """
    用于处理按照六元组groupby之后的数据
    包括创建对应的文件夹，储存对应的数据，储存对应的文件
    """
    line = df.iloc[0]["six_tuple"]
    # 文件夹不允许出现这些符号
    banned_chars = '* " / \ : |'.split()
    dir_name = "".join(i for i in line if i not in banned_chars)
    # print(f"mkdir -p ./output/'{dir_name}'")
    os.system(f"mkdir -p ./output/request_response/'{dir_name}'")
    extracted_files = set(os.listdir("./extract_files"))
    orig_fuids = df['orig_fuids'].apply(lambda x:[i for i in x.split("--") ])
    resp_fuids = df['resp_fuids'].apply(lambda x:[i for i in x.split("--") ])
    fuids = ["HTTP-"+i for i in orig_fuids.explode()+resp_fuids.explode()]

    # 这种遍历匹配文件名的时间复杂度太高了
    # for fuid in fuids:
    #     for file in extracted_files:
    #         if fuid in file:
    #             shutil.copy(
    #                 os.path.join("./extract_files",file),
    #                 os.path.join(f"./output/{dir_name}",file)
    #                 )

    # 把文件名拆开求交集
    data_for_find = {}
    for file in extracted_files:
        name = file.split(".")[0]
        suffix = file.split(".")[1]
        if name in data_for_find:
            data_for_find[name].append(suffix)
        else:
            data_for_find[name] = [suffix,]

    session_files = set(fuids)&set(data_for_find)
    for session_file in session_files:
        name = session_file
        suffixs = data_for_find[name]
        for suffix in suffixs:
            filename = name+"."+suffix
            shutil.copy(
                os.path.join("./extract_files",filename),
                os.path.join(f"./output/request_response/{dir_name}",filename)
                )

    file_path = os.path.join("./output/request_response",dir_name,"data.csv")
    df['request'] = df['request'].apply(lambda x:json.dumps(x))
    df['response'] = df['response'].apply(lambda x:json.dumps(x))
    # df.to_json(file_path,orient="records")
    # print(df)
    # df.to_csv("~/a.csv",index=False)
    # print("Over")
    df.to_csv(file_path,index=False)


def _filter_df(df:pd.DataFrame,filter:dict,return_columns:list):
    """
    按照filter这个字典筛选df，取第一行
    返回return_columns对应的值
    """
    for k,v in filter.items():
        df = df[df[k]==v]
    
    line = df.iloc[0][return_columns]
    return line
def _add_data(sr1,sr2,columns):
    for column in columns:
        sr1[column] = sr2[column]
    return sr1
def merge_result():
    """
    根据["src_ip","dst_ip","src_port","dst_port","protocol"]合并zeek与nfstream的分析结果
    并将会话储存到对应六元组中
    """
    with open("./temp/message_extract.log",encoding='utf-8') as f:
        data = [json.loads(i) for i in f.readlines()]
    zeek_df = pd.DataFrame(data).astype(str)
    zeek_df.rename(columns={"orig_h":"src_ip","resp_h":"dst_ip","orig_p":"src_port","resp_p":"dst_port","proto":"protocol"},inplace=True)
    
    # zeek与nfstream的协议分别用字符与数字表示，统一成数字
    protocol_number = pd.read_csv("support_file/协议号.txt",sep='\t')
    protocol_map = dict(zip(protocol_number['协议'],[str(p) for p in protocol_number['协议号']]))
    zeek_df['protocol'] = zeek_df['protocol'].map(protocol_map)
    nfstream_df = pd.read_csv("./temp/nsf_feature.csv").astype(str)
    on=["src_ip","dst_ip","src_port","dst_port","protocol"]
    

    print("zeek_df.shape",zeek_df.shape)
    added_columns = ['application_name','application_category_name']
    df = zeek_df.apply(lambda x:_add_data(x, _filter_df(nfstream_df,
                                                        dict(zip(on,x[on])),
                                                        added_columns
                                                        )
                                        ,added_columns)
                        ,axis=1)

    print("df.shape",df.shape)
    print(df.shape)
    # groupby 之后提取特征
    df.groupby("six_tuple").progress_apply(lambda x:_save_sub_df(x))


def main(filename):
    """
    将zeek与nfstream的分析结果结合起来，然后利用六元组将不同的session保存下来
    """
    file_path = os.path.abspath(os.path.join("./pcaps",filename))
    print("begin run_zeek")
    run_zeek(file_path)
    print("begin run_nfstream")
    run_nfstream(file_path)
    print("begin merge_result")
    merge_result()

if __name__== "__main__":
    main("nikto_scan.pcap")
    # merge_result()