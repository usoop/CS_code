import os
from nfstream import NFStreamer

def run_nfstream(filename):
    """
    利用NFStreamer获取应用层协议, 将文件保存到./temp/nsf_feature.csv
    """
    pcap_path = os.path.join("./pcaps",filename)
    df = NFStreamer(source=pcap_path).to_pandas()[["src_ip",        #
                                                    "src_port",
                                                    "dst_ip",       #
                                                    "dst_port",     #
                                                    "protocol",     #
                                                    "application_name",
                                                    "application_category_name",
                                                    "user_agent",   #
                                                    "requested_server_name"
                                                    ]]
    df.to_csv("./temp/nsf_feature.csv",index=False)



if __name__ == "__main__":
    run_nfstream("selenium.pcap")