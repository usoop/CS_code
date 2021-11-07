'''
调用zeek脚本分析

'''
import os

def run_zeek(pcap_path):
    """
    调用构造的zeek脚本实现：
    1. 提取request与response到./temp/message_extract.log 
    2. 提取文件到./extract_files
    """
    zeek_path = "/opt/zeek/bin/zeek"
    zeek_extract_file_path = "./zeek_script/file_extraction.zeek"
    zeek_get_message_path = "./zeek_script/get_message.zeek"
    cmd_get_message = f"{zeek_path} -b -C -r {pcap_path} {zeek_get_message_path} LogAscii::use_json=T > /dev/null"
    cmd_extract_file = f"{zeek_path} -C -r {pcap_path} {zeek_extract_file_path}"
    os.system(cmd_get_message)
    os.system(cmd_extract_file)


    # 删除日志文件
    logfile = ['conn.log', 'http.log','dns.log','dec_rpc.log', 'ftp.log', 'irc.log', 'packet_filter.log', 'tunnel.log',  'weird.log', 'ssh.log', 'smb_mapping.log', 'weired.log', 'ntlm.log', 'kerberos.log', 'mysql.log', 'radius.log', 'dpd.log', 'sbm_files.log',  'rdp.log', 'syslog.log', 'smtp.log', 'sip.log','ssl.log', 'x509.log']
    for file in os.listdir():
        if file in logfile and os.path.exists(file):
            os.remove(file)
    