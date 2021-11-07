'''
调用zeek脚本分析

'''
import os

def run_zeek(filename):
    """
    调用构造的zeek脚本实现：
    1. 提取request与response到./temp/message_extract.log 
    2. 提取文件到./extract_files
    """
    zeek_path = "/opt/zeek/bin/zeek"
    zeek_associate_http_tls_path = "./zeek_script/associate_http_tls.zeek"
    pcap_path = os.path.join("./pcaps",filename)
    cmd_associate_http_tls = f"{zeek_path} -b -C -r {pcap_path} {zeek_associate_http_tls_path} LogAscii::use_json=T > /dev/null"
    os.system(cmd_associate_http_tls)


    # 删除日志文件
    logfile = ['conn.log', 'http.log','dns.log','dec_rpc.log', 'ftp.log', 'irc.log', 'packet_filter.log', 'tunnel.log',  'weird.log', 'ssh.log', 'smb_mapping.log', 'weired.log', 'ntlm.log', 'kerberos.log', 'mysql.log', 'radius.log', 'dpd.log', 'sbm_files.log',  'rdp.log', 'syslog.log', 'smtp.log', 'sip.log','ssl.log', 'x509.log']
    for file in os.listdir():
        if file in logfile and os.path.exists(file):
            os.remove(file)
    