r"""
 # @Author: your name
 # @Date: 2021-10-23 11:10:14
 # @LastEditTime: 2021-10-25 22:54:18
 # @LastEditors: Please set LastEditors
 # @Description: In User Settings Edit
 # @FilePath: \trffic_analysis_7-8\problem7.py
 """
import dpkt
import datetime
import socket
from dpkt.compat import compat_ord
import pandas as pd
import os


"""
提取：Timestmap域，Client IP域，Client Port域，Server IP域，Server Port域，IP报头Protocol域
"""

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)



def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def extract_message(pcap,df_path):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    items = []
    for timestamp, buf in pcap:
        line = dict()
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now grab the data within the Ethernet frame (the IP packet)
        ip = eth.data

        # Check for TCP in the transport layer
        # if isinstance(ip.data, dpkt.tcp.TCP):

            # Set the TCP data
        ip_data = ip.data

        # Now see if we can parse the contents as a HTTP request
        try:
            request = dpkt.http.Request(ip_data.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        # print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
        # print('IP: %s -> %s ' %(inet_to_str(ip.src), inet_to_str(ip.dst)))
        # print("client port->%d, server port -> %d"%(ip_data.sport,ip_data.dport))
        # print("ip header protocol %d"%(ip.p))
        # print('HTTP request: %s\n' % repr(request))


        item = {}
        item['timestamp'] = str(datetime.datetime.utcfromtimestamp(timestamp))
        item['client_ip'] = inet_to_str(ip.src)
        item['server_ip'] = inet_to_str(ip.dst)
        item['client_port'] = ip_data.sport
        item['server_port'] = ip_data.dport
        item['ip_header_protocol'] = ip.p
        item['method'] = request.method
        item['uri'] = request.uri
        item['host'] = request.headers.get("host")
        referer = request.headers.get("referer")
        item['referer'] = referer if referer else "-" 
        item['user-agent'] = request.headers.get("user-agent")
        item['cookie'] = request.headers.get("cookie")
        items.append(item)



        # Check for Header spanning acrossed TCP segments
        if not ip_data.data.endswith(b'\r\n'):
            print('\nHEADER TRUNCATED! Reassemble TCP segments!\n')
    df = pd.DataFrame(items)
    df.to_csv(df_path,index=False)

        
def run_extract(filename:str):
    """Open up a test pcap file and print out the packets"""
    csv_path = os.path.join("./output/http_request",filename+".csv")
    pcap_path = os.path.join("./pcaps",filename)
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        extract_message(pcap,csv_path)





if __name__ == "__main__":
    run_extract(r"httrack.pcap")
