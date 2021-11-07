from python_script import extract_features
from python_script import extract_request
from python_script import get_req_resp_proto
from python_script import zeek_associate_http_tls_wrapper

def extract_http_tls_features(filename,is_http:bool=False):
    """
    加密与明文流量特征提取

    filename：要分析的pcap文件名，如 selenium.pcap
    is_http:是否分析http特征
    """
    extractor = extract_features.Extractor()
    extractor.extract_traffic_integration(filename,is_http=is_http)

def extract_http_request(filename):
    """
    提取http 请求的特征
    """
    extract_request.run_extract(filename)


def extract_request_response(filename):
    """
    提取filename文件的request与response以及应用层协议
    """
    get_req_resp_proto.main(filename)

def associate_http_tls(filename):
    """
    关联ssl与http五元组
    """
    zeek_associate_http_tls_wrapper.run_zeek(filename)


if __name__ == "__main__":
    http_file = "httrack.pcap"
    https_file = "selenium.pcap"
    filename = ""
    is_http = False

    # 进行http或tls特征分析
    # extract_http_tls_features(https_file,is_http=True)
    
    # extract_http_tls_features(http_file,is_http=False)
    # 进行http request分析
    # extract_http_request(http_file)

    # 提取http request、response以及对应的application protocol
    # extract_request_response(http_file)

    # 关联http与tls五元组
    # associate_http_tls("test_20211031_v6.pcap")