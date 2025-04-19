"""
模块功能: 规则过滤模块：根据给定的过滤条件，筛选并匹配特定的 HTTP 流量数据
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-04-2
"""

from core_processing import core_processing_request, core_processing_response,based_on_tshark


def call_pyshark(uri,file_data,headers,http_type, search_uri=None, search_all_fields=None, To_request=False, To_response=False, byte=False,tshark=False):
    """规则过滤"""
    # 规则 1: 只匹配指定 URI 指定过滤路径
    if search_uri and search_uri not in uri:
        return False
    decoded_str_s= uri+headers+file_data
    # 规则 2: 在所有 HTTP 头部/Body 搜索关键字
    if search_all_fields and search_all_fields not in decoded_str_s:
        return False
    # 规则 3: 去掉请求
    if To_request and http_type == "Request":
        return None
    return True

def Rule_filtering(pkt, search_uri=None, search_all_fields=None, To_request=False, To_response=False, byte=False):
    # 解析 HTTP 请求
    if hasattr(pkt, 'http') and hasattr(pkt.http, 'request_method'):
        http_type = "Request"
        first_line, cleaned_headers, decoded_str = core_processing_request(pkt, byte)  # 获取请求
        decoded_str_s = " ".join(cleaned_headers) + " " + str(decoded_str)
        # 规则 2: 在所有 HTTP 头部/Body 搜索关键字
        if search_all_fields and search_all_fields not in decoded_str_s:
            return False

    # 解析 HTTP 响应
    elif hasattr(pkt, 'http') and hasattr(pkt.http, 'response_code'):
        http_type = "Response"
        first_line, cleaned_headers, decoded_str = core_processing_response(pkt, byte)  # 获取响应
        decoded_str_s = " ".join(cleaned_headers) + " " + str(decoded_str)
        # 规则 2: 在所有 HTTP 头部/Body 搜索关键字
        if search_all_fields and search_all_fields not in decoded_str_s:
            return False
    else:
        return False
    if not hasattr(pkt.http, 'request_full_uri'):
        return False
    http_uri = pkt.http.request_full_uri

    # 规则 1: 只匹配指定 URI 指定过滤路径
    if search_uri and search_uri not in http_uri:
        return False

    # 规则 3: 去掉请求
    if To_request and http_type == "Request":
        return None

    # 规则 4: 去掉响应
    if To_response and http_type == "Response":
        return None

    return first_line, cleaned_headers, decoded_str, http_type