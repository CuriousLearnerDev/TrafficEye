"""
模块功能: 处理会话数据（如存储、整理 HTTP 请求/响应）
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-04-04
"""

import Godzilla
import module
from urllib.parse import urlparse
from custom_extension import data_processing
import modsec_crs

def sroom_session(method=None,full_uri=None, cleaned_headers=None, decoded_str=None, http_type=None,response_code=None):
    """ 整理会话数据 """
    headers_dict = module.parse_http_headers(cleaned_headers)  # 解析 HTTP 头部成字典
    result={
            http_type: {
            'method':method,
            'request_url': full_uri,
            'uri': urlparse(full_uri).path,
            'headers': headers_dict,
            'http_byte': decoded_str
            }
            }
    if http_type=="Request":
        # 用户自定义
        data_processing.request_data(full_uri,urlparse(full_uri).path,headers_dict,decoded_str)

        # 安全检测
        #modsec_crs.request_data(result)

    elif http_type=="Response":
        # 用户自定义
        data_processing.response_data(response_code,headers_dict,decoded_str)

        # 安全检测
        #modsec_crs.response_data(result)
    return result

def Abnormal_flow_detection(uri, session_data):
    """ 检测异常流量 """
    if Godzilla.check_ghost_shell_traffic(session_data):
        print(f"⚠️ 可能的哥斯拉 Webshell 连接 -  {uri}")
