"""
模块功能: 核心处理模块：处理 HTTP 请求/响应数据的解析和转换
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-04-04
"""

import subprocess
from urllib.parse import urlparse
from collections import defaultdict

import pyshark

import module

from session_utils import sroom_session, Abnormal_flow_detection



def parse_headers(header_string):
    """
    将HTTP头部字符串转换为字典
    """
    headers = {}
    for line in header_string.split("\n"):
        if line.strip():  # 只处理不为空的行
            key, value = line.split(':', 1)  # 分割成 key 和 value，最多一次分割
            headers[key.strip()] = value.strip()  # 去除多余的空格
    return headers

def core_processing(pkt, url_count, session_data=None):
    """ 提取文件里面的响应数据 """

    # 统一赋值None
    http_type =headers= uri = method = full_uri = ip = stream_id = file_data = http_version = response_phrase = response_code = ""

    # 解析 HTTP 请求
    if hasattr(pkt, 'http') and hasattr(pkt.http, 'request_method')  and hasattr(pkt.http, 'request_full_uri'):
        http_type = "Request"
        uri = urlparse(pkt.http.request_full_uri).path
        full_uri=pkt.http.request_full_uri

        method=pkt.http.request_method

        if hasattr(pkt.http, 'x_forwarded_for'):
            url_count[full_uri]['source_IP'][pkt.http.x_forwarded_for] += 1
            ip=pkt.http.x_forwarded_for
        elif hasattr(pkt, 'ip') and hasattr(pkt.ip, 'src'):
            url_count[full_uri]['source_IP'][pkt.ip.src] += 1
            ip = pkt.ip.src
        http_version=pkt.http.request_version

        # 获取头部
        lists_response = pkt.http.request_line.all_fields

        headers = {req.showname_key: req.showname_value.replace('\\n', '').replace('\\r', '') for req in lists_response}
        stream_id=pkt.tcp.stream


        # 解析 HTTP Body
        if hasattr(pkt.http, 'file_data'):
            file_data=pkt.http.file_data.replace(':', '')
        if hasattr(pkt.http, 'data'):
            file_data = pkt.http.data.replace(':', '')

        session_data.append(sroom_session(method=method, full_uri=full_uri, cleaned_headers=headers, decoded_str=file_data,http_type=http_type))

    elif hasattr(pkt, 'http') and hasattr(pkt.http, 'response_line') and hasattr(pkt.http, 'request_full_uri'):
        http_type="Response"
        uri = urlparse(pkt.http.request_full_uri).path
        full_uri = pkt.http.request_full_uri
        response_phrase=pkt.http.response_phrase
        #method = pkt.http.response_method

        # 获取头部
        lists_response = pkt.http.response_line.all_fields
        headers = {req.showname_key: req.showname_value.replace('\\n', '').replace('\\r', '') for req in lists_response}
        stream_id = pkt.tcp.stream

        if hasattr(pkt.http, 'file_data'):
            file_data = pkt.http.file_data.replace(':', '')

        http_version=pkt.http.response_version

        response_code=pkt.http.response_code
        session_data.append(sroom_session(full_uri=full_uri, cleaned_headers=headers, decoded_str=file_data, http_type=http_type,response_code=response_code))

    return {
        'http_type': http_type,
        "uri": uri,
        "url": full_uri,
        "method": method,
        "ip": ip,
        'stream_id': stream_id,
        'headers': headers,
        'file_data': file_data,
        "http_version": http_version,
        "response_phrase": response_phrase,
        "response_code": response_code,  # 响应代码
        'session_data': session_data
    }



def based_on_tshark(traffic_file):
    # 设置 tShark 命令
    command = [
        "tshark",
        "-r", traffic_file,
        "-T", "fields",
        "-Y", "http",
        "-e", "tcp.stream",
        "-e", "http.request.method",
        "-e", "http.request.uri",
        "-e", "http.request.version",
        "-e", "http.request.line",
        "-e", "http.response.version",
        "-e", "http.response.code",
        "-e", "http.response.phrase",
        "-e", "http.response.line",
        "-e", "http.file_data",
        "-e", "ip.src",
        "-e", "http.request.full_uri",
        "-e", "http.x_forwarded_for",
        "-E", "separator=|"
    ]

    # 使用 subprocess 运行 tShark 命令
    try:
        # 使用 Popen 动态读取输出
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return process
    except subprocess.CalledProcessError as e:
        print(f"tShark 命令执行失败: {e}")
    except Exception as e:
        print(f"发生错误: {e}")


def process_tshark_line(line, url_count, session_data=None):
    # 去除空白字符并分割字段（以 "|" 为分隔符）
    fields = line.strip().split("|")

    stream_id = fields[0]  # tcp.stream
    method = fields[1] if len(fields) > 1 else None  # http.request.method # 获取请求方式
    uri = fields[2] if len(fields) > 2 else None  # http.request.uri 请求uri
    version = fields[3] if len(fields) > 3 else None  # http.request.version 协议
    request_line = fields[4] if len(fields) > 4 else None  # http.request.line 完整请求头
    response_version = fields[5] if len(fields) > 5 else None  # http.response.version
    response_code = fields[6] if len(fields) > 6 else None  # http.response.code
    response_phrase = fields[7] if len(fields) > 7 else None  # http.response.phrase
    response_line = fields[8] if len(fields) > 8 else None  # http.response.line
    file_data = fields[9] if len(fields) > 9 else None  # http.file_data
    ip_src = fields[10] if len(fields) > 10 else None  # ip_src
    full_uri = fields[11] if len(fields) > 11 else None  # full_uri
    x_forwarded_for = fields[12] if len(fields) > 12 else None  # x_forwarded_for

    # 处理数据格式
    if request_line:
        request_line = request_line.replace(r"\r\n,", "\n").replace(r"\r\n", "\n")
    if response_line:
        response_line = response_line.replace(r"\r\n,", "\n").replace(r"\r\n", "\n")


    http_type = "Request" if method else "Response"

    ip = ""
    if method:  # 如果是请求
        url_count[full_uri]['count'] += 1  # 统计请求次数
        if x_forwarded_for:
            url_count[full_uri]['source_IP'][x_forwarded_for] += 1
            ip = x_forwarded_for
        elif ip_src:
            url_count[full_uri]['source_IP'][ip_src] += 1
            ip = ip_src

        http_version = version
        headers = parse_headers(request_line)  # 使用提取出来的函数解析头部

        session_data.append(sroom_session(method=method, full_uri=full_uri, cleaned_headers=headers,decoded_str=file_data, http_type=http_type))
    else:  # 如果是响应
        url_count[full_uri]['status_codes'][response_code] += 1  # 统计状态码

        http_version = response_version
        headers = parse_headers(response_line)
        session_data.append(sroom_session(full_uri=full_uri, cleaned_headers=headers, decoded_str=file_data,http_type=http_type, response_code=response_code))




    return {
        'http_type': http_type,
        "uri": uri,
        "url": full_uri,
        "method": method,
        "ip": ip,
        'stream_id': stream_id,
        'headers': headers,
        'file_data': file_data,
        "http_version": http_version,
        "response_phrase": response_phrase,
        "response_code": response_code, # 响应代码
        'session_data': session_data
    }

