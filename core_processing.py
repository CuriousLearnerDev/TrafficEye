"""
模块功能: 核心处理模块：处理 HTTP 请求/响应数据的解析和转换
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-04-24
"""

import subprocess
from datetime import datetime
from urllib.parse import urlparse
import platform
import csv
import io
from dateutil.parser import parse

import pyshark

import module



# 获取当前操作系统信息
current_os = platform.system()
# 判断当前操作系统
if current_os == "Windows":
    #tshark = "tshark.exe"  # windows 工作目录
    tshark = ".\\lib\\tshark.exe"  # windows 工作目录
elif current_os == "Linux":
    tshark = "tshark"  # linux 工作目录



# 设置字段大小限制为1000MB
csv.field_size_limit(1000 * 1024 * 1024)  # 设置为1000MB

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

def processing_head_json(header_string):
    try:
       return {req.showname_key: req.showname_value.replace('\\n', '').replace('\\r', '') for req in header_string}
    except:
        return ""


def core_processing(pkt, url_count, session_data=None):
    """ 提取文件里面的响应数据 """

    # 统一赋值None
    UA=http_type =headers= uri = method = full_uri = ip = stream_id = file_data = http_version = response_phrase = response_code = ""

    # 解析 HTTP 请求
    if hasattr(pkt, 'http') and hasattr(pkt.http, 'request_method')  and hasattr(pkt.http, 'request_full_uri'):
        http_type = "Request"
        uri = urlparse(pkt.http.request_full_uri).path
        full_uri=pkt.http.request_full_uri
        url_count[full_uri]['count'] += 1  # 统计请求次数
        method=pkt.http.request_method
        url_count[full_uri]['methods'][method] += 1
        if hasattr(pkt.http, 'x_forwarded_for'):
            ip=pkt.http.x_forwarded_for.split(',')[0].strip()
            url_count[full_uri]['source_ips'][module.Offline_IP_query(ip)] += 1
        elif hasattr(pkt, 'ip') and hasattr(pkt.ip, 'src'):
            ip = pkt.ip.src
            url_count[full_uri]['source_ips'][module.Offline_IP_query(ip)] += 1
        http_version=pkt.http.request_version

        time = pkt.sniff_time.strftime("%Y-%m-%d %H:%M:%S")  # 转为可读格式
        if time:
            # 如果 'request_time' 是一个列表，直接追加时间
            if isinstance(url_count[full_uri]['request_time'], list):
                url_count[full_uri]['request_time'].append(time)
            else:
                # 如果 'request_time' 不是列表，则初始化为列表并添加时间
                url_count[full_uri]['request_time'] = [time]
        print(time)
        # 获取头部
        headers = processing_head_json(pkt.http.request_line.all_fields)

        if "User-Agent" in headers:
            url_count[full_uri]["UA"][headers["User-Agent"]] += 1

        stream_id=pkt.tcp.stream


        # 解析 HTTP Body
        if hasattr(pkt.http, 'file_data'):
            file_data=pkt.http.file_data.replace(':', '')
        if hasattr(pkt.http, 'data'):
            file_data = pkt.http.data.replace(':', '')

        #session_data.append(sroom_session(method=method, full_uri=full_uri, cleaned_headers=headers, decoded_str=file_data,http_type=http_type))

    elif hasattr(pkt, 'http') and hasattr(pkt.http, 'response_line') and hasattr(pkt.http, 'request_full_uri'):
        http_type="Response"
        uri = urlparse(pkt.http.request_full_uri).path
        full_uri = pkt.http.request_full_uri
        response_phrase=""
        if hasattr(pkt.http, 'response_phrase'):
            response_phrase = pkt.http.response_phrase

        #method = pkt.http.response_method

        # 获取头部
        headers = processing_head_json(pkt.http.response_line.all_fields)
        stream_id = pkt.tcp.stream

        if hasattr(pkt.http, 'file_data'):
            file_data = pkt.http.file_data.replace(':', '')

        http_version=pkt.http.response_version

        response_code=pkt.http.response_code

        url_count[full_uri]['status_codes'][response_code] += 1  # 统计状态码
        #session_data.append(sroom_session(full_uri=full_uri, cleaned_headers=headers, decoded_str=file_data, http_type=http_type,response_code=response_code))

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
        "request_time": response_code,  # 响应代码
        'session_data': session_data # 统计
    }



def based_on_tshark(traffic_file,sslkeylogfile=None):
    # 设置 tShark 命令
    command = [
        tshark,
        "-r", traffic_file,
        "-T", "fields",
        "-Y", "http || http2",
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
        "-e", "frame.time",
        "-E", "separator=|",
        "-E", "quote=d"
    ]
    if sslkeylogfile:
        # 如果提供了 SSL 密钥日志文件，添加到命令中
        command.extend(["-o", f"ssl.keylog_file:{sslkeylogfile}"])

    # 使用 subprocess 运行 tShark 命令
    try:
        # 使用 Popen 动态读取输出

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,encoding='utf-8')

        return process
    except subprocess.CalledProcessError as e:
        print(f"tShark 命令执行失败: {e}")
    except Exception as e:
        print(f"发生错误: {e}")


def process_tshark_line(line, url_count, session_data=None):
    # 去除空白字符并分割字段（以 "|" 为分隔符）
    # 用 csv 处理带引号的字段（避免分隔符错分）

    reader = csv.reader(io.StringIO(line), delimiter='|', quotechar='"')
    fields = next(reader)
    #fields = line.strip().split("|")

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
    time = fields[13] if len(fields) > 13 else None  # 请求时间

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
            ip = x_forwarded_for.split(',')[0].strip()
            url_count[full_uri]['source_ips'][module.Offline_IP_query(ip)] += 1
        elif ip_src:
            ip = ip_src
            url_count[full_uri]['source_ips'][module.Offline_IP_query(ip)] += 1


        if time:
            # 如果 'request_time' 是一个列表，直接追加时间
            if isinstance(url_count[full_uri]['request_time'], list):
                url_count[full_uri]['request_time'].append(convert_frame_time(time))
            else:
                # 如果 'request_time' 不是列表，则初始化为列表并添加时间
                url_count[full_uri]['request_time'] = [convert_frame_time(time)]


        url_count[full_uri]['methods'][method] +=1

        http_version = version
        headers = parse_headers(request_line)  # 使用提取出来的函数解析头部

        if "User-Agent" in headers:
            url_count[full_uri]["UA"][headers["User-Agent"]] += 1
        #session_data.append(sroom_session(method=method, full_uri=full_uri, cleaned_headers=headers,decoded_str=file_data, http_type=http_type))
    else:  # 如果是响应
        url_count[full_uri]['status_codes'][response_code] += 1  # 统计状态码
        http_version = response_version
        headers = parse_headers(response_line)
        #session_data.append(sroom_session(full_uri=full_uri, cleaned_headers=headers, decoded_str=file_data,http_type=http_type, response_code=response_code))

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
        "request_time": response_code, # 响应代码
        'session_data': session_data
    }


def convert_frame_time(raw_time_str):
    """
    时间字符串转换为易读格式，例如：2025-04-16 10:58:43.315355
    """
    try:
        if raw_time_str.endswith(" CST"):
            raw_time_str = raw_time_str.replace(" CST", "")
        if '.' in raw_time_str:
            raw_time_str = raw_time_str.split('.')[0]

        # 使用dateutil的parse函数，它能自动识别多种时间格式
        dt = parse(raw_time_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        print(f"[时间解析失败] 原始字符串: '{raw_time_str}' 错误: {e}")
        return raw_time_str
