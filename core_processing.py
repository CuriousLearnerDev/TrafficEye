"""
模块功能: 核心处理模块：处理 HTTP 请求/响应数据的解析和转换
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-05-10
"""

import subprocess
import platform
import csv
import io
import yaml
from dateutil.parser import parse


import module
from examine import SecurityScanner

scanner = SecurityScanner()


def reload_scanner(config_path: str = "config.yaml"):
    """规则配置保存后热重载，使 PCAP/Python 扫描立即生效。"""
    global scanner
    try:
        scanner = SecurityScanner(config_path)
        return True, None
    except Exception as e:
        return False, str(e)

# 获取当前操作系统信息
current_os = platform.system()
# 判断当前操作系统
if current_os == "Windows":
    #tshark = "tshark.exe"  # windows 工作目录
    tshark = ".\\lib\\tshark.exe"  # windows 工作目录
else:
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
    pass

    return None

def based_on_tshark(traffic_file,sslkeylogfile=None):
    # 设置 tShark 命令
    command = [
        tshark,
        # "-i", "wlan0",
        # "-l",
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


def process_tshark_line(line, url_count, session_data=None,optional_parameters=None):
    """处理tshark输出的单行数据"""
    reader = csv.reader(io.StringIO(line), delimiter='|', quotechar='"')
    fields = next(reader)

    stream_id = fields[0]
    method = fields[1] if len(fields) > 1 else None
    uri = fields[2] if len(fields) > 2 else None
    version = fields[3] if len(fields) > 3 else None
    request_line = fields[4] if len(fields) > 4 else None
    response_version = fields[5] if len(fields) > 5 else None
    response_code = fields[6] if len(fields) > 6 else None
    response_phrase = fields[7] if len(fields) > 7 else None
    response_line = fields[8] if len(fields) > 8 else None
    file_data = fields[9] if len(fields) > 9 else None
    ip_src = fields[10] if len(fields) > 10 else None
    full_uri = fields[11] if len(fields) > 11 else None
    x_forwarded_for = fields[12] if len(fields) > 12 else None
    time = fields[13] if len(fields) > 13 else None

    # 处理数据格式
    if request_line:
        request_line = request_line.replace(r"\r\n,", "\n").replace(r"\r\n", "\n")
    if response_line:
        response_line = response_line.replace(r"\r\n,", "\n").replace(r"\r\n", "\n")

    http_type = "Request" if method else "Response"
    ip_with_location = "Unknown"
    formatted_time = "Unknown"

    recording_stream_id = None

    recording_stream = []

    if method:  # 处理请求
        url_count[full_uri]['count'] += 1
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
            ip_with_location = module.Offline_IP_query(ip)
        elif ip_src:
            ip = ip_src
            ip_with_location = module.Offline_IP_query(ip)

        # 保存请求IP到会话数据中
        if session_data is not None:
            session_data.append({'stream_id': stream_id,'client_ip': ip_with_location,'url': full_uri })


        # 更新该URL对应的IP相关统计
        url_count[full_uri]['source_ips'][ip_with_location]['count'] += 1
        url_count[full_uri]['source_ips'][ip_with_location]['methods'][method] += 1
        if time:
            formatted_time = convert_frame_time(time)
            url_count[full_uri]['source_ips'][ip_with_location]['request_time'][formatted_time] += 1
        http_version = version
        headers = parse_headers(request_line)

        if "User-Agent" in headers:
            UA = headers["User-Agent"]
            url_count[full_uri]['source_ips'][ip_with_location]['UA'][UA] += 1

        if optional_parameters:
            # ################URI检测###################
            if optional_parameters["URL_Security_Check"]:
                # 执行安全扫描
                scan_results = scanner.scan_url(uri)
                if scan_results:  # 统计危险 数
                    url_count[full_uri]['danger_count'] += 1
                # 存储完整的检测结果
                danger_summary = []
                for rule_type, matches in scan_results.items():
                    for match in matches:
                        danger_summary.append({
                            'rule_type': rule_type,
                            'rule_name': match.rule_name,
                            'matched': match.matched,
                            'position': match.position,
                            'context': match.context,
                            'severity': match.severity.value
                        })

                # 将结果存储到danger字段
                url_count[full_uri]['source_ips'][ip_with_location]['danger'].extend(danger_summary)

            lowercase_data = {k.lower(): v for k, v in headers.items()}

            # ####################头部检测###############
            if optional_parameters["Request_Head_Security_Check"]:
                header_results = scanner.scan_headers(lowercase_data)
                if header_results:  # 统计危险 数
                    url_count[full_uri]['danger_count'] += 1
                danger_summary = []
                for rule_type, matches in header_results.items():
                    for match in matches:
                        danger_summary.append({
                            'rule_type': rule_type,
                            'rule_name': match.rule_name,
                            'matched': match.matched,
                            'position': match.position,
                            'context': match.context,
                            'severity': match.severity.value
                        })
                url_count[full_uri]['source_ips'][ip_with_location]['danger'].extend(danger_summary)
            if optional_parameters["Data_section_detection"]:
                ####################数据部分检测###############
                if not ("GET" in method or  "HEAD" in method):
                    if "content-type" in lowercase_data:
                        if "multipart/form-data" in lowercase_data["content-type"]:
                            analysis_data = bytes.fromhex(file_data).decode('utf-8', errors='ignore')  # 跳过不能解码的部分
                        else:
                            try:
                                analysis_data=bytes.fromhex(file_data).decode('utf-8')
                            except:
                                lowercase_data["content-type"]="binary"
                                analysis_data=file_data

                        scan_results = scanner.scan_body(analysis_data,lowercase_data["content-type"],optional_parameters=optional_parameters)
                        if scan_results:  # 统计危险 数
                            url_count[full_uri]['danger_count'] += 1
                        danger_summary = []
                        for rule_type, matches in scan_results.items():
                            for match in matches:
                                danger_summary.append({
                                    'rule_type': rule_type,
                                    'rule_name': match.rule_name,
                                    'matched': match.matched,
                                    'position': match.position,
                                    'context': match.context,
                                    'severity': match.severity.value
                                })
                        # 将结果存储到danger字段
                        url_count[full_uri]['source_ips'][ip_with_location]['danger'].extend(danger_summary)

    else:  # 处理响应
        # 通过stream_id查找对应的请求IP
        client_ip_with_location = "Unknown"
        if session_data is not None:
            for session in session_data:
                if session['stream_id'] == stream_id and session['url'] == full_uri:
                    client_ip_with_location = session['client_ip']
                    break
        # 记录响应状态码到请求方的统计中
        url_count[full_uri]['source_ips'][client_ip_with_location]['status_codes'][response_code] += 1

        http_version = response_version
        headers = parse_headers(response_line)


    return {
        'http_type': http_type,
        "uri": uri,
        "url": full_uri,
        "method": method,
        "ip": ip_with_location if http_type == "Request" else client_ip_with_location,
        'stream_id': stream_id,
        'headers': headers,
        'file_data': file_data,
        "http_version": http_version,
        "response_phrase": response_phrase,
        "response_code": response_code,
        "request_time": formatted_time,
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
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception as e:
        print(f"[时间解析失败] 原始字符串: '{raw_time_str}' 错误: {e}")
        return raw_time_str

if __name__ == '__main__':
    from collections import defaultdict

    url_count = defaultdict(lambda: {
        'count': 0,
        'danger_count': 0,
        'source_ips': defaultdict(lambda: {
            'count': 0,
            'methods': defaultdict(int),
            'status_codes': defaultdict(int),
            'UA': defaultdict(int),
            'sizes': defaultdict(int),
            'frontend': defaultdict(int),
            'request_time': defaultdict(int),
            'backend': defaultdict(int),
            'danger': list()
        }),
    }) # 用字典统计 URL 的出现次数和响应状态码
    session_data = []
    optional_parameters = {
        "URL_Security_Check": True,
        "Request_Head_Security_Check": True,
        "Data_section_detection": {
            "enabled": True,  # ← 是否勾选“请求体安全检测”总开关
            "binary": True,
            "forms": True,
            "json": True,
            "xml": True,
            "multipart": True
        }
    }
    process = based_on_tshark("抓取流量(2).pcapng")
    for line in process.stdout:
        result=process_tshark_line(line, url_count, session_data=session_data,optional_parameters=optional_parameters)

        print(url_count)











    #
    # cap = pyshark.FileCapture("gsl.pcap",
    #                           display_filter='http || http2',
    #                           debug=False  # 关闭调试输出
    #                           )  # 读取 cap 文件
    # for index, pkt in enumerate(cap, start=0):
    #     result=core_processing(pkt, url_count, session_data=session_data)
