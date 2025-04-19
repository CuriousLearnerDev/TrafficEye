"""
模块功能: 匹配日志的核心代码
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-04-14
"""


import json
import module
import re
from collections import defaultdict
import yaml


# # 几种常见日志格式正则
# LOG_FORMATS = {
#     'f5_healthcheck': re.compile(r'^\d+\.\d+\.\d+\.\d+ - - \[.*\] "GET /f5[_\w]+ HTTP/1\.1" \d+ \d+'),
#     'apache_access': re.compile(r'^\d+\.\d+\.\d+\.\d+ - - \[\d{2}/[A-Za-z]{3}/\d{4}.*\] "\w+ .* HTTP/[\d.]+" \d+ \d+$'),
#     'nginx_access': re.compile(r'^\d+\.\d+\.\d+\.\d+ - - \[\d{2}/[A-Za-z]{3}/\d{4}.*\] "\w+ .* HTTP/[\d.]+" \d+ \d+(?: \d+\.\d+)?(?: \d+\.\d+)?'),
#     'json_log': re.compile(r'^\s*\{.*\}\s*$'),
#     'haproxy_access': re.compile(r'^\w{3}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+haproxy\[\d+\]:\s+\d+\.\d+\.\d+\.\d+:\d+ \[.+\] .+ .+ \d+/\d+/\d+/\d+/\d+ \d+ \d+ .+ ".+"$'),
#     'iis_log': re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+ [A-Z]+ /.* \S+ \d+ \S+ [\d\.]+ .+ \d{3} \d+ \d+ \d+$'),
#     'tomcat_access_log': re.compile(r'^\d+\.\d+\.\d+\.\d+ - - \[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [\+\-]\d{4}\] "\w+ \S+ HTTP/[\d.]+" \d+ \d+$')
# }
#
# iis_log = re.compile(
#     r'(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) '
#     r'(?P<s_ip>\S+) (?P<method>[A-Z]+) (?P<path>\S+) (?P<query>\S+) '
#     r'(?P<port>\d+) (?P<username>\S+) (?P<client_ip>[0-9a-fA-F:.]+) '
#     r'(?P<user_agent>.+?) (?P<status_code>\d{3}) \d+ \d+ (?P<time_taken>\d+)'
# )
#
# haproxy_access = re.compile(
#     r'\S+ \S+ \S+ \[\d+\]: '
#     r'(?P<ip>[0-9a-fA-F:.]+):\d+ \[(?P<timestamp>[^\]]+)\] '
#     r'(?P<frontend>\S+) (?P<backend>\S+/\S+) '
#     r'\d+/\d+/\d+/\d+/\d+ (?P<status_code>\d{3}) (?P<size>\d+) '
#     r'[^"]*"(?P<method>[A-Z]+) (?P<path>[^ ]+) HTTP/[^"]+"'
# )
# access_log = re.compile(
#     r'(?P<ip>[0-9a-fA-F:.]+) [^ ]+ [^ ]+ \[(?P<timestamp>[^\]]+)\] '
#     r'"(?P<method>[A-Z]+) (?P<path>[^ ]+) HTTP/[^"]+" '
#     r'(?P<status_code>\d{3}) (?P<size>\d+|-) '
#     r'"(?P<referer>[^"]*)" '
#     r'"(?P<user_agent>[^"]*)"'
# )


def load_config(config_path='config.yaml'):
    """加载 YAML 配置文件，并编译正则表达式"""
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    # 编译日志格式的正则
    config['compiled_log_formats'] = {
        name: re.compile(pattern)
        for name, pattern in config.get('log_formats', {}).items()
    }

    # 编译解析器正则表达式
    parsers = config.get('parsers', {})
    for name, parser in parsers.items():
        if isinstance(parser, str):
            # 如果是字符串，包裹成 dict
            parser = {'pattern': parser}
            config['parsers'][name] = parser
        parser['compiled_pattern'] = re.compile(parser['pattern'])

    return config


# 加载配置
CONFIG = load_config()


def process_log_file(file_path, url_count, log_type):
    """处理日志文件并提取统计信息"""
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if log_type in ["apache_access", "nginx_access", "tomcat_access_log", "f5_healthcheck"]:
                line = line.strip().replace('＂', '"')  # 清理空白和全角引号
                parse_access_line(line, url_count, log_type)
            elif log_type == "json_log":
                parse_json_web_log(line, url_count)
            elif log_type == "haproxy_access":
                parse_haproxy_access_web_log(line, url_count)
            elif log_type == "iis_log":
                parse_iis_web_log(line, url_count)


def parse_iis_web_log(log_line, url_count):
    """解析 iis_log 格式的 Web 日志并更新统计"""
    match = CONFIG['parsers']['iis_log']['compiled_pattern'].match(log_line)
    if match:
        groups = match.groupdict()
        path = groups['path']
        method = groups['method']
        status_code = groups['status_code']
        client_ip = groups['client_ip']
        user_agent = groups['user_agent']

        url_count[path]['count'] += 1
        url_count[path]['source_ips'][module.Offline_IP_query(client_ip)] += 1
        url_count[path]['methods'][method] += 1
        url_count[path]['status_codes'][status_code] += 1
        url_count[path]["UA"][user_agent] += 1


def parse_haproxy_access_web_log(log_line, url_count):
    """解析 haproxy_access 格式的 Web 日志并更新统计"""
    match = CONFIG['parsers']['haproxy_access']['compiled_pattern'].match(log_line)
    if match:
        groups = match.groupdict()
        ip = groups['ip']
        path = groups['path']
        method = groups['method']
        status_code = groups['status_code']
        frontend = groups['frontend']
        backend = groups['backend']
        size = groups['size']
        timestamp = groups['timestamp']

        # 更新统计信息
        url_count[path]['count'] += 1
        url_count[path]['source_ips'][module.Offline_IP_query(ip)] += 1
        url_count[path]['methods'][method] += 1
        url_count[path]["status_codes"][status_code] += 1
        url_count[path]["sizes"][size] += 1
        url_count[path]["frontend"][frontend] += 1
        url_count[path]["backend"][backend] += 1


def parse_json_web_log(log_line, url_count):
    """解析 JSON 格式的 Web 日志并更新统计"""
    log_data = json.loads(log_line)

    path = log_data.get("url")
    ip = log_data.get("client_ip")
    method = log_data.get("method")
    status_code = str(log_data.get("status_code"))
    user_agent = log_data.get("user_agent")

    url_count[path]["count"] += 1
    url_count[path]["source_ips"][module.Offline_IP_query(ip)] += 1
    url_count[path]["methods"][method] += 1
    url_count[path]["UA"][user_agent] += 1
    url_count[path]["status_codes"][status_code] += 1


def parse_access_line(log_line, url_count, log_type):
    """解析 apache/nginx/tomcat 访问日志"""
    match = CONFIG['parsers']['access_log']['compiled_pattern'].match(log_line)
    if match:
        groups = match.groupdict()
        ip = groups['ip']
        path = groups['path']
        method = groups['method']
        status_code = groups['status_code']
        user_agent = groups['user_agent']

        url_count[path]['count'] += 1
        url_count[path]['source_ips'][module.Offline_IP_query(ip)] += 1
        url_count[path]['methods'][method] += 1
        url_count[path]["UA"][user_agent] += 1
        url_count[path]["status_codes"][status_code] += 1


def guess_log_format(file_path, max_lines=10):
    """猜测日志文件格式"""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = []
        for _ in range(max_lines):
            line = f.readline()
            if not line:
                break
            line = line.strip().replace('＂', '"')  # 清理空白和全角引号
            if line:
                lines.append(line)

    if not lines:
        return 'unknown'

    matches = {name: 0 for name in CONFIG['compiled_log_formats']}

    for line in lines:
        for name, pattern in CONFIG['compiled_log_formats'].items():
            if pattern.match(line):
                matches[name] += 1

    best_match = max(matches.items(), key=lambda x: x[1])

    # 至少要有一半匹配才能算数
    if best_match[1] / len(lines) >= 0.5:
        return best_match[0]
    return 'unknown'
