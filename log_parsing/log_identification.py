"""
模块功能: 匹配日志的核心代码
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-04-14
"""

import json
import time
import module
from examine import SecurityScanner
import re
from collections import defaultdict
import yaml
from datetime import datetime
from dateutil.parser import parse

scanner = SecurityScanner()


def _append_danger(danger_summary, rule_type, match):
    """把一次规则命中转成 dict 并加入 danger_summary 列表"""
    danger_summary.append({
        'rule_type': rule_type,
        'rule_name':  match.rule_name,
        'matched':    match.matched,
        'position':   getattr(match, 'position', None),
        'context':    getattr(match, 'context',  None),
        # 如果 severity 是 Enum，把 value 取出来；否则直接塞进去
        'severity':   getattr(match.severity, 'value', match.severity)
    })


def load_config(config_path='config.yaml'):
    """加载 YAML 配置文件，并编译正则表达式"""
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    config['compiled_log_formats'] = {
        name: re.compile(pattern)
        for name, pattern in config.get('log_formats', {}).items()
    }

    for name, parser in config.get('parsers', {}).items():
        if isinstance(parser, str):
            parser = {'pattern': parser}
            config['parsers'][name] = parser
        parser['compiled_pattern'] = re.compile(parser['pattern'])

    return config

CONFIG = load_config()
ip_cache = {}

def cached_ip_query(ip):
    """带缓存的 IP 查询"""
    if ip in ip_cache:
        return ip_cache[ip]
    result = module.Offline_IP_query(ip)
    ip_cache[ip] = result
    return result

def format_time_str(timestr: str) -> str:
    if not timestr:
        return ""
    for fmt in ("%Y-%m-%d %H:%M:%S%z", "%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S %z"):
        try:
            dt = datetime.strptime(timestr, fmt)
            return dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            continue
    # 避免 dateutil fuzzy 对异常时间逐行解析（大日志会极慢/像卡死）
    try:
        dt = parse(timestr, fuzzy=False)
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return (timestr[:16] if len(timestr) >= 16 else timestr)

def parse_access_line(log_line, url_count, log_type,optional_parameters_log):
    """解析 apache/nginx/tomcat 访问日志"""
    match = CONFIG['parsers']['common_web_log']['compiled_pattern'].match(log_line)
    if not match:
        return

    groups = match.groupdict()
    ip = groups['ip']
    time = groups['time']
    formatted_time = format_time_str(time)
    path = groups['path']
    method = groups['method']
    status_code = groups['status_code']
    user_agent = groups['user_agent']

    url_count[path]['count'] += 1
    if optional_parameters_log and optional_parameters_log.get("Skip_IP_Geo"):
        ip_info = ip
    else:
        ip_info = cached_ip_query(ip)

    url_count[path]['source_ips'][ip_info]['count'] += 1
    url_count[path]['source_ips'][ip_info]['methods'][method] += 1
    url_count[path]['source_ips'][ip_info]["UA"][user_agent] += 1
    url_count[path]['source_ips'][ip_info]["status_codes"][status_code] += 1
    url_count[path]['source_ips'][ip_info]['request_time'][formatted_time] += 1

    if optional_parameters_log['URI_Security_Check']: # 启动安全探测
        scan_results = scanner.scan_url(path)
        if scan_results:
            url_count[path]['danger_count'] += 1

        danger_summary = []
        for rule_type, matches in scan_results.items():
            for match in matches:
                _append_danger(danger_summary, rule_type, match)
        url_count[path]['source_ips'][ip_info]['danger'].extend(danger_summary)

def parse_json_web_log(log_line, url_count,optional_parameters_log):
    """解析 JSON 格式的 Web 日志并更新统计"""
    log_data = json.loads(log_line)
    path = log_data.get("url")
    ip = log_data.get("client_ip")
    method = log_data.get("method")
    status_code = str(log_data.get("status_code"))
    user_agent = log_data.get("user_agent")

    ip_info = cached_ip_query(ip)

    url_count[path]["count"] += 1
    url_count[path]['source_ips'][ip_info]['count'] += 1
    url_count[path]['source_ips'][ip_info]['methods'][method] += 1
    url_count[path]['source_ips'][ip_info]["UA"][user_agent] += 1
    url_count[path]['source_ips'][ip_info]["status_codes"][status_code] += 1

    if optional_parameters_log['URI_Security_Check']:  # 启动安全探测
        scan_results = scanner.scan_url(path)

        if scan_results:
            url_count[path]['danger_count'] += 1

        danger_summary = []
        for rule_type, matches in scan_results.items():
            for match in matches:
                _append_danger(danger_summary, rule_type, match)
        url_count[path]['source_ips'][ip_info]['danger'].extend(danger_summary)

def parse_haproxy_access_web_log(log_line, url_count,optional_parameters_log):
    """解析 haproxy_access 格式的 Web 日志"""
    match = CONFIG['parsers']['haproxy_access']['compiled_pattern'].match(log_line)
    if not match:
        return
    groups = match.groupdict()
    ip = groups['ip']
    path = groups['path']
    method = groups['method']
    status_code = groups['status_code']
    frontend = groups['frontend']
    backend = groups['backend']
    size = groups['size']

    ip_info = cached_ip_query(ip)

    url_count[path]['count'] += 1
    url_count[path]['source_ips'][ip_info]['count'] += 1
    url_count[path]['source_ips'][ip_info]['methods'][method] += 1
    url_count[path]['source_ips'][ip_info]["status_codes"][status_code] += 1
    url_count[path]['source_ips'][ip_info]["sizes"][size] += 1
    url_count[path]['source_ips'][ip_info]["frontend"][frontend] += 1
    url_count[path]['source_ips'][ip_info]["backend"][backend] += 1

    if optional_parameters_log['URI_Security_Check']:  # 启动安全探测
        scan_results = scanner.scan_url(path)

        if scan_results:
            url_count[path]['danger_count'] += 1

        danger_summary = []
        for rule_type, matches in scan_results.items():
            for match in matches:
                _append_danger(danger_summary, rule_type, match)
        url_count[path]['source_ips'][ip_info]['danger'].extend(danger_summary)

def parse_iis_web_log(log_line, url_count,optional_parameters_log):
    """解析 IIS 日志"""
    match = CONFIG['parsers']['iis_log']['compiled_pattern'].match(log_line)
    if not match:
        return
    groups = match.groupdict()
    path = groups['path']
    method = groups['method']
    status_code = groups['status_code']
    client_ip = groups['client_ip']
    user_agent = groups['user_agent']

    ip_info = cached_ip_query(client_ip)

    url_count[path]['count'] += 1
    url_count[path]['source_ips'][ip_info]['count'] += 1
    url_count[path]['source_ips'][ip_info]['methods'][method] += 1
    url_count[path]['source_ips'][ip_info]['status_codes'][status_code] += 1
    url_count[path]['source_ips'][ip_info]["UA"][user_agent] += 1

    if optional_parameters_log['URI_Security_Check']:  # 启动安全探测
        scan_results = scanner.scan_url(path)

        if scan_results:
            url_count[path]['danger_count'] += 1

        danger_summary = []
        for rule_type, matches in scan_results.items():
            for match in matches:
                _append_danger(danger_summary, rule_type, match)
        url_count[path]['source_ips'][ip_info]['danger'].extend(danger_summary)

def process_log_file(file_path, url_count, log_type,optional_parameters_log):
    """处理日志文件并提取统计信息"""
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip().replace('＂', '"')
            if log_type in ["apache_access", "nginx_access", "tomcat_access_log", "f5_healthcheck"]:
                parse_access_line(line, url_count, log_type,optional_parameters_log)
            elif log_type == "json_log":
                parse_json_web_log(line, url_count,optional_parameters_log)
            elif log_type == "haproxy_access":
                parse_haproxy_access_web_log(line, url_count,optional_parameters_log)
            elif log_type == "iis_log":
                parse_iis_web_log(line, url_count,optional_parameters_log)

    total_ips = set()
    total_uris = set()
    total_status_codes = defaultdict(int)

    for uri, data in url_count.items():
        total_uris.add(uri)
        for ip, ip_data in data['source_ips'].items():
            total_ips.add(ip)
            for status_code, count in ip_data['status_codes'].items():
                total_status_codes[status_code] += count

    try:
        danger = 0
        for i in url_count.values():
            if not "未检测到安全威胁" in i['danger']:
                if i['danger']:
                    danger += 1
    except:
        danger = ""

    url_count['_global_stats'] = {
        'request_total': sum(stats['count'] for stats in url_count.values()),
        'danger_total': danger,
        'total_unique_ips': len(total_ips),
        'total_unique_uris': len(total_uris),
        'total_unique_status_code': len(total_status_codes)
    }

def guess_log_format_remote(content):
    lines=[content.strip().replace('＂', '"')]

    matches = {name: 0 for name in CONFIG['compiled_log_formats']}

    for line in lines:
        for name, pattern in CONFIG['compiled_log_formats'].items():
            if pattern.match(line):
                matches[name] += 1

    best_match = max(matches.items(), key=lambda x: x[1])
    if best_match[1] / len(lines) >= 0.5:
        return best_match[0]
    return 'unknown'




def guess_log_format(file_path, max_lines=10):
    """猜测日志文件格式"""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = []
        for _ in range(max_lines):
            line = f.readline()
            if not line:
                break
            line = line.strip().replace('＂', '"')
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
    if best_match[1] / len(lines) >= 0.5:
        return best_match[0]
    return 'unknown'

if __name__ == "__main__":
    # 开始计时
    start_time = time.time()
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
        }),})

    # 启动日志文件分析对话框
    optional_parameters_log = {
        "URI_Security_Check": False
    }

    path = "log_parsing/f5_healthcheck.txt"
    log_format = guess_log_format(path)
    print(f"检测到日志类型：{log_format}")

    process_log_file(path, url_count, log_format,optional_parameters_log)
    print(f"URL统计信息：{url_count}")
    # 结束计时
    end_time = time.time()

    # 打印用时
    print(f"程序运行时间：{end_time - start_time:.4f} 秒")






