"""
模块功能: 存放公共函数或类，可以被多个模块复用
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-04-14
"""
__author__ = "W啥都学"

import re
import os
from loguru import logger
import yaml
import string
import random
import subprocess
import time
import tldextract
from urllib.parse import urlparse
import platform
from lib.xdbSearcher import XdbSearcher

# 创建日志文件夹（如果不存在的话）
log_folder = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
os.makedirs(log_folder, exist_ok=True)

# 配置日志文件
log_path = os.path.join(log_folder, "run_{time:YYYY-MM-DD}.log")
logger.add(log_path, rotation="00:00", retention="7 days", encoding="utf-8")

# 导出 logger 供其他模块使用
__all__ = ['logger']


# 移除ANSI转义码的正则表达式
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[mK]')


def create_folder_if_not_exists(self, folder_path):
    """判断文件夹存在不，不存在创建"""
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        logger.info(f"文件夹 '{folder_path}' 创建成功.")
        return False
    else:
        logger.info(f"文件夹 '{folder_path}' 已存在.")
        return True

def threading_directory(path):
    # 获取当前操作系统信息
    current_os = platform.system()
    if current_os == "Windows":
        os.startfile(path.replace('/', '\\'))
    elif current_os == "Linux":
        subprocess.call(["xdg-open", path])  # windows 工作目录
    else:
        logger.info("当前操作系统是其他操作系统")


def Offline_IP_query(ip):
    dbPath = "lib/ip2region.xdb"
    vi = XdbSearcher.loadVectorIndexFromFile(dbfile=dbPath)
    searcher = XdbSearcher(dbfile=dbPath, vectorIndex=vi)
    region_str = searcher.search(ip)

    # 去掉值为 "0" 的字段
    fields = region_str.split('|')
    fields = [field for field in fields if field != "0" and field.strip()]
    region_str = "-".join(fields)

    region_str= f"{ip}：{region_str}"

    # 4. 关闭searcher
    searcher.close()
    return region_str

def mac_to_binary(mac_address):
    """叫mac地址换成二进制"""
    # 这里假设经过 data_conversion 后的 MAC 地址已经是字符串
    # 不需要移除分隔符，因为原始MAC地址已经是无分隔符形式
    mac_binary = ''.join(format(ord(char), '08b') for char in mac_address)
    return mac_binary


def remove_ansi_escape_codes(text):
    """ 移除ANSI转义码 """
    return ANSI_ESCAPE.sub('', text)

def parse_http_headers(http_headers):
    """  解析 HTTP 头部成字典 """
    headers_dict = {}
    for header in http_headers:
        if ": " in header:  # 避免空行
            key, value = header.split(": ", 1)  # 只分割一次，避免内容包含 `: `
            headers_dict[key] = value
    return headers_dict


def decode_body(hex_str, byte_output):
    """ 解码 HTTP Body 数据 """

    byte_data = bytes.fromhex(hex_str)
    if byte_output:
        return str(byte_data)
    else:
        return byte_data.decode('utf-8', errors='replace')
def get_address_info(url=None,x_forwarded_for=None,ip_src=None):
    """
    获取请求的地址信息，支持 X-Forwarded-For 和 IP 源地址
    """
    if x_forwarded_for:
        return f"\nX-Forwarded-For: {x_forwarded_for}\n请求地址: {url}\n{'=' * 50}"
    elif ip_src:
        return f"\n包头中的源IP地址: {ip_src}\n请求地址: {url}\n{'=' * 50}"
    else:
        return f"\n请求的内容：{url}\n{'=' * 50}"
def remove_duplicates(input_list):
    """
    去重功能函数，保持列表的顺序。

    参数:
        input_list (list): 需要去重的列表。

    返回:
        list: 去重后的新列表，保留原始顺序。
    """
    unique_list = []
    [unique_list.append(item) for item in input_list if item not in unique_list]
    return unique_list

def Del_Filename(self, filename):
    try:
        if os.path.exists(filename):
            os.remove(filename)
            logger.info(f"删除{filename}成功！")
    except:
        logger.exception("请求错误！")
        return False


def load_config(): # 获取配置文件
    try:
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
        return config
    except:
        logger.exception("请求错误！")
        return False
def read_file_list(route): # 将文件的每一行作为列表中的元素
    try:
        with open(route, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        return lines
    except:
        logger.exception("请求错误！")
        return False
def filter_domains(input_list):
    """
    过滤列表中的域名，排除 IP 地址。

    参数:
        input_list (list): 包含 IP 和域名的列表。

    返回:
        list: 仅包含域名的列表。
    """
    return [item for item in input_list if item and any(c.isalpha() for c in item)]

def get_file_domain(route): # 批量提取文件域名
    lines = read_file_list(route)
    domain_lines=[]
    for uri in lines:
        domain_lines.append(get_root_domain(uri))
    return filter_domains(domain_lines)

def get_lines_domain(lines): # 批量提取lines跟域名
    lines = filter_domains(lines)
    domain_lines=[]
    for uri in lines:
        domain_lines.append(get_root_domain(uri))
    return filter_domains(domain_lines)

def get_root_domain(url):
    """
    获取URL的根域名。

    参数:
        url (str): 输入的URL或域名。

    返回:
        str: 根域名。
    """
    extracted = tldextract.extract(url)
    root_domain = f"{extracted.domain}.{extracted.suffix}"
    return root_domain

def pause_for_minutes(minutes):
    """
    暂停程序执行指定的分钟数。

    参数:
        minutes (int or float): 暂停的分钟数。
    """
    seconds = minutes * 60
    print(f"暂停 {minutes} 分钟...")
    time.sleep(seconds)
    print("继续执行")

def random_digit_string(length):
    """
    生成指定长度的随机数字字符串。

    参数:
        length (int): 字符串的长度。

    返回:
        str: 随机数字字符串。
    """
    digits = string.digits
    return ''.join(random.choice(digits) for _ in range(length))



def extract_domain(urls):
    """
    从URL列表中提取域名。

    参数:
        urls (list): 包含多个URL的列表。

    返回:
        list: 域名的列表。
    """
    domains = []
    for url in urls:
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            # 如果有端口号，移除端口号
            domain = domain.split(':')[0]
            domains.append(domain)
        except Exception as e:
            print(f"Error extracting domain from {url}: {e}")
            domains.append(None)
    return domains



# 提取出来的结果保存起来
def Searchresults(content, file_name):
    """ 写入文件 """
    with open(file_name, 'a') as file:
        file.write(content + '\n')

def custom_output(content):
    """ 自定义输出，这样统一好管理 """
    from output_filtering import Specify_save
    if Specify_save:
        print(content)
        Searchresults(content,Specify_save)
    else:
        print(content)
