"""
模块功能: 存放公共函数或类，可以被多个模块复用
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-04-14
"""
__author__ = "W啥都学"

import re
import os

from PyQt6.QtCore import QModelIndex, Qt, QSize
from PyQt6.QtGui import QIcon, QPixmap, QColor
from PyQt6.QtWidgets import QStyleOptionViewItem, QStyledItemDelegate
from loguru import logger
import yaml
import string
import random
import subprocess
import time
import tldextract
from collections import defaultdict
import platform
from urllib.parse import urlparse

from lib.xdbSearcher import XdbSearcher


with open("ui_config.yaml", "r", encoding="utf-8") as f:
    ui_config = yaml.safe_load(f)


# 配置 loguru 日志记录
logger.add("logs/run_{time:YYYY-MM-DD}.log", rotation="00:00", retention="7 days", backtrace=False)


def parse_http_request(request_string):
    """
    解析一个原始的HTTP请求字符串。
    参数:
    request_string (str): 包含完整HTTP请求的字符串。
    返回:
    tuple: (path, headers, body)
           - path (str): 请求的路径 (例如 /js/utils.js)
           - headers (dict): 包含所有请求头的字典
           - body (str): 请求数据（请求体），如果没有则为空字符串
    """
    # 检查是否有空行，空行是头和body的分隔符
    if '\r\n\r\n' in request_string:
        header_part, body = request_string.split('\r\n\r\n', 1)
    elif '\n\n' in request_string:
        header_part, body = request_string.split('\n\n', 1)
    else:
        # 没有分隔符，意味着没有body
        header_part = request_string
        body = ""

    # 按行分割头部
    header_lines = header_part.strip().split('\n')

    # 1. 解析请求行 (第一行)
    request_line = header_lines[0]
    try:
        method, path, protocol = request_line.split(' ')
    except ValueError:
        return None, {}, ""

    # 2. 解析请求头 (第一行之后的所有行)
    headers = {}
    wrong=None
    for line in header_lines[1:]:
        # 确保行不为空
        if line.strip():
            try:
                # 按第一个冒号分割
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
            except ValueError:
                wrong=f"警告: 忽略格式不正确的头: {line}"

    # 3. 返回路径、头、和数据
    return path, headers, body, wrong


class CountryFlagDelegate(QStyledItemDelegate):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.flag_icons = {}  # 缓存国旗图标
        self.icon_size = QSize(24, 16)
    def _get_country_code(self, location: str) -> str:
        """
        从归属地字符串中提取国家代码（如 "中国" -> "cn"）
        :param location: 归属地字符串（如 "中国-浙江省-丽水市-电信"）
        :return: 国家代码（如 "cn"），找不到返回空字符串
        """
        if not location:
            return ""

        country = location.split("-")[0]  # 提取国家部分

        # 国家名称 -> 国家代码映射（按需补充）
        country_mapping = {
            "China": "cn",
            "United States": "us",
            "Japan": "jp",
            "Germany": "de",
            "United Kingdom": "gb",
            "France": "fr",
            "Italy": "it",
            "Canada": "ca",
            "Russia": "ru",
            "Australia": "au",
            "Spain": "es",
            "India": "in",
            "Singapore": "sg",
            "Malaysia": "my",
            "South Korea": "kr",
            "Vietnam": "vn",
            "Philippines": "ph",
            "Thailand": "th",
            "Brazil": "br",
            "Mexico": "mx",
            "Turkey": "tr",
            "Netherlands": "nl",
            "The Netherlands": "nl",
            "Belgium": "be",
            "Sweden": "se",
            "Finland": "fi",
            "Norway": "no",
            "Denmark": "dk",
            "Poland": "pl",
            "Ukraine": "ua",
            "Hungary": "hu",
            "Czech Republic": "cz",
            "Slovakia": "sk",
            "Austria": "at",
            "Switzerland": "ch",
            "Ireland": "ie",
            "Portugal": "pt",
            "Greece": "gr",
            "Israel": "il",
            "United Arab Emirates": "ae",
            "South Africa": "za",
            "Egypt": "eg",
            "Argentina": "ar",
            "Chile": "cl",
            "Colombia": "co",
            "Peru": "pe",
            "New Zealand": "nz",
            "Kazakhstan": "kz",
            "Saudi Arabia": "sa",
            "Indonesia": "id",
            "Pakistan": "pk",
            "Bangladesh": "bd",
            "Nigeria": "ng",
            "Kenya": "ke",
            "Tanzania": "tz",
            "Zimbabwe": "zw",
            "Morocco": "ma",
            "Algeria": "dz",
            "Tunisia": "tn",
            "Venezuela": "ve",
            "Cuba": "cu",
            "North Korea": "kp",
            "Hong Kong": "hk",
            "Macau": "mo",
            "Taiwan": "tw",
            "Luxembourg": "lu",
            "Monaco": "mc",
            "Liechtenstein": "li",
            "Estonia": "ee",
            "Latvia": "lv",
            "Lithuania": "lt",
            "Iceland": "is",
            "Slovenia": "si",
            "Croatia": "hr",
            "Bulgaria": "bg",
            "Romania": "ro",
            "Serbia": "rs",
            "Azerbaijan": "az",
            "Georgia": "ge",
            "Armenia": "am",
            "Iran": "ir",
            "Iraq": "iq",
            "Syria": "sy",
            "Afghanistan": "af",
            "Myanmar": "mm",
            "Cambodia": "kh",
            "Laos": "la",
            "Sri Lanka": "lk",
            "Nepal": "np",
            "Bhutan": "bt",
            "Maldives": "mv",
            "Mongolia": "mn",
            "Palestine": "ps",
            "Qatar": "qa",
            "Kuwait": "kw",
            "Oman": "om",
            "Yemen": "ye",
            "Lebanon": "lb",
            "Jordan": "jo",
            "Bahrain": "bh",
            "South Sudan": "ss",
            "Sudan": "sd",
            "DR Congo": "cd",
            "Republic of the Congo": "cg",
            "Ghana": "gh",
            "Cameroon": "cm",
            "Uganda": "ug",
            "Rwanda": "rw",
            "Senegal": "sn",
            "Madagascar": "mg",
            "Botswana": "bw",
            "Namibia": "na",
            "Zambia": "zm",
            "Mozambique": "mz",
            "Angola": "ao",
            "Albania": "al",
            "Montenegro": "me",
            "North Macedonia": "mk",
            "Bosnia and Herzegovina": "ba",
            "Kosovo": "xk",
            "中国": "cn",
            "美国": "us",
            "日本": "jp",
            "德国": "de",
            "英国": "gb",
            "法国": "fr",
            "意大利": "it",
            "加拿大": "ca",
            "俄罗斯": "ru",
            "澳大利亚": "au",
            "西班牙": "es",
            "印度": "in",
            "新加坡": "sg",
            "马来西亚": "my",
            "韩国": "kr",
            "越南": "vn",
            "菲律宾": "ph",
            "泰国": "th",
            "巴西": "br",
            "墨西哥": "mx",
            "土耳其": "tr",
            "荷兰": "nl",
            "比利时": "be",
            "瑞典": "se",
            "芬兰": "fi",
            "挪威": "no",
            "丹麦": "dk",
            "波兰": "pl",
            "乌克兰": "ua",
            "匈牙利": "hu",
            "捷克": "cz",
            "斯洛伐克": "sk",
            "奥地利": "at",
            "瑞士": "ch",
            "爱尔兰": "ie",
            "葡萄牙": "pt",
            "希腊": "gr",
            "以色列": "il",
            "阿联酋": "ae",
            "南非": "za",
            "埃及": "eg",
            "阿根廷": "ar",
            "智利": "cl",
            "哥伦比亚": "co",
            "秘鲁": "pe",
            "新西兰": "nz",
            "哈萨克斯坦": "kz",
            "沙特阿拉伯": "sa",
            "印尼": "id",
            "巴基斯坦": "pk",
            "孟加拉国": "bd",
            "尼日利亚": "ng",
            "肯尼亚": "ke",
            "坦桑尼亚": "tz",
            "津巴布韦": "zw",
            "摩洛哥": "ma",
            "阿尔及利亚": "dz",
            "突尼斯": "tn",
            "委内瑞拉": "ve",
            "古巴": "cu",
            "朝鲜": "kp",
            "香港": "hk",
            "澳门": "mo",
            "台湾": "cn",
            "卢森堡": "lu",
            "摩纳哥": "mc",
            "列支敦士登": "li",
            "爱沙尼亚": "ee",
            "拉脱维亚": "lv",
            "立陶宛": "lt",
            "冰岛": "is",
            "斯洛文尼亚": "si",
            "克罗地亚": "hr",
            "保加利亚": "bg",
            "罗马尼亚": "ro",
            "塞尔维亚": "rs",
            "阿塞拜疆": "az",
            "格鲁吉亚": "ge",
            "亚美尼亚": "am",
            "伊朗": "ir",
            "伊拉克": "iq",
            "叙利亚": "sy",
            "阿富汗": "af",
            "缅甸": "mm",
            "柬埔寨": "kh",
            "老挝": "la",
            "斯里兰卡": "lk",
            "尼泊尔": "np",
            "不丹": "bt",
            "马尔代夫": "mv",
            "蒙古": "mn",
            "巴勒斯坦": "ps",
            "卡塔尔": "qa",
            "科威特": "kw",
            "阿曼": "om",
            "也门": "ye",
            "黎巴嫩": "lb",
            "约旦": "jo",
            "巴林": "bh",
            "叙利亚": "sy",
            "南苏丹": "ss",
            "苏丹": "sd",
            "刚果（金）": "cd",
            "刚果（布）": "cg",
            "加纳": "gh",
            "喀麦隆": "cm",
            "乌干达": "ug",
            "卢旺达": "rw",
            "塞内加尔": "sn",
            "马达加斯加": "mg",
            "博茨瓦纳": "bw",
            "纳米比亚": "na",
            "津巴布韦": "zw",
            "赞比亚": "zm",
            "莫桑比克": "mz",
            "安哥拉": "ao",
            "阿尔巴尼亚": "al",
            "黑山": "me",
            "北马其顿": "mk",
            "波黑": "ba",
            "科索沃": "xk",
            "未知": "zz"  # 默认图标
        }

        return country_mapping.get(country, "")

    def initStyleOption(self, option: QStyleOptionViewItem, index: QModelIndex):
        super().initStyleOption(option, index)
        ip_info = index.data(Qt.ItemDataRole.DisplayRole)
        if not ip_info:
            return

        # 父行汇总（如 "12 IP"）或提示行，不画国旗
        text = str(ip_info).strip()
        if "\n" not in text or text.endswith(" IP") or text.startswith("…") or text.startswith("..."):
            return

        ip_parts = text.split("\n")
        ip_address = ip_parts[0]
        loc_raw = ip_parts[1].strip() if len(ip_parts) > 1 else ""
        if loc_raw.startswith("(") and loc_raw.endswith(")"):
            location = loc_raw[1:-1]
        else:
            location = loc_raw or "未知"
        country = self._get_country_code(location)

        if country not in self.flag_icons:
            flag_path = f"flags/{country}.svg"
            # 尝试加载图标
            icon = QIcon(flag_path)

            # 检查图标是否有效
            if icon.isNull():
                # 创建彩色占位符
                pixmap = QPixmap(self.icon_size)
                color = QColor(255, 0, 0) if country == "cn" else QColor(0, 0, 255)
                pixmap.fill(color)
                icon = QIcon(pixmap)

            self.flag_icons[country] = icon

        option.icon = self.flag_icons[country]
        option.iconSize = self.icon_size  # 明确设置图标显示尺寸
        option.text = ip_address
        option.displayAlignment = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
        option.features |= QStyleOptionViewItem.ViewItemFeature.HasDecoration  # 确保显示图标

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:
        base_size = super().sizeHint(option, index)
        return QSize(base_size.width(), max(base_size.height(), self.icon_size.height() + 4))

# 移除ANSI转义码的正则表达式
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[mK]')
def some_function(data):
    """ 记录日志  """
    logger.info(data)

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


import geoip2.database

_geoip_reader = None
_xdb_searcher = None
_xdb_lock_init = False


def _get_geoip_reader(db_path='lib/GeoLite2-City.mmdb'):
    global _geoip_reader
    if _geoip_reader is None:
        _geoip_reader = geoip2.database.Reader(db_path)
    return _geoip_reader


def geoip_to_ip2region_style(ip, db_path='lib/GeoLite2-City.mmdb'):
    try:
        reader = _get_geoip_reader(db_path)
        response = reader.city(ip)

        # 获取各字段（空值替换为 ""）
        country = response.country.name or ""
        region = response.subdivisions.most_specific.name if response.subdivisions else ""
        city = response.city.name if response.city else ""
        isp = response.traits.isp or ""

        # 拼接字段并过滤空值
        fields = [country, region, city, isp]
        fields = [f for f in fields if f]  # 移除空字符串
        region_str = "-".join(fields) if fields else "Unknown"

        return f"{ip}：{region_str}"
    except Exception as e:
        return f"{ip}：Error ({e})"


def _get_xdb_searcher(db_path="lib/ip2region.xdb"):
    """复用 xdb searcher，避免每个 IP 重新 loadVectorIndex（极慢）。"""
    global _xdb_searcher, _xdb_lock_init
    if _xdb_searcher is None:
        vi = XdbSearcher.loadVectorIndexFromFile(dbfile=db_path)
        _xdb_searcher = XdbSearcher(dbfile=db_path, vectorIndex=vi)
        _xdb_lock_init = True
    return _xdb_searcher


def ip2region_IP_query(ip):
    """ ip地址查询 """
    try:
        searcher = _get_xdb_searcher()
        region_str = searcher.search(ip)
    except Exception:
        region_str = ip
    # 去掉值为 "0" 的字段
    fields = region_str.split('|')
    fields = [field for field in fields if field != "0" and field.strip()]
    region_str = "-".join(fields)

    return f"{ip}：{region_str}"


def Offline_IP_query(ip):
    """ ip地址查询 """
    if "en" in ui_config['language']:
        return geoip_to_ip2region_style(ip)
    else:
        return ip2region_IP_query(ip)




def calculate_global_stats(url_count):
    """计算全局统计数据"""
    global_stats = {
        'request_total': 0,
        'danger_total': 0,
        'total_unique_ips': set(),
        'total_unique_uris': set(),
        'total_unique_status_code': set()
    }

    for path, data in url_count['data'].items():
        global_stats['request_total'] += data['count']
        global_stats['total_unique_uris'].add(path)

        for danger in data['danger']:
            if danger != "未检测到安全威胁":
                global_stats['danger_total'] += data['danger'][danger]

        for ip_info, ip_data in data['source_ips'].items():
            global_stats['total_unique_ips'].add(ip_info)
            for status_code in ip_data['status_codes']['data']:
                global_stats['total_unique_status_code'].add(status_code)

    # 转换集合为计数
    global_stats['total_unique_ips'] = len(global_stats['total_unique_ips'])
    global_stats['total_unique_uris'] = len(global_stats['total_unique_uris'])
    global_stats['total_unique_status_code'] = len(global_stats['total_unique_status_code'])

    url_count['_global_stats'] = global_stats

def extract_defaultdicts(obj):
    """递归转换所有 defaultdict 为普通 dict"""
    if isinstance(obj, defaultdict):
        return {k: extract_defaultdicts(v) for k, v in obj.items()}
    elif isinstance(obj, dict):
        return {k: extract_defaultdicts(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [extract_defaultdicts(v) for v in obj]
    else:
        return obj  # 基础类型直接返回
def count_lines(file_path):
    """ 快速计算当前文件有多少行 """
    line_count = 0
    with open(file_path, 'rb') as f:
        while True:
            block = f.read(1024 * 1024)
            if not block:
                break
            line_count += block.count(b'\n')
    return line_count


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
        with open("config.yaml", 'r', encoding='utf-8') as file:
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


def Searchresults(content, file_name):
    """ 写入文件 """
    try:
        with open(file_name, 'a', encoding='utf-8') as file:
            file.write(content + '\n')
    except Exception as e:
        logger.info(e)
def custom_output(content):
    """ 自定义输出，这样统一好管理 """
    from output_filtering import Specify_save
    if Specify_save:
        print(content)
        Searchresults(content,Specify_save)
    else:
        print(content)
if __name__ == '__main__':
    a=""
    print(Offline_IP_query("185.224.128.52"))
