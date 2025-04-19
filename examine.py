import re
import yaml
from typing import Dict, List, Tuple


class SecurityScanner:
    def __init__(self, config_path: str = 'config.yaml'):
        """
        初始化安全扫描器，加载配置文件

        :param config_path: 配置文件路径
        """
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f)
        self.compiled_rules = self._compile_rules()

    def _compile_rules(self) -> Dict[str, List[Tuple[str, re.Pattern]]]:
        """
        编译所有正则表达式规则

        :return: 编译后的规则字典 {规则类型: [(规则名称, 编译后的正则)]}
        """
        compiled = {}
        for rule_type, rule_data in self.config['safety_testing'].items():
            compiled[rule_type] = []
            for i, rule in enumerate(rule_data['rules']):
                # 对每个规则，关联其所有可能的名称
                rule_names = rule_data['name'] if isinstance(rule_data['name'], list) else [rule_data['name']]
                try:
                    pattern = re.compile(rule, re.IGNORECASE)
                    compiled[rule_type].append((', '.join(rule_names), pattern))
                except re.error as e:
                    print(f"警告: 规则 {rule_type}[{i}] 编译失败: {e}")
        return compiled

    def scan(self, input_str: str) -> Dict[str, List[Dict]]:
        """
        扫描输入字符串，检测所有可能的安全威胁

        :param input_str: 要检测的输入字符串
        :return: 检测结果字典 {规则类型: [匹配结果]}
        """
        results = {}
        for rule_type, rules in self.compiled_rules.items():
            rule_results = []
            for name, pattern in rules:
                matches = pattern.finditer(input_str)
                for match in matches:
                    rule_results.append({
                        'rule_name': name,
                        'matched': match.group(),
                        'position': match.span(),
                        'context': input_str[max(0, match.start() - 20):min(len(input_str), match.end() + 20)]
                    })
            if rule_results:
                results[rule_type] = rule_results
        return results

    def scan_url(self, url: str) -> Dict[str, List[Dict]]:
        """
        专门用于扫描URL的安全检测方法

        :param url: 要检测的URL
        :return: 检测结果
        """
        # 先解码URL编码的字符
        from urllib.parse import unquote
        decoded_url = unquote(url)
        # 将 URL 中的 '+' 替换为空格
        decoded_url = decoded_url.replace('+', ' ')
        print(decoded_url)
        return self.scan(decoded_url)


    def gui_pretty_print_results(self, results: Dict[str, List[Dict]]):
        if not results:
            return "未检测到安全威胁"
        a = ""
        for rule_type, matches in results.items():
            for i, match in enumerate(matches, 1):
                a = a + " | "+match['rule_name']
        Record_risk_type=f"威胁类型: {a}"

        return Record_risk_type
    def pretty_print_results(self, results: Dict[str, List[Dict]]):
        """
        美观地打印检测结果

        :param results: scan()方法返回的结果
        """
        if not results:
            return "未检测到安全威胁"

        a=""
        for rule_type, matches in results.items():

            print(f"\n 威胁类型: {rule_type.upper()}")
            for i, match in enumerate(matches, 1):
                a = a + " | " + match['rule_name']
                print(f"  {i}. 规则: {match['rule_name']}")
                print(f"     匹配内容: {match['matched']}")
                print(f"     位置: {match['position']}")
                print(f"     上下文: ...{match['context']}...")

        Record_risk_type=f"威胁类型: {a}"

        return Record_risk_type
