import re
from typing import Dict, List
from urllib.parse import unquote  # 新增：用于 URL 解码


class ModSecRuleParser:
    def __init__(self):
        self.rules = []
        self.operators = {
            "@rx": self._match_regex,
            "@contains": self._match_contains,
            "@streq": self._match_exact,
        }

    def load_rules(self, rule_file: str):
        try:
            with open(rule_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("SecRule"):
                        self._parse_sec_rule(line)
            print(f"成功加载 {len(self.rules)} 条规则")
        except FileNotFoundError:
            print(f"错误：规则文件 {rule_file} 不存在")

    def _parse_sec_rule(self, rule_line: str):
        parts = re.split(r'\s+"', rule_line)
        if len(parts) < 3:
            return

        variables = parts[0].split()[1].split("|")
        op_pattern = parts[1].split()
        operator = op_pattern[0]
        pattern = " ".join(op_pattern[1:]).strip('"')
        actions = {}

        for item in parts[2].split(","):
            if ":" in item:
                key, val = item.split(":", 1)
                actions[key] = val.strip('"')

        self.rules.append({
            "variables": variables,
            "operator": operator,
            "pattern": pattern,
            "actions": actions
        })

    def match_request(self, method: str, uri: str, headers: Dict, body: str) -> List[Dict]:
        alerts = []
        for rule in self.rules:
            for var in rule["variables"]:
                target_data = None
                if var == "ARGS":
                    target_data = body
                    if "?" in uri:
                        query = unquote(uri.split("?")[1])
                        target_data = query if not target_data else f"{query}&{target_data}"
                elif var == "REQUEST_HEADERS":
                    target_data = str(headers)
                elif var == "REQUEST_URI":
                    target_data = unquote(uri)  # 解码后的 URI
                elif var == "REQUEST_URI_RAW":
                    target_data = uri  # 原始 URI（未解码）

                if target_data and self._match_rule(rule, target_data):
                    alerts.append(rule["actions"])
        return alerts

    def _match_rule(self, rule: Dict, data: str) -> bool:
        op_func = self.operators.get(rule["operator"])
        if op_func:
            matched = op_func(data, rule["pattern"])
            if matched:
                print(f"[DEBUG] 规则匹配: {rule['id']} | 变量: {rule['variables']} | 数据: {data[:50]}...")
            return matched
        return False

    def _match_regex(self, data: str, pattern: str) -> bool:
        try:
            return bool(re.search(pattern, data, re.IGNORECASE))
        except re.error:
            print(f"警告：无效的正则表达式 '{pattern}'")
            return False

    def _match_contains(self, data: str, pattern: str) -> bool:
        return pattern.lower() in data.lower()

    def _match_exact(self, data: str, pattern: str) -> bool:
        return data == pattern