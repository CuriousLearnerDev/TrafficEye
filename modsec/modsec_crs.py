import re

# 假设这是要读取的 .conf 文件路径和 http.log 文件路径
conf_file_path = 'rules/APPLICATION-ATTACK-LFI.conf'



def extract_rules_from_conf(file_path):
    """ 提取正则表达式规则的函数 """
    rules = []
    with open(file_path, 'r') as file:
        content = file.read()
    # 使用正则表达式提取所有 SecRule 的正则表达式部分
    pattern = r'@rx\s*(\S.*?)(?=\s*"|$)'  # 提取 "@rx" 后面的正则表达式
    matches = re.findall(pattern, content)
    rules.extend(matches)

    return rules


def detect_malicious_traffic(log_file_path, rules):
    """ 应用规则来检测恶意流量 """
    with open(log_file_path, 'r') as file:
        log_lines = file.readlines()  # 逐行读取日志文件
    # 遍历所有规则并检查每一行是否有匹配的恶意流量
    for rule in rules:
        for line in log_lines:
            if re.search(rule, line):  # 如果匹配到规则
                print(f"检测到恶意流量，匹配规则：{rule}")
                print(f"匹配的日志行：{line.strip()}")  # 输出匹配的日志行


# 主函数
def main():
    rules = extract_rules_from_conf(conf_file_path)  # 提取规则
    if rules:
        print(f"提取到 {len(rules)} 条规则，开始检测日志...")
        detect_malicious_traffic(log_file_path, rules)  # 检测恶意流量
    else:
        print("没有提取到有效规则")


# 调用主函数
main()
