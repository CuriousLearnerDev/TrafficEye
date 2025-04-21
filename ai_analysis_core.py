"""
模块功能: AI分析的处理工作
作者: W啥都学
创建日期: 2025-03-20
修改时间：2025-04-21
"""


from urllib.parse import unquote

def prepare_ai_analysis_data(data,analysis_selection=None):
    """准备要分析的数据"""
    if "log" in data["request"]:
        uri_s=prepare_ai_analysis_data_log(data["request"]["log"])
        conversational_Statements=[]
        for uri_l in uri_s:
            conversational_Statements.append(build_prompt_log(uri_l))
        return "log",conversational_Statements
    else:
        all_data_list=[]
        for all_data in data["request"]["all"]:
            all_data_list.append({
                "uri":all_data['uri'],
                "method":all_data['method'],
                "headers":all_data['headers'],
                "request_body":all_data['file_data']
            })
        conversational_Statements=prepare_ai_analysis_data_all(all_data_list,analysis_selection)
        return "all", conversational_Statements
def build_base_prompt():
    """构建基础的分析提示"""
    return """你是一个专业的网络安全分析师。请分析以下HTTP流量数据，识别潜在的安全威胁和异常行为。

分析要求:
1. 重点关注SQL注入、XSS、CSRF、路径遍历、命令注入等常见Web攻击
2. 分析异常请求参数和URL结构
5. 使用中文回复，简明扼要

流量数据:
    """
def prepare_ai_analysis_data_all(data,analysis_selection):
    """构建分析提示"""
    uri_s=[]
    result = []
    for stats in data:
        prompt = build_base_prompt()
        if analysis_selection['choose_url']:
            uri_s.append(unquote(stats['uri']))
            prompt += f"- URI: {unquote(stats['uri'])}\n"
        if analysis_selection['choose_headers']:
            prompt += f"- 请求头: {"\n".join([f"{key}: {value}" for key, value in stats['headers'].items()])}\n"
        if stats["request_body"] and analysis_selection['choose_Body']:
            prompt += f"- 请求数据: \n{bytes.fromhex(stats["request_body"]).decode('utf-8', errors='replace')}\n"
        prompt += "\n请分析上述流量数据，指出可疑请求和安全威胁:"
        result.append(prompt)

    if analysis_selection['choose_url'] and not analysis_selection['choose_headers'] and not analysis_selection["choose_Body"]:
        uri_s = prepare_ai_analysis_data_log(list(set(uri_s)))
        conversational_Statements = []
        for uri_l in uri_s:
            conversational_Statements.append(build_prompt_log(uri_l))
        return conversational_Statements

    return result

def build_prompt_log(uri_s):
        """构建分析提示"""
        prompt = build_base_prompt()
        # 添加URL统计信息
        prompt += "\nURI统计:\n"
        for url in uri_s:
            prompt += f"- URI: {unquote(url)}\n"
        prompt += "\n请分析上述流量数据，指出可疑请求和安全威胁:"
        return prompt


def prepare_ai_analysis_data_log(url_s):

    chunk_list = [""]  # 初始化列表，至少包含一个空字符串
    result = []
    current_string = ""  # 初始化为字符串

    for prompt in url_s:
        current_string += prompt  # 拼接字符串

        chunk_list.append(prompt)
        if len(current_string) > 1000:  # 如果当前字符串的长度超过 1000，换到新的字符串
            result.append(chunk_list)  # 将当前的列表 chunk_list 添加到 result 中
            chunk_list = []  # 清空 chunk_list，准备收集下一个字符串
            current_string = ""  # 清空 current_string，重新开始拼接下一个字符串

    # 如果循环结束时 current_string 仍有内容，记得将剩余部分添加到 result 中
    if current_string:
        result.append(chunk_list)


    return result
