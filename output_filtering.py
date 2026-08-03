"""
模块功能: 输出过滤模块：过滤请求和响应的输出，根据规则筛选需要的信息并展示
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-05-05
"""
import module

Specify_save=None
request_replay=None # 用于重放验证


def get_address_info(http_data):
    """
    获取请求的地址信息，支持 X-Forwarded-For 和 IP 源地址
    """
    if http_data['http_type']=="Response":
        address_information = f"\n响应的内容：🔗{http_data['url']}\n{'=' * 50}"
        return address_information
    if 'x_forwarded_for' in http_data['headers']:
        ip=http_data['headers']['x_forwarded_for'].split(',')[0].strip()
        return f"\nX-Forwarded-For: {ip}\n请求地址: 🔗{http_data['url']}\n{'=' * 50}"
    elif http_data['ip']:
        ip=http_data['ip']
        return f"\n包头中的源IP地址: {ip}\n请求地址: 🔗{http_data['url']}\n{'=' * 50}"
    else:
        return f"\n请求的内容：🔗{http_data['url']}\n{'=' * 50}"

def complete_data(http_data,show_body=None):
    headers = ""
    """ 获取完整的http请求 """
    if http_data['http_type'] == "Request":
        first_line = f"{http_data['method']} {http_data['uri']} {http_data['http_version']}"
    else:
        first_line = f"{http_data['http_version']} {http_data['response_code']} {http_data['response_phrase']}"
    if http_data['headers']:
        headers = "\n".join([f"{key}: {value}" for key, value in http_data['headers'].items()])
    try:
        if show_body:
            file_data = http_data['file_data']
        else:
            file_data = bytes.fromhex(http_data['file_data'])
    except ValueError as e:
        file_data = http_data['file_data']
    return f"{first_line}\n{headers}\n\n{file_data}"


def visual_output(http_data,show_body):
    if http_data['http_type']=="Request":
        data=complete_data(http_data,show_body)
        output_content=f"会话：{http_data['stream_id']}{get_address_info(http_data)}\n{data}\n"

        return output_content
    else:
        data = complete_data(http_data, show_body)
        output_content = f"会话：{http_data['stream_id']}{get_address_info(http_data)}\n{data}\n"
        return output_content

