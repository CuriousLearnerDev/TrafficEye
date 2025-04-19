import requests


def process_response(response):
    """将响应信息格式化成字符串"""

    # 将响应信息格式化成字符串
    response_str = f"HTTP/1.1 {response.status_code}\n"
    # 添加响应头
    for header, value in response.headers.items():
        response_str += f"{header}: {value}\n"
    # 添加响应体
    response_str += "\n" + response.text
    return response_str


def replay_post_request(url, headers, body,proxies):
    """重放 POST 请求"""
    try:
        response = requests.post(url, headers=headers, data=body, proxies=proxies, verify=False)
        # 将响应信息格式化成字符串
        response_str = f"HTTP/1.1 {response.status_code}\n"
        # 添加响应头
        for header, value in response.headers.items():
            response_str += f"{header}: {value}\n"
        # 添加响应体
        response_str += "\n" + response.text
        return process_response(response)
    except Exception as e:
        return str(e)

def replay_get_request(url, headers,proxies):
    """重放 GET 请求"""
    try:
        response = requests.get(url, headers=headers, proxies=proxies, verify=False)
        return process_response(response)
    except Exception as e:
        return str(e)


def build_send(result,proxies):
    if result['method'] == "GET":
        url = result['url']
        headers = result['headers']
        return replay_get_request(url, headers, proxies)
    elif result['method'] == "POST":
        url = result['url']
        file_data = bytes.fromhex(result['file_data'])
        return replay_post_request(url, result['headers'], file_data, proxies)
