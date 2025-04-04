import requests
import module

# 设置代理
proxies = {
    'http': 'http://127.0.0.1:8080',   # HTTP 代理
    'https': 'http://127.0.0.1:8080',  # HTTPS 代理
}

def replay_post_request(url, headers, body):
    """ 重放 POST 请求 """

    response = requests.post(url, headers=headers, data=body, proxies=proxies)
    print(response)
    #return response

def replay_get_request(url, headers):
    """ 重放 GET 请求 """

    response = requests.get(url, headers=headers, proxies=proxies)
    print(response)

    #return response


def build_send(session_data):

    for i in session_data:
        if not "Request" in i:
            continue
        if i['Request']['method']=="GET":
            headers = i['Request']['headers']
            url=i['Request']['request_url']
            headers_dict = {key: value for key, value in headers.items()}
            replay_get_request(url,headers_dict)
        elif i['Request']['method']=="POST":
            url = i['Request']['request_url']
            headers = i['Request']['headers']
            headers_dict = {key: value for key, value in headers.items()}
            http_byte= i['Request']['http_byte']
            replay_post_request(url,headers_dict,http_byte)

if __name__ == '__main__':
    build_send()