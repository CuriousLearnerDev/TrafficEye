

# 检测哥斯拉 Webshell
def check_ghost_shell_traffic(packets):

    if len(packets)/2 != 3: # 请求会话次数等于三
        return False
    # 获取三个数据包
    request_0 = packets[0]['Request'] # 获取第一个会话请求
    response_0 = packets[1]['Response']  # 获取第一个会话响应请求

    #request_1 = packets[2]['Request'] # 获取第二个会话请求
    response_1 = packets[3]['Response']  # 获取第二个会话响应请求

    request_2 = packets[4]['Request'] # 获取第三个会话请求
    response_2 = packets[5]['Response']  # 获取第三个会话响应请求


    if len(request_0['http_type']) < 40000: # 判断第一个数据包的部分大于40000
        return False
    if len(response_0['http_type']) != 0: # 判断第一个数据包响应内容是 0
        return False
    if len(response_1['http_type']) != 64: # 判断第二个响应数据字段是长度为64个字节
        return False
    response_data = response_1['http_type']
    part1 = response_data[:16]  # 前16字节
    part2 = response_data[16:48]  # 中间32字节
    part3 = response_data[48:]  # 后16字节

    # 判断第三个请求包是否有相似的特征
    if response_2['http_type'][:16] != part1 and  response_2['http_type'][-16:] !=part3:
        return False

    # 检查请求头中的Accept字段
    if not ("Accept" in request_2['headers'] and "*/*;q=0.8" in request_2['headers']['Accept']):
        return False

    if not ';' in request_2['headers']['Cookie'][-1:]: # 判断Cookie字段最后一个;
        return False

    return True


def core_processing_request(pkt):
    """ 提取请求数据 """
    try:
        request_info = {
            "method": pkt.http.get("Request Method", ""),
            "uri": pkt.http.get("Request URI", ""),
            "content_length": int(pkt.http.get("Content-Length", "0")),
            "accept": pkt.http.get("Accept", ""),
            "cookie": pkt.http.get("Cookie", ""),
        }
        return request_info
    except Exception as e:
        print(f"请求处理错误: {e}")
        return None

def core_processing_response(pkt):
    """ 提取响应数据 """
    try:
        response_info = {
            "code": pkt.http.get("Response Code", ""),
            "content_length": int(pkt.http.get("Content-Length", "0")),
            "body": getattr(pkt.http, "file_data", ""),
            "set_cookie": pkt.http.get("Set-Cookie", ""),
        }
        print(response_info)
        return response_info
    except Exception as e:
        print(f"响应处理错误: {e}")
        return None