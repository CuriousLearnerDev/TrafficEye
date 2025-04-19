"""
模块功能: 处理会话数据（如存储、整理 HTTP 请求/响应）
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-04-14
"""
import json
import os


import Godzilla
import module
from urllib.parse import urlparse
from custom_extension import data_processing



def operational_record_keeping(time_item, action_item, file_item, status_item):
    save_path = "history/trafficeye_data.json"
    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    # 封装成字符串形式
    record = [
        time_item.text(),
        action_item.text(),
        file_item.text(),
        status_item.text()
    ]

    # 读取原始数据
    if os.path.exists(save_path):
        with open(save_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
    else:
        data = {}

    recent = data.get("recent", [])
    recent.append(record)

    # 保持最近100条
    recent = recent[-100:]

    # 写回文件
    data["recent"] = recent
    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return time_item, action_item, file_item, status_item
#




def sroom_session(method=None,full_uri=None, cleaned_headers=None, decoded_str=None, http_type=None,response_code=None):
    """ 整理会话数据 """
    result={
            http_type: {
            'method':method,
            'request_url': full_uri,
            'uri': urlparse(full_uri).path,
            'headers': cleaned_headers,
            'http_byte': decoded_str
            }
            }
    if http_type=="Request":
        # 用户自定义
        data_processing.request_data(full_uri,urlparse(full_uri).path,cleaned_headers,decoded_str)

        # 安全检测
        #modsec_crs.request_data(result)

    elif http_type=="Response":
        # 用户自定义
        data_processing.response_data(response_code,cleaned_headers,decoded_str)

        # 安全检测
        #modsec_crs.response_data(result)
    return result

def Abnormal_flow_detection(uri, session_data):
    """ 检测异常流量 """
    if Godzilla.check_ghost_shell_traffic(session_data):
        print(f"⚠️ 可能的哥斯拉 Webshell 连接 -  {uri}")
