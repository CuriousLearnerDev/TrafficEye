import requests
import csv
import time
from datetime import datetime

def query_ip_reputation_batch(apikey, ip_list, output_file, batch_size=100):
    """
    批量查询IP信誉数据并保存为CSV文件
    :param apikey: API密钥
    :param ip_list: IP地址列表
    :param output_file: 输出的CSV文件路径   
    :param batch_size: 每次查询的IP数量（最大支持100个）
    """
    url = "https://api.threatbook.cn/v3/scene/ip_reputation"
    headers = [
        "IP地址", "是否恶意", "可信度", "严重程度", "威胁类型", "标签类别", "标签信息",
        "国家", "省份", "城市", "运营商", "更新时间"
    ]

    results = {}
    
    # 按批次处理
    for i in range(0, len(ip_list), batch_size):
        batch_ips = ip_list[i:i + batch_size]
        params = {
            "apikey": apikey,
            "resource": ",".join(batch_ips),  # 批量查询多个IP
            "lang": "zh"  # 可选，返回中文结果
        }

        

        try:
            response = requests.get(url, params=params)
            data = response.json()


            if data.get("response_code") == 0:
                results.update(data.get("data", {}))
            else:
                print(f"查询失败，错误消息: {data.get('verbose_msg')}")

            # 避免频率限制
            time.sleep(1)
        except Exception as e:
            print(f"请求失败，批次: {batch_ips}, 错误: {e}")
    
    # 写入CSV文件
    with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for ip, record in results.items():
            # 提取核心字段
            is_malicious = record.get("is_malicious", "")  # 是否恶意
            confidence_level = record.get("confidence_level", "")  # 可信度
            severity = record.get("severity", "")  # 严重程度
            judgments = ",".join(record.get("judgments", []))  # 威胁类型

            # 提取标签信息
            tags_classes = record.get("tags_classes", [])
            tags_types = "; ".join([tag.get("tags_type", "") for tag in tags_classes])  # 标签类别
            tags_info = "; ".join(
                [", ".join(tag.get("tags", [])) if isinstance(tag.get("tags", []), list) else str(tag.get("tags", ""))
                 for tag in tags_classes]
            )

            # 提取位置信息
            location = record.get("basic", {}).get("location", {})
            country = location.get("country", "")  # 国家
            province = location.get("province", "")  # 省份
            city = location.get("city", "")  # 城市

            # 提取运营商和更新时间
            carrier = record.get("basic", {}).get("carrier", "")  # 运营商
            update_time = record.get("update_time", "")  # 更新时间

            # 写入行数据
            row = [
                ip,
                is_malicious,
                confidence_level,
                severity,
                judgments,
                tags_types,
                tags_info,
                country,
                province,
                city,
                carrier,
                update_time
            ]
            writer.writerow(row)
            print(f"已处理IP: {ip}")

if __name__ == "__main__":
    # 示例输入
    input_ips = ["8.8.8.8", "1.1.1.1", "192.168.0.1", "172.16.0.1"]  # 待查询的IP列表
    api_key = "******"  # 替换为实际的API Key
    output_csv = f"./ip_reputation_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    # 调用查询函数
    query_ip_reputation_batch(api_key, input_ips, output_csv)
    print(f"查询完成，结果已保存到文件: {output_csv}")
