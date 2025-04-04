"""
模块功能: URL 统计模块：对 URL 的访问频次、状态码等进行统计和分析
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-03-31
"""

from module import custom_output

def print_url_statistics(url_count):
    """ 打印请求地址和状态码统计 """
    from output_filtering import Specify_save
    custom_output("\n请求地址和路径的出现次数（从高到低排序）：")
    sorted_urls = sorted(url_count.items(), key=lambda x: x[1]['count'], reverse=True)
    for url, data in sorted_urls:
        if url:
            output = f"{url}: 请求 {data['count']} 次"
            for status_code, count in data['status_codes'].items():
                output += f"，状态码 {status_code}: {count} 次"
            custom_output(output)
