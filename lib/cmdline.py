import argparse
import random


banner_1 = r"""    
      ______           _________      ______         
     /_  __/________ _/ __/ __(_)____/ ____/_  _____ 
      / / / ___/ __ `/ /_/ /_/ / ___/ __/ / / / / _ \
     / / / /  / /_/ / __/ __/ / /__/ /___/ /_/ /  __/
    /_/ /_/   \__,_/_/ /_/ /_/\___/_____/\__, /\___/ 
                                        /____/  
"""


banner_2 = r"""    
            
            +-+-+-+-+-+-+-+-+-+-+
            |T|r|a|f|f|i|c|E|y|e|
            +-+-+-+-+-+-+-+-+-+-+
                    
"""



banner_3 = r"""    
      *   )        (    (                         
    ` )  /((      ))\ ) )\ ) (      (  (      (   
     ( )(_))(  ( /(()/((()/( )\  (  )\ )\ )  ))\  
    (_(_()|()\ )(_))(_))/(_)|(_) )\((_|()/( /((_) 
    |_   _|((_|(_)(_) _(_) _|(_)((_) __)(_)|_))   
      | | | '_/ _` |  _||  _|| / _|| _| || / -_)  
      |_| |_| \__,_|_|  |_|  |_\__||___\_, \___|  
                                       |__/       
"""



banner_4 = r"""    
.------..------..------..------..------..------..------..------..------..------.
|T.--. ||R.--. ||A.--. ||F.--. ||F.--. ||I.--. ||C.--. ||E.--. ||Y.--. ||E.--. |
| :/\: || :(): || (\/) || :(): || :(): || (\/) || :/\: || (\/) || (\/) || (\/) |
| (__) || ()() || :\/: || ()() || ()() || :\/: || :\/: || :\/: || :\/: || :\/: |
| '--'T|| '--'R|| '--'A|| '--'F|| '--'F|| '--'I|| '--'C|| '--'E|| '--'Y|| '--'E|
`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'
"""


def picture_choice():
    i = random.choice(range(4))
    if i == 0:
        return banner_1
    elif i == 1:
        return banner_2
    elif i == 2:
        return banner_3
    elif i == 3:
        return banner_4


def banner():
    tool_name='\033[0;33m工具：流量之眼\033[0m'
    Author='\033[0;33m作者：w啥都学\033[0m'
    github='\033[0;33mgithub项目地址：https://github.com/Zhao-sai-sai/Full-Scanner\033[0m'
    Frame=f'\033[0;33m {"*"*60}\033[0m'
    icon=f"""{picture_choice()}\n{tool_name}\n\n{Author}\n{github}\n{Frame}                              """
    return  icon


def help_h():
    parser = argparse.ArgumentParser(
        description='本程序是一个多功能全流量分析工具，支持图形化和命令行模式。',
        usage='python3  [-i] [要分析的流量文件] [其他参数]',
        formatter_class=argparse.RawTextHelpFormatter)

    # 设置命令行选项
    Choose_cmdline = parser.add_argument_group("\033[0;33m选择模式\033[0m",
                                               "如果不喜欢输入命令那样，可以选择图形化模式或者其他选项。")
    Choose_cmdline.add_argument("-GUI", action="store_true",
                                help="\033[0;34m图形化模式\033[0m：启动图形界面模式，适合不喜欢命令行的用户。")

    # 默认参数
    default = parser.add_argument_group("\033[0;32m全自动化：\033[0m",
                                        "默认会提取所有的 HTTP 请求和响应，并保存输出，统计请求次数和响应次数。")
    default.add_argument("-i", metavar='指定要分析的流量文件', dest='file_name', type=str,help="指定要分析的流量文件。例如：-i traffic.pcap")
    default.add_argument("-it", metavar='指定要分析的流量文件', dest='tshark', type=str,help="该方法会调用系统wireshark的tshark命令拆分数据速度是默认-i大概的100倍。例如：-it traffic.pcap")

    # 可选参数
    Optional = parser.add_argument_group("\033[0;31m可选参数\033[0m","以下是一些可选参数，帮助你更精确地分析流量。")

    # 选项说明
    Optional.add_argument("--search-uri", metavar='[路径]', dest='search_uri', type=str,
                          help="指定搜索的请求路径。\n例如：--search-uri '/api/v2/'")
    Optional.add_argument("--search-all", metavar='[要搜索的内容]', dest='search_all', type=str,
                          help="在所有 HTTP 头部/Body 中搜索关键字。\n例如：--search-all 'User-Agent: Mozilla/5.0'")
    Optional.add_argument("--request-only", metavar='True', dest='To_request', type=str,
                          help="去除请求内容。\n例如：--request-only True")
    Optional.add_argument("--response-only", metavar='True', dest='To_response', type=str,
                          help="去除响应内容。\n例如：--response-only True")
    Optional.add_argument("--output", metavar='文件名', dest='output', type=str,
                          help="输出文件路径。\n例如：--output result.txt")
    Optional.add_argument("--body", metavar='True', dest='byte', type=str,
                          help="将请求响应的内容部分转换为字节流，适用于二进制内容输出。\n例如：--body True")

    Vulnerability_detection_optional = parser.add_argument_group("\033[0;31m漏洞检测可选参数\033[0m",
                                         "用于检测攻击流量")
    Vulnerability_detection_optional.add_argument("-sql", metavar='', dest='sql', type=str,
                                                   help="添加上这个参数可以检测流量里面是否有sql注入攻击。列如：-sql")
    Vulnerability_detection_optional.add_argument("-directory_traversal", metavar='', dest='directory_traversal', type=str,
                                                   help="添加上这个参数可以检测流量里面是否有目录遍历攻击。列如：-directory_traversal")
    Vulnerability_detection_optional.add_argument("-remote_file_contains", metavar='', dest='remote_file_contains', type=str,
                                                   help="添加上这个参数可以检测流量里面是否有远程文件包含攻击。列如：-directory_traversal")
    Vulnerability_detection_optional.add_argument("-rce", metavar='', dest='rce', type=str,
                                                   help="添加上这个参数可以检测流量里面是否有RCE攻击。列如：-rce")
    Request_replay = parser.add_argument_group("\033[0;31m请求重放\033[0m",
                                         "请求重放用于漏洞复现")
    Request_replay.add_argument("--request-replay", metavar='', dest='request_replay', type=str,
                                                   help="请求重放。列如：--request-replay 指定会话号")

    return parser.parse_args()


if __name__ == '__main__':
    print("\033[1;32m欢迎使用流量分析工具！\033[0m")
    help_h()