## 目前还在研发阶段。。


### 工具介绍

该工具的主要目标是对hw蓝队的网络流量进行详细分析，识别潜在的安全威胁，特别是针对Web应用的攻击（如SQL注入、XSS、Webshell等），它通过模块化设计让用户能够根据需要选择和定制不同的功能，适用于安全研究人员、渗透测试人员和网络管理员等专业人士

## 截止2025年04月08日界面情况

![image-20250408174822199](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250408174822199.png)

## 工具架构

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/2025-04-04_22-37.png)





### 目前进度

截止到04月04号、模块开发情况

```
├── core_processing.py    # 核心处理模块：处理 HTTP 请求/响应数据的解析和转换
├── custom_extension/     
│   ├── data_processing.py  # 自定义数据处理模块：用于处理特殊流量数据或定制的数据解析
├── Godzilla.py           # 特殊流量检测模块：检测异常流量、恶意流量或 Webshell 相关的行为
├── lib/                 
│   └── cmdline.py        # 命令行接口模块：提供与程序交互的命令行工具
├── modsec/               
│   ├── modsec_crs.py     # ModSecurity集成模块：基于OWASP CRS规则进行流量检测
│   ├── rules/            
│   │   ├── APPLICATION-ATTACK-LFI.conf   # 本地文件包含攻击(LFI)检测规则
│   │   ├── REQUEST-901-INITIALIZATION.conf # 请求初始化规则
│   │   ├── REQUEST-931-APPLICATION-ATTACK-RFI.conf # 远程文件包含攻击(RFI)检测规则
│   │   ├── REQUEST-932-APPLICATION-ATTACK-RCE.conf # 远程代码执行攻击(RCE)规则
│   │   ├── REQUEST-942-APPLICATION-ATTACK-SQLI.conf # SQL注入攻击(SQLi)规则
│   │   ├── unix-shell.data  # Unix Shell命令数据，检测恶意命令
│   │   └── windows-powershell-commands.data # Windows PowerShell命令数据，检测恶意命令
│   ├── rules_APPLICATION_ATTACK_LFI.py # LFI攻击规则处理脚本
│   ├── rules_APPLICATION_ATTACK_RCE.py # RCE攻击规则处理脚本
│   ├── rules_APPLICATION_ATTACK_RFI.py # RFI攻击规则处理脚本
│   └── rules_APPLICATION_ATTACK_SQLI.py # SQLi攻击规则处理脚本
├── module.py             # 共享模块：存放公共函数或类，可以被多个模块复用
├── replay_request.py     # 流量重放模块：用于复现捕获的流量，模拟攻击过程或漏洞验证
├── rule_filtering.py     # 规则过滤模块：根据给定的过滤条件筛选和匹配HTTP流量数据
├── session_utils.py      # 会话管理工具：整理、存储和排序HTTP请求/响应的会话数据
└── url_statistics.py     # URL统计模块：对URL的访问频次、状态码等进行统计和分析
```



