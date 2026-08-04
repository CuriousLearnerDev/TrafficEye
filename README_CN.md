[English](./README.md) | 中文

### 问题反应群


![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/2025-06-03_11-45.png)

### 📥 运行：

GIhutb下载地址：👉 https://github.com/CuriousLearnerDev/TrafficEye/releases

需要 **Python 3.10+**

```bash
解压下载好的文件
cd TrafficEye
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python mian.py
```

注意如果是linux系统需要执行一下：`chmod +x lib/log_identification`

###  📄 安全检测规则配置

#### 一、语法基础说明

规则在config.yaml里面的**safety_testing**字典里面

用于定义在哪些位置进行匹配检测，可以组合使用，多个位置用 `|` 分隔。

| 标识名                        | 描述                                                |
| ----------------------------- | --------------------------------------------------- |
| `ALL`                         | 匹配所有字段（全局检测）                            |
| `!xxx`                        | 排除 `xxx` 字段不检测                               |
| `URI`                         | URL 整体检测                                        |
| `URI_key`                     | URL 中的键名                                        |
| `URI_value`                   | URL 中的键值                                        |
| `ALL_headers`                 | 所有请求头                                          |
| `headers:xxx`                 | 指定请求头，例如 `headers:cookie`                   |
| `binary`                      | 整体二进制数据                                      |
| `forms_body`                  | 表单整体内容（`application/x-www-form-urlencoded`） |
| `forms_key_body`              | 表单键名                                            |
| `forms_value_body`            | 表单键值                                            |
| `json_body`                   | JSON 整体内容                                       |
| `json_key_body`               | JSON 中的键名                                       |
| `json_value_body`             | JSON 中的值                                         |
| `json_item_body`              | JSON 中列表项                                       |
| `xml_body`                    | XML 整体内容                                        |
| `xml_value_body`              | XML 中的值                                          |
| `xml_attribute_body`          | XML 属性值                                          |
| `multipart_body`              | 上传整体内容                                        |
| `multipart_file_name_body`    | 上传文件名                                          |
| `multipart_content_type_body` | 上传文件类型                                        |
| `multipart_data_body`         | 上传文件的二进制数据                                |

#### 二、示例配置说明

检测规则结构说明

```yaml
风险标识名:
  name:
    - 规则说明名称
  detection_location:
    - 检测目标字段（支持多个，使用 `|` 分隔）
  rules:
    - 正则表达式（可多条）
  severity:
    - 危险等级（高危 / 中危 / 低危）
```

例如：config.yaml文件的

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250706190259281.png)

```yaml
safety_testing:
  Directory_Traversal_Attack:
    name:
      - "路径遍历攻击 (/../) 或 (/.../)有效载荷"
    detection_location:
      - 'URI|forms_key_body|multipart_file_name_body|ALL_headers|xml_value_body|!headers:referer'
    rules:
      - >-
        (?:(?:^|[\x5c/;])\.{2,3}[\x5c/;]|[\x5c/;]\.{2,3}[\x5c/;])
    severity:
      - 中危
```

上面规则检测的位置

检测以下字段内容：

1. **`URI`**
    → 整体 URL 地址，例如：

   ```bash
   http://example.com/download.php?file=../../etc/passwd
   ```

2. **`forms_key_body`**
    → 表单中的键名，比如：

   ```bash
   username=admin&file=../../../etc/shadow
   ↑ 这里是 forms_key_body
   ```

3. **`multipart_file_name_body`**
    → 上传文件时的文件名字段，比如：

   ```kotlin
   Content-Disposition: form-data; name="upload"; filename="../../shell.php"
   ```

4. **`ALL_headers`**
    → 所有 HTTP 请求头，比如 `User-Agent`, `Cookie`, `X-Forwarded-For` 等内容。

5. **`xml_value_body`**
    → XML 数据中的节点值，比如：

   ```xml
   <config>../../etc/passwd</config>
   ```

6. `!headers:referer`

   → 不匹配请求头里面的referer

### 🧪 工具介绍

该工具的主要目标是对护网蓝队、流量分析的网络流量进行详细分析，识别潜在的安全威胁，特别是针对Web应用的攻击（如SQL注入、XSS、Webshell等），它通过模块化设计让用户能够根据需要选择和定制不同的功能，适用于安全研究人员、渗透测试人员和网络管理员等专业人士


## 🧱 工具架构

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/2025-04-04_22-37.png)

## 🚀 工具现有功能

- ✅ `pyshark `

- ✅ 已完成 `tshark` 调用优化，性能大幅提升（解析速度为 `pyshark` 的约 100 倍，原本几分钟的分析现在可在数秒内完成）

- ✅自动识别文件类型进行分析

- ✅可以使用sslkeys.log对HTTPS的数据解密

- 🎯 全流量文件.pcapng、pcap、cap、dns

  - ✅ 支持输出Burp Suite的http数据
  - ✅ 支持输出POST数据部分字节流格式
  - ✅ 支持输出POST数据部原始16进制数据
  - ✅ 支持过滤输出uri、过滤请求和响应

- 📄 LOG文件分析

    - ✅ 支持Apache
    - ✅ 支持Nginx
    - ✅ 支持JSON
    - ✅ 支持F5
    - ✅ 支持HAProxy
    - ✅ 支持Tomcat
    - ✅ 支持IIS

- 🔁 数据重放

    - ✅ 原封不动重放请求
    - ✅ 发送完整二进制请求数据
    - **按会话发送请求：** 请求会按照建立的连接会话顺序发送，例如，在哥斯拉工具中，测试 Webshell 时会自动发送三次请求，这三次请求构成一个会话，输入会话 ID 后可以重放这三次请求，完全复现会话过程

- 📦 二进制文件提取支持：

    \- ✅ 支持：JAVA 序列化二进制数据

    \- ✅ 支持：C# 序列化数据

    \- ✅ 支持：C# Base64 序列化数据

    \- ✅ 支持：JAVA 字节码

    \- ✅ 支持：ZIP 文件

    \- ✅ 支持：7z 文件

    \- ✅ 支持：图片文件 (JPEG, PNG, GIF, BMP, TIFF等)

    \- ✅ 支持：音频文件 (MP3, WAV, FLAC等)

    \- ✅ 支持：视频文件 (MP4, AVI, MOV, MKV等)

    \- ✅ 支持：PDF 文件

    \- ✅ 支持：文档文件 (Word, Excel, PowerPoint, PDF等)

    \- ✅ 支持：压缩包文件 (RAR, TAR, GZ, ARJ等)

    \- ✅ 支持：邮件文件 (MBOX, PST, DBX, EML等)

    \- ✅ 支持：数据库文件 (SQLite, MySQL, MongoDB等)

    \- ✅ 支持：脚本和代码文件 (Python, JavaScript, PHP, Ruby, Java等)

    \- ✅ 支持：二进制文件签名检测（如：特定软件或硬件生成的二进制格式）

- 📊 统计

    - ✅ 支持访问地址整理访问次数
    - ✅ IP地址归属地
    - ✅ 原始IP
    - ✅ 使用的方法
    - ✅ 访问次数

- 🧰 安全检测

    - ✅ 信息泄露/目录遍历
    - ✅ 敏感文件泄露
    - ✅ 目录遍历
    - ✅ 远程文件包含
    - ✅ 本地文件包含
    - ✅ 远程代码执行
    - ✅ SQL注入攻击
    - ✅ 跨站脚本攻击（XSS）

- 🧠 AI检测

    - ✅ 支持指定URI分析，分析优化
    - ✅ 支持自动化批量分析
    - ✅ 支持指定请求头、请求体分析

### 📸 界面预览

仪表盘统计界面

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260803142205710.png)

流量文件二进制数据提取

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260803142233996.png)

全流量接触可以拆分成更容易阅读的格式，方便我们分析流量

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260803142553970.png)

DNS查看

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260803142627218.png)

恶意流量分析

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260803142352207.png)

流量会话重放

- 原封不动重放请求
- 发送完整二进制请求数据
- **按会话发送请求：** 请求会按照建立的连接会话顺序发送，例如，在哥斯拉工具中，测试 Webshell 时会自动发送三次请求，这三次请求构成一个会话，输入会话 ID 后可以重放这三次请求，完全复现会话过程

例如：哥斯拉会话id如下

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250425104909500.png)

我们就可以输入id发送这个请求

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250425104823648.png)

统计分析

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260803142325063.png)

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250706214153311.png)

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250425105343607.png)

正则验证



AI分析

![image-20260803142649234](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260803142649234.png)

### 目前进度

#### 📁 `custom_extension/`

- `data_processing.py`：（研发中）自定义数据处理模块，用于处理特定格式的流量或自定义解析逻辑

#### 📁 `history/`

- `trafficeye_data.json`：历史流量分析数据文件，持久化存储统计信息与分析记录

#### 📁 `ico/`

- 用于存放程序所需的图标资源（如 GUI、输出标识等）

#### 📁 `lib/`

- `cmdline.py`：命令行接口模块，定义程序入口参数与CLI交互逻辑
- `ip2region.xdb`：IP 地理位置数据库文件，用于 IP 归属地识别
- `xdbSearcher.py`：`ip2region` 查询工具类，执行高效 IP 查询
- `bench_test.py` / `iptest.py` / `search_test.py`：调试测试模块，用于测试 IP 匹配、性能基准等功能

#### 📁 `log_parsing/`

- `log_identification.py`：日志识别模块，用于匹配不同格式的日志并选择相应解析器

#### 📁 `modsec/`（研发中）

- `modsec_crs.py`：OWASP ModSecurity Core Rule Set 规则引擎接口模块。
- `rules/`：存储 OWASP CRS 的规则文件与辅助数据（如 LFI/RFI/RCE/SQLi 等攻击规则）
- `rules_APPLICATION_ATTACK_*.py`：用于解析和执行特定攻击规则（LFI、RFI、RCE、SQLi）的脚本

#### 📄 `main.py`

- 主程序入口，用于加载配置、调度模块并启动流量处理流程
#### 📄  `binary_extraction.py`
- 二进制文件识别、二进制文件提取模块
#### 📄 `core_processing.py`

- 核心处理模块，负责 HTTP 请求/响应数据的解析、转换与提取关键字段

#### 📄 `Godzilla.py`

- WebShell 与恶意流量检测模块，针对特殊流量行为进行识别和告警

#### 📄 `examine.py`

- 检查与分析工具模块，用于手动检查、特征提取或测试用途

#### 📄 `module.py`

- 公共模块，存放多个模块共享使用的函数、常量或基础类

#### 📄 `output_filtering.py`

- 过滤输出模块，根据用户定义的过滤条件筛选展示结果

#### 📄 `replay_request.py`

- 请求重放模块，用于重现捕获的请求流量，实现漏洞复现或攻击模拟

#### 📄 `rule_filtering.py`

- 规则筛选模块，结合用户配置对已加载规则进行按需启用、禁用或精细化过滤

#### 📄 `session_utils.py`

- 会话管理工具，用于聚合、排序和提取多个 HTTP 请求/响应构成的会话信息

#### 📄 `url_statistics.py`

- URL 统计模块，分析访问频率、状态码分布等维度的统计数据

#### 📄 `config.yaml`

### 🙏 非常感谢下面的团队和信息安全研究人员建议和意见
- 知攻善防实验室
- 雪娃娃
- ChinaRan404
- 糖糖
- niuᴗu
- 雪娃娃
- 我数挖槽

### 作者公众号

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/qrcode_for_gh_e911bdfdbe01_344.png)

✨随着时间的推移，观星者
[![Stargazers over time](https://starchart.cc/CuriousLearnerDev/TrafficEye.svg?variant=light)](https://starchart.cc/CuriousLearnerDev/TrafficEye)

