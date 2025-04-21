"""
模块功能: 负责二进制文件识别和提取
作者: W啥都学
创建日期: 2025-04-13
修改时间：2025-04-15
"""


import hashlib
import yaml
import os
from typing import List, Optional


def load_signatures(config_path: str, target_types: Optional[List[str]] = None) -> List[dict]:
    """
    从 YAML 配置文件中加载签名信息，并可选地按类型过滤。

    参数:
        config_path: YAML 配置文件的路径
        target_types: 指定要包含的文件类型列表（为 None 表示包含所有启用的签名）

    返回:
        签名字典列表，按 header 长度从长到短排序（匹配更精确的签名）
    """
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    signatures = []
    for sig in config.get('signatures', []):
        if sig.get('enabled', True):
            # 如果指定了 target_types，则只包含匹配的类型
            if target_types is None or sig['type'] in target_types:
                header_len = len(sig['header']) // 2  # 将十六进制字符长度转换为字节数
                signatures.append((header_len, sig))

    # 根据 header 长度从长到短排序（优先匹配更具体的签名）
    signatures.sort(reverse=True, key=lambda x: x[0])
    return [sig for _, sig in signatures]


def identify_file_type(hex_str: str, signatures: list) -> Optional[dict]:
    """
    根据签名信息识别十六进制字符串的文件类型。

    参数:
        hex_str: 输入的十六进制字符串（不区分大小写）
        signatures: 要匹配的签名字典列表

    返回:
        匹配到的签名字典；如果未匹配则返回 None
    """
    hex_str = hex_str.lower()
    for sig in signatures:
        if hex_str.startswith(sig['header'].lower()):
            if 'footer' in sig:
                if hex_str.endswith(sig['footer'].lower()):
                    return sig
            else:
                return sig
    return None


def extract_file(hex_str: str,signatures: list,output_dir: str = ".",url: Optional[str] = None,max_attempts: int = 5) -> dict:
    """
    根据签名信息从十六进制字符串中提取嵌入的文件。

    参数:
        hex_str: 输入的十六进制字符串（不区分大小写）
        signatures: 签名字典列表，用于匹配文件
        output_dir: 提取文件保存的目录
        url: 可选来源 URL，仅作记录用
        max_attempts: 最大提取尝试次数

    返回:
        包含提取结果的字典
    """
    hex_str = hex_str.lower()
    os.makedirs(output_dir, exist_ok=True)

    for sig in signatures:
        header = sig['header'].lower()
        footer = sig.get('footer', '').lower()
        file_type = sig['type']
        max_size = sig.get('max_size', 10 * 1024 * 1024) * 2  # 以十六进制字符为单位

        start = 0
        attempts = 0

        while attempts < max_attempts:
            start = hex_str.find(header, start)
            if start == -1:
                break

            if footer:
                end = hex_str.find(footer, start + len(header))
                if end == -1:
                    break
                end += len(footer)
            else:
                end = start + max_size
                end = min(end, len(hex_str))

            try:
                data = bytes.fromhex(hex_str[start:end])
                file_hash = hashlib.sha256(data).hexdigest()  # 使用更安全的 SHA-256 哈希
                filename = f"{file_hash[:16]}_{start}.{file_type}"
                save_path = os.path.join(output_dir, filename)

                with open(save_path, "wb") as f:
                    f.write(data)

                return {
                    "filename": filename,
                    "filetype": file_type,
                    "size": len(data),
                    "url": url or "N/A",
                    "status": "提取成功",
                    "save_path": save_path,
                    "start": start,
                    "end": end,
                    "signature": sig.get('description', '')
                }

            except Exception as e:
                attempts += 1
                start += len(header)  # 提取失败时向后移动避免死循环

    return {
        "filename": None,
        "filetype": None,
        "size": 0,
        "url": url or "N/A",
        "status": "提取失败",
        "save_path": None,
        "start": None,
        "end": None,
        "signature": None
    }


if __name__ == "__main__":
    import sys
    a=['png']
    config_path = "config.yaml"
    hex_data = "57d97ff7692ff8fa689504e470d0a1a0a0000000d494844520000003000000030080300000060dc09b500000051504c54457d97ff7692ff8fa6ffa7b8ff555e804c505e6476be849eff819bff879fff829cff697fd58ba3ff98acff5c6a9e708af36d85e76070ae9cb0ff50566d4b4e5a494a509fb3ff92a8ffa4b7ff88a1ffaabcffce1e00160000016c49444154785ecd95d99284200c451356f7add799ffffd021607544280b7d98eaf304e8edced180f038c985c01d4e70bf18a89a2238f0fa2d4172a0f929e2ba432959079c95d6ca6075e860c587e9e1d12388846c49142054a9c368a6a9bdb9447b1410f2c3d24bd98f2e7003b9e3cd81fa1503834b4cdd6e951d52e82f8653efc159e82387f78e6626ed265e7c72a0eb77788901fa988392f04160b903559479155cd23306b50f0c10ad2e9bc012012df506d5142d1f38b89b15854ca1c344f563da81696b706368f44f1645be3584dc82de57869af2cd1763dc9d2300686ad91287db5afc40c17cc00a065a52ae84e868308360f207192852a651a8297b0840c584ad4023df20d3e65aeac09567b751f6a8444dca611cb6115fcb3980f1ca6152fb09740b3b24c7bdff515c2715ba809e0d24c73dd386b25988481daa7a2528d71f50f94098d88c0318c7e6d13fd1283543ea50af58db586beb0d40ac17bffaa368bb22feeda3788ef3813f6e9e5e7dea6d61c10000000049454e44ae42608257d97ff7692ff8fa6"  # 放十六进制数据
    output_dir = "./output"

    os.makedirs(output_dir, exist_ok=True)
    signatures = load_signatures(config_path)
    print(signatures)
    #result = extract_file(hex_data, signatures, output_dir,a, url="example.com/sample.hex")

    # if result["status"] == "success":
    #     print(f"""
    #     文件提取成功!
    #     文件名: {result['filename']}
    #     类型: {result['filetype']}
    #     大小: {result['size']} 字节
    #     来源: {result['url']}
    #     保存路径: {result['save_path']}
    #     偏移: {result['start']} - {result['end']}
    #     """)
    # else:
    #     print("未识别到文件或提取失败。")

