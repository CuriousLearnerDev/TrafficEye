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

