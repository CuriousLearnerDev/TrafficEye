# -*- coding: utf-8 -*-
"""天眼类 CSV/TSV 表格导入：自动映射列 -> url_stats 结构。"""

from __future__ import annotations

import csv
import io
import os
import re
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# 目标字段 -> 候选表头（小写比较）
COLUMN_ALIASES = {
    "ip": [
        "源ip", "源地址", "客户端ip", "客户ip", "sip", "src_ip", "srcip", "client_ip",
        "remote_addr", "ip", "源 IP", "攻击ip", "发起ip",
    ],
    "path": [
        "url", "uri", "请求uri", "请求url", "访问url", "路径", "path", "request_uri",
        "request url", "完整url", "目标url", "请求路径",
    ],
    "method": [
        "方法", "请求方法", "method", "http方法", "http_method", "动词",
    ],
    "status": [
        "状态码", "状态", "status", "status_code", "code", "响应码", "http状态码",
    ],
    "time": [
        "时间", "访问时间", "请求时间", "发生时间", "timestamp", "datetime", "date",
        "开始时间", "time",
    ],
    "ua": [
        "ua", "user-agent", "user_agent", "用户代理", "浏览器",
    ],
    "host": [
        "host", "域名", "主机", "目标主机", "目的域名", "站点",
    ],
}


def _norm_header(h: str) -> str:
    h = (h or "").strip().lower().replace("\ufeff", "")
    h = re.sub(r"\s+", "", h)
    return h


def _alias_map() -> Dict[str, str]:
    m = {}
    for field, aliases in COLUMN_ALIASES.items():
        for a in aliases:
            m[_norm_header(a)] = field
    return m


def detect_delimiter(sample: str) -> str:
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t|;")
        return dialect.delimiter
    except Exception:
        if sample.count("\t") >= sample.count(","):
            return "\t"
        return ","


def read_table_headers(file_path: str) -> Tuple[List[str], str, List[dict]]:
    """返回 (headers, delimiter, preview_rows[<=5])."""
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        raw = f.read(65536)
    delim = detect_delimiter(raw.splitlines()[0] if raw else ",")
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        reader = csv.DictReader(f, delimiter=delim)
        headers = list(reader.fieldnames or [])
        preview = []
        for i, row in enumerate(reader):
            if i >= 5:
                break
            preview.append(dict(row))
    return headers, delim, preview


def auto_map_columns(headers: List[str]) -> Dict[str, Optional[str]]:
    """field -> header name (original) or None."""
    aliases = _alias_map()
    mapping = {k: None for k in COLUMN_ALIASES}
    used = set()
    for h in headers:
        key = aliases.get(_norm_header(h))
        if key and mapping[key] is None and h not in used:
            mapping[key] = h
            used.add(h)
    return mapping


def mapping_score(mapping: Dict[str, Optional[str]]) -> int:
    # 至少要有 path 或 host，以及最好有 ip
    score = 0
    if mapping.get("path"):
        score += 3
    if mapping.get("ip"):
        score += 2
    if mapping.get("method"):
        score += 1
    if mapping.get("status"):
        score += 1
    return score


def _cell(row: dict, header: Optional[str]) -> str:
    if not header:
        return ""
    v = row.get(header)
    if v is None:
        return ""
    return str(v).strip()


def rows_to_url_stats(rows: List[dict], mapping: Dict[str, Optional[str]]) -> dict:
    """转为与现有分析兼容的 url_stats 结构。"""
    url_count = defaultdict(lambda: {
        "count": 0,
        "danger_count": 0,
        "source_ips": defaultdict(lambda: {
            "count": 0,
            "methods": defaultdict(int),
            "status_codes": defaultdict(int),
            "UA": defaultdict(int),
            "request_time": defaultdict(int),
            "danger": [],
            "ipPositioning": "",
        }),
    })

    for row in rows:
        path = _cell(row, mapping.get("path"))
        host = _cell(row, mapping.get("host"))
        if not path and host:
            path = f"http://{host}/"
        if not path:
            continue
        # 若 path 是完整 URL 且无 host，保持
        ip = _cell(row, mapping.get("ip")) or "0.0.0.0"
        method = _cell(row, mapping.get("method")) or "-"
        status = _cell(row, mapping.get("status")) or "-"
        ua = _cell(row, mapping.get("ua")) or ""
        t = _cell(row, mapping.get("time")) or ""

        url_count[path]["count"] += 1
        ip_stats = url_count[path]["source_ips"][ip]
        ip_stats["count"] += 1
        ip_stats["methods"][method] += 1
        ip_stats["status_codes"][status] += 1
        if ua:
            ip_stats["UA"][ua] += 1
        if t:
            ip_stats["request_time"][t] += 1

    # 转普通 dict
    data = {}
    total_ips = set()
    total_uris = set()
    total_status = set()
    request_total = 0
    for uri, stats in url_count.items():
        total_uris.add(uri)
        request_total += stats["count"]
        src = {}
        for ip, ip_s in stats["source_ips"].items():
            total_ips.add(ip)
            total_status.update(ip_s["status_codes"].keys())
            src[ip] = {
                "count": ip_s["count"],
                "methods": dict(ip_s["methods"]),
                "status_codes": dict(ip_s["status_codes"]),
                "UA": dict(ip_s["UA"]),
                "request_time": dict(ip_s["request_time"]),
                "danger": list(ip_s["danger"]),
                "ipPositioning": ip_s.get("ipPositioning", ""),
            }
        data[uri] = {
            "count": stats["count"],
            "danger_count": stats["danger_count"],
            "source_ips": src,
        }

    return {
        "data": data,
        "_global_stats": {
            "request_total": request_total,
            "danger_total": 0,
            "total_unique_ips": len(total_ips),
            "total_unique_uris": len(total_uris),
            "total_unique_status_code": len(total_status),
        },
        "_import_meta": {"source": "table_csv", "mapping": mapping},
    }


def import_table_file(file_path: str, mapping: Optional[Dict[str, Optional[str]]] = None) -> Tuple[dict, Dict[str, Optional[str]], List[str]]:
    """
    导入 CSV/TSV。
    返回 (url_stats, mapping_used, headers)
    """
    headers, delim, _ = read_table_headers(file_path)
    if mapping is None:
        mapping = auto_map_columns(headers)

    rows = []
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        reader = csv.DictReader(f, delimiter=delim)
        for row in reader:
            rows.append(dict(row))

    stats = rows_to_url_stats(rows, mapping)
    return stats, mapping, headers


def extract_dns_with_tshark(pcap_path: str, tshark_bin: str = None) -> Optional[dict]:
    """Python 侧 DNS 回退抽取（Go 未产出 dns_result_path 时用）。"""
    import json
    import subprocess
    import shutil
    from collections import defaultdict

    bin_path = tshark_bin or shutil.which("tshark") or shutil.which("tshark.exe")
    lib_win = os.path.join(os.getcwd(), "lib", "tshark.exe")
    if not bin_path and os.path.isfile(lib_win):
        bin_path = lib_win
    if not bin_path:
        return None

    def run_fields(display_filter, fields):
        args = [bin_path, "-r", pcap_path, "-T", "fields", "-Y", display_filter]
        for f in fields:
            args.extend(["-e", f])
        args.extend(["-E", "separator=|", "-E", "occurrence=f"])
        try:
            out = subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=600)
            return out.decode("utf-8", errors="ignore").splitlines()
        except Exception:
            return []

    agg = {}
    for line in run_fields("dns && dns.flags.response == 0",
                           ["frame.time", "ip.src", "ip.dst", "dns.qry.name", "dns.qry.type"]):
        parts = (line.split("|") + [""] * 5)[:5]
        name = parts[3].strip().rstrip(".")
        if not name:
            continue
        item = agg.setdefault(name, {
            "domain": name, "count": 0, "types": defaultdict(int),
            "src_ips": defaultdict(int), "dst_ips": defaultdict(int),
            "answers": defaultdict(int), "last_time": "",
        })
        item["count"] += 1
        item["types"][parts[4] or "?"] += 1
        if parts[1]:
            item["src_ips"][parts[1]] += 1
        if parts[2]:
            item["dst_ips"][parts[2]] += 1
        item["last_time"] = parts[0]

    for line in run_fields("dns && dns.flags.response == 1",
                           ["dns.qry.name", "dns.a", "dns.aaaa"]):
        parts = (line.split("|") + [""] * 3)[:3]
        name = parts[0].strip().rstrip(".")
        if not name:
            continue
        item = agg.setdefault(name, {
            "domain": name, "count": 0, "types": defaultdict(int),
            "src_ips": defaultdict(int), "dst_ips": defaultdict(int),
            "answers": defaultdict(int), "last_time": "",
        })
        for field in parts[1:]:
            for ans in field.split(","):
                ans = ans.strip()
                if ans:
                    item["answers"][ans] += 1

    queries = []
    total = 0
    for name, item in agg.items():
        total += item["count"]
        queries.append({
            "domain": item["domain"],
            "count": item["count"],
            "types": dict(item["types"]),
            "src_ips": dict(item["src_ips"]),
            "dst_ips": dict(item["dst_ips"]),
            "answers": dict(item["answers"]),
            "last_time": item["last_time"],
        })
    queries.sort(key=lambda x: x["count"], reverse=True)
    return {
        "queries": queries,
        "total_queries": total,
        "unique_domains": len(queries),
    }
