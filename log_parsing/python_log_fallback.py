# -*- coding: utf-8 -*-
"""本地日志 Python 多格式解析（含通用回退），结果结构与 Go 输出兼容。"""

from __future__ import annotations

import json
import os
import re
import time
from collections import defaultdict

from PyQt6.QtCore import QThread, pyqtSignal


def _init_stats():
    return defaultdict(lambda: {
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
            "sizes": defaultdict(int),
            "frontend": defaultdict(int),
            "backend": defaultdict(int),
        }),
    })


_GENERIC_IP = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")
_GENERIC_REQ = re.compile(r'"(?P<method>[A-Z]{3,10})\s+(?P<path>[^"\s]+)\s+HTTP/[0-9.]+"')
_GENERIC_STATUS = re.compile(r"\s(?P<status>\d{3})\s")
_GENERIC_UA = re.compile(r'"(?P<ua>[^"]*)"\s*$')


def parse_generic_line(line: str):
    m = _GENERIC_REQ.search(line)
    if not m:
        return None
    ip_m = _GENERIC_IP.search(line)
    st_m = _GENERIC_STATUS.search(line)
    ua_m = _GENERIC_UA.search(line)
    return {
        "ip": ip_m.group("ip") if ip_m else "0.0.0.0",
        "path": m.group("path"),
        "method": m.group("method"),
        "status": st_m.group("status") if st_m else "-",
        "ua": ua_m.group("ua") if ua_m else "",
    }


def _bump(url_count, path, ip, method, status, ua="", t=""):
    url_count[path]["count"] += 1
    ip_s = url_count[path]["source_ips"][ip]
    ip_s["count"] += 1
    ip_s["methods"][method] += 1
    ip_s["status_codes"][status] += 1
    if ua:
        ip_s["UA"][ua] += 1
    if t:
        ip_s["request_time"][t] += 1


def _total_count(url_count) -> int:
    return sum(v["count"] for v in url_count.values())


def _to_result(url_count, log_type: str) -> dict:
    data = {}
    total_ips, total_uris, total_status = set(), set(), set()
    request_total = 0
    danger_total = 0
    for uri, stats in url_count.items():
        total_uris.add(uri)
        request_total += stats["count"]
        danger_total += int(stats.get("danger_count") or 0)
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
                "danger": list(ip_s.get("danger") or []),
                "ipPositioning": "",
            }
        data[uri] = {
            "count": stats["count"],
            "danger_count": stats.get("danger_count", 0),
            "source_ips": src,
        }
    return {
        "data": data,
        "_global_stats": {
            "request_total": request_total,
            "danger_total": danger_total,
            "total_unique_ips": len(total_ips),
            "total_unique_uris": len(total_uris),
            "total_unique_status_code": len(total_status),
        },
        "_import_meta": {"source": "python_log_fallback", "log_type": log_type},
    }


def _count_lines_fast(file_path: str) -> int:
    """按字节粗算行数，用于进度；失败则返回 0。"""
    try:
        n = 0
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                n += chunk.count(b"\n")
        return max(n, 1)
    except Exception:
        return 0


def process_log_file_python(file_path: str, optional_parameters_log=None, progress_cb=None) -> dict:
    optional_parameters_log = optional_parameters_log or {"URI_Security_Check": False}
    # 保证缺省键存在，避免 KeyError
    optional_parameters_log.setdefault("URI_Security_Check", False)
    from log_parsing import log_identification

    url_count = _init_stats()
    log_type = log_identification.guess_log_format(file_path) or "unknown"
    total_lines = _count_lines_fast(file_path)
    processed = 0
    last_pct = -1

    def _emit(pct: int):
        nonlocal last_pct
        pct = max(1, min(90, int(pct)))
        if pct != last_pct and progress_cb:
            last_pct = pct
            try:
                progress_cb(pct)
            except Exception:
                pass

    if progress_cb:
        progress_cb(2)

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            processed += 1
            line = raw.strip().replace("＂", '"')
            if not line or line.startswith("#"):
                if total_lines and processed % 2000 == 0:
                    _emit(int(processed * 90 / total_lines))
                continue
            before = _total_count(url_count)
            try:
                if log_type in ["apache_access", "nginx_access", "tomcat_access_log", "f5_healthcheck"]:
                    log_identification.parse_access_line(line, url_count, log_type, optional_parameters_log)
                elif log_type == "json_log":
                    log_identification.parse_json_web_log(line, url_count, optional_parameters_log)
                elif log_type == "haproxy_access":
                    log_identification.parse_haproxy_access_web_log(line, url_count, optional_parameters_log)
                elif log_type == "iis_log":
                    log_identification.parse_iis_web_log(line, url_count, optional_parameters_log)
                else:
                    # common / unknown：先试 common 再 generic
                    log_identification.parse_access_line(line, url_count, "common_web_log", optional_parameters_log)
            except Exception:
                pass
            if _total_count(url_count) == before:
                g = parse_generic_line(line)
                if g:
                    _bump(url_count, g["path"], g["ip"], g["method"], g["status"], g["ua"])

            if total_lines and (processed % 2000 == 0 or processed == total_lines):
                _emit(int(processed * 90 / total_lines))

    if progress_cb:
        progress_cb(92)
    return _to_result(url_count, log_type)


class PythonLogFallbackThread(QThread):
    finished = pyqtSignal(object, str)
    progress_updated = pyqtSignal(int)
    error = pyqtSignal(str)

    def __init__(self, file_path, ai_analysis_starts, optional_parameters_log):
        super().__init__()
        self.file_path = file_path
        self.ai_analysis_starts = ai_analysis_starts
        self.optional_parameters_log = optional_parameters_log or {}

    def run(self):
        try:
            self.progress_updated.emit(1)

            def on_prog(p):
                self.progress_updated.emit(int(p))

            stats = process_log_file_python(
                self.file_path,
                self.optional_parameters_log,
                progress_cb=on_prog,
            )
            self.progress_updated.emit(95)
            os.makedirs("output", exist_ok=True)
            out = os.path.join("output", f"output_py_log_{int(time.time())}.json")
            with open(out, "w", encoding="utf-8") as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)
            self.progress_updated.emit(100)
            self.finished.emit(self.ai_analysis_starts, out)
        except Exception as e:
            self.error.emit(str(e))
