# -*- coding: utf-8 -*-
"""从 url_stats 导出访问情报，生成外置 3D 地球 HTML（系统浏览器打开）。"""
from __future__ import annotations

import json
import os
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# 中文/别名 → ECharts world.json 的 name（用于国家填色）
CN_TO_ECHARTS: Dict[str, str] = {
    "中国": "China", "China": "China",
    "香港": "China", "Hong Kong": "China", "澳门": "China", "Macau": "China", "台湾": "China", "Taiwan": "China",
    "美国": "United States", "United States": "United States",
    "日本": "Japan", "Japan": "Japan",
    "韩国": "Korea", "South Korea": "Korea", "Korea": "Korea",
    "朝鲜": "Dem. Rep. Korea", "North Korea": "Dem. Rep. Korea",
    "俄罗斯": "Russia", "Russia": "Russia",
    "英国": "United Kingdom", "United Kingdom": "United Kingdom",
    "德国": "Germany", "Germany": "Germany",
    "法国": "France", "France": "France",
    "意大利": "Italy", "Italy": "Italy",
    "西班牙": "Spain", "Spain": "Spain",
    "荷兰": "Netherlands", "Netherlands": "Netherlands",
    "比利时": "Belgium", "Belgium": "Belgium",
    "瑞典": "Sweden", "Sweden": "Sweden",
    "挪威": "Norway", "Norway": "Norway",
    "芬兰": "Finland", "Finland": "Finland",
    "丹麦": "Denmark", "Denmark": "Denmark",
    "波兰": "Poland", "Poland": "Poland",
    "乌克兰": "Ukraine", "Ukraine": "Ukraine",
    "土耳其": "Turkey", "Turkey": "Turkey",
    "加拿大": "Canada", "Canada": "Canada",
    "巴西": "Brazil", "Brazil": "Brazil",
    "墨西哥": "Mexico", "Mexico": "Mexico",
    "阿根廷": "Argentina", "Argentina": "Argentina",
    "澳大利亚": "Australia", "Australia": "Australia",
    "新西兰": "New Zealand", "New Zealand": "New Zealand",
    "印度": "India", "India": "India",
    "新加坡": "Singapore", "Singapore": "Singapore",
    "马来西亚": "Malaysia", "Malaysia": "Malaysia",
    "印尼": "Indonesia", "印度尼西亚": "Indonesia", "Indonesia": "Indonesia",
    "泰国": "Thailand", "Thailand": "Thailand",
    "越南": "Vietnam", "Vietnam": "Vietnam",
    "菲律宾": "Philippines", "Philippines": "Philippines",
    "缅甸": "Myanmar", "Myanmar": "Myanmar",
    "柬埔寨": "Cambodia", "Cambodia": "Cambodia",
    "老挝": "Lao PDR", "Laos": "Lao PDR",
    "巴基斯坦": "Pakistan", "Pakistan": "Pakistan",
    "孟加拉": "Bangladesh", "孟加拉国": "Bangladesh", "Bangladesh": "Bangladesh",
    "伊朗": "Iran", "Iran": "Iran",
    "伊拉克": "Iraq", "Iraq": "Iraq",
    "以色列": "Israel", "Israel": "Israel",
    "沙特阿拉伯": "Saudi Arabia", "Saudi Arabia": "Saudi Arabia",
    "阿联酋": "United Arab Emirates", "United Arab Emirates": "United Arab Emirates",
    "南非": "South Africa", "South Africa": "South Africa",
    "埃及": "Egypt", "Egypt": "Egypt",
    "尼日利亚": "Nigeria", "Nigeria": "Nigeria",
    "哈萨克斯坦": "Kazakhstan", "Kazakhstan": "Kazakhstan",
    "瑞士": "Switzerland", "Switzerland": "Switzerland",
    "奥地利": "Austria", "Austria": "Austria",
    "葡萄牙": "Portugal", "Portugal": "Portugal",
    "希腊": "Greece", "Greece": "Greece",
    "爱尔兰": "Ireland", "Ireland": "Ireland",
    "捷克": "Czech Rep.", "Czech Republic": "Czech Rep.",
    "罗马尼亚": "Romania", "Romania": "Romania",
    "保加利亚": "Bulgaria", "Bulgaria": "Bulgaria",
    "加纳": "Ghana", "Ghana": "Ghana",
    "摩尔多瓦": "Moldova", "Moldova": "Moldova",
    "拉脱维亚": "Latvia", "Latvia": "Latvia",
    "阿尔巴尼亚": "Albania", "Albania": "Albania",
    "立陶宛": "Lithuania", "Lithuania": "Lithuania",
    "也门": "Yemen", "Yemen": "Yemen",
    "蒙古": "Mongolia", "Mongolia": "Mongolia",
    "黎巴嫩": "Lebanon", "Lebanon": "Lebanon",
    "卢森堡": "Luxembourg", "Luxembourg": "Luxembourg",
    "摩洛哥": "Morocco", "Morocco": "Morocco",
    "厄瓜多尔": "Ecuador", "Ecuador": "Ecuador",
    "尼泊尔": "Nepal", "Nepal": "Nepal",
    "秘鲁": "Peru", "Peru": "Peru",
    "埃塞俄比亚": "Ethiopia", "Ethiopia": "Ethiopia",
    "阿富汗": "Afghanistan", "Afghanistan": "Afghanistan",
    "圣文森特和格林纳丁斯": "St. Vin. and Gren.",
    "白俄罗斯": "Belarus", "Belarus": "Belarus",
    "塞尔维亚": "Serbia", "Serbia": "Serbia",
    "克罗地亚": "Croatia", "Croatia": "Croatia",
    "斯洛伐克": "Slovakia", "Slovakia": "Slovakia",
    "斯洛文尼亚": "Slovenia", "Slovenia": "Slovenia",
    "匈牙利": "Hungary", "Hungary": "Hungary",
    "智利": "Chile", "Chile": "Chile",
    "哥伦比亚": "Colombia", "Colombia": "Colombia",
    "委内瑞拉": "Venezuela", "Venezuela": "Venezuela",
    "古巴": "Cuba", "Cuba": "Cuba",
    "肯尼亚": "Kenya", "Kenya": "Kenya",
    "坦桑尼亚": "Tanzania", "Tanzania": "Tanzania",
    "乌兹别克斯坦": "Uzbekistan", "Uzbekistan": "Uzbekistan",
    "阿塞拜疆": "Azerbaijan", "Azerbaijan": "Azerbaijan",
    "格鲁吉亚": "Georgia", "Georgia": "Georgia",
    "亚美尼亚": "Armenia", "Armenia": "Armenia",
    "叙利亚": "Syria", "Syria": "Syria",
    "约旦": "Jordan", "Jordan": "Jordan",
    "科威特": "Kuwait", "Kuwait": "Kuwait",
    "卡塔尔": "Qatar", "Qatar": "Qatar",
    "阿曼": "Oman", "Oman": "Oman",
    "斯里兰卡": "Sri Lanka", "Sri Lanka": "Sri Lanka",
    "文莱": "Brunei", "Brunei": "Brunei",
    "冰岛": "Iceland", "Iceland": "Iceland",
    "爱沙尼亚": "Estonia", "Estonia": "Estonia",
    "马耳他": "Malta", "Malta": "Malta",
    "塞浦路斯": "Cyprus", "Cyprus": "Cyprus",
    "巴拿马": "Panama", "Panama": "Panama",
    "哥斯达黎加": "Costa Rica", "Costa Rica": "Costa Rica",
    "乌拉圭": "Uruguay", "Uruguay": "Uruguay",
    "巴拉圭": "Paraguay", "Paraguay": "Paraguay",
    "玻利维亚": "Bolivia", "Bolivia": "Bolivia",
    "阿尔及利亚": "Algeria", "Algeria": "Algeria",
    "突尼斯": "Tunisia", "Tunisia": "Tunisia",
    "利比亚": "Libya", "Libya": "Libya",
    "苏丹": "Sudan", "Sudan": "Sudan",
    "安哥拉": "Angola", "Angola": "Angola",
    "刚果": "Congo", "刚果民主共和国": "Dem. Rep. Congo",
    "亚太地区": "", "北美地区": "", "欧洲": "", "内网": "", "未知": "", "Unknown": "",
}

# 国家/地区中心点（经度, 纬度）
COUNTRY_COORDS: Dict[str, Tuple[float, float]] = {
    "中国": (104.195, 35.861), "China": (104.195, 35.861),
    "香港": (114.169, 22.319), "Hong Kong": (114.169, 22.319),
    "澳门": (113.543, 22.199), "Macau": (113.543, 22.199),
    "台湾": (120.961, 23.698), "Taiwan": (120.961, 23.698),
    "美国": (-95.713, 37.090), "United States": (-95.713, 37.090),
    "日本": (138.253, 36.205), "Japan": (138.253, 36.205),
    "韩国": (127.767, 35.908), "South Korea": (127.767, 35.908), "Korea": (127.767, 35.908),
    "朝鲜": (127.510, 40.340), "North Korea": (127.510, 40.340),
    "俄罗斯": (105.319, 61.524), "Russia": (105.319, 61.524),
    "英国": (-3.436, 55.378), "United Kingdom": (-3.436, 55.378),
    "德国": (10.451, 51.166), "Germany": (10.451, 51.166),
    "法国": (2.213, 46.228), "France": (2.213, 46.228),
    "意大利": (12.567, 41.871), "Italy": (12.567, 41.871),
    "西班牙": (-3.749, 40.464), "Spain": (-3.749, 40.464),
    "荷兰": (5.291, 52.133), "Netherlands": (5.291, 52.133),
    "比利时": (4.470, 50.503), "Belgium": (4.470, 50.503),
    "瑞典": (18.643, 60.128), "Sweden": (18.643, 60.128),
    "挪威": (8.469, 60.472), "Norway": (8.469, 60.472),
    "芬兰": (25.748, 61.924), "Finland": (25.748, 61.924),
    "丹麦": (9.502, 56.264), "Denmark": (9.502, 56.264),
    "波兰": (19.145, 51.919), "Poland": (19.145, 51.919),
    "乌克兰": (31.166, 48.379), "Ukraine": (31.166, 48.379),
    "土耳其": (35.243, 38.964), "Turkey": (35.243, 38.964),
    "加拿大": (-106.347, 56.130), "Canada": (-106.347, 56.130),
    "巴西": (-51.925, -14.235), "Brazil": (-51.925, -14.235),
    "墨西哥": (-102.553, 23.635), "Mexico": (-102.553, 23.635),
    "阿根廷": (-63.617, -38.416), "Argentina": (-63.617, -38.416),
    "澳大利亚": (133.775, -25.274), "Australia": (133.775, -25.274),
    "新西兰": (174.886, -40.901), "New Zealand": (174.886, -40.901),
    "印度": (78.963, 20.594), "India": (78.963, 20.594),
    "新加坡": (103.820, 1.352), "Singapore": (103.820, 1.352),
    "马来西亚": (101.975, 4.210), "Malaysia": (101.975, 4.210),
    "印尼": (113.921, -0.789), "印度尼西亚": (113.921, -0.789), "Indonesia": (113.921, -0.789),
    "泰国": (100.993, 15.870), "Thailand": (100.993, 15.870),
    "越南": (108.277, 14.058), "Vietnam": (108.277, 14.058),
    "菲律宾": (121.774, 12.879), "Philippines": (121.774, 12.879),
    "缅甸": (95.956, 21.914), "Myanmar": (95.956, 21.914),
    "柬埔寨": (104.991, 12.566), "Cambodia": (104.991, 12.566),
    "老挝": (102.495, 19.856), "Laos": (102.495, 19.856),
    "巴基斯坦": (69.345, 30.375), "Pakistan": (69.345, 30.375),
    "孟加拉": (90.356, 23.685), "Bangladesh": (90.356, 23.685),
    "伊朗": (53.688, 32.428), "Iran": (53.688, 32.428),
    "伊拉克": (43.679, 33.223), "Iraq": (43.679, 33.223),
    "以色列": (34.851, 31.047), "Israel": (34.851, 31.047),
    "沙特阿拉伯": (45.079, 23.886), "Saudi Arabia": (45.079, 23.886),
    "阿联酋": (53.848, 23.424), "United Arab Emirates": (53.848, 23.424),
    "南非": (22.938, -30.560), "South Africa": (22.938, -30.560),
    "埃及": (30.802, 26.821), "Egypt": (30.802, 26.821),
    "尼日利亚": (8.675, 9.082), "Nigeria": (8.675, 9.082),
    "哈萨克斯坦": (66.924, 48.019), "Kazakhstan": (66.924, 48.019),
    "瑞士": (8.228, 46.818), "Switzerland": (8.228, 46.818),
    "奥地利": (14.550, 47.516), "Austria": (14.550, 47.516),
    "葡萄牙": (-8.224, 39.400), "Portugal": (-8.224, 39.400),
    "希腊": (21.824, 39.074), "Greece": (21.824, 39.074),
    "爱尔兰": (-8.244, 53.413), "Ireland": (-8.244, 53.413),
    "捷克": (15.473, 49.818), "Czech Republic": (15.473, 49.818),
    "罗马尼亚": (24.967, 45.943), "Romania": (24.967, 45.943),
    "保加利亚": (25.485, 42.733), "Bulgaria": (25.485, 42.733),
    "加纳": (-1.023, 7.946), "Ghana": (-1.023, 7.946),
    "摩尔多瓦": (28.370, 47.412), "Moldova": (28.370, 47.412),
    "拉脱维亚": (24.603, 56.880), "Latvia": (24.603, 56.880),
    "阿尔巴尼亚": (20.168, 41.153), "Albania": (20.168, 41.153),
    "立陶宛": (23.881, 55.169), "Lithuania": (23.881, 55.169),
    "也门": (48.516, 15.553), "Yemen": (48.516, 15.553),
    "蒙古": (103.847, 46.863), "Mongolia": (103.847, 46.863),
    "黎巴嫩": (35.862, 33.855), "Lebanon": (35.862, 33.855),
    "卢森堡": (6.130, 49.815), "Luxembourg": (6.130, 49.815),
    "摩洛哥": (-7.093, 31.792), "Morocco": (-7.093, 31.792),
    "厄瓜多尔": (-78.183, -1.831), "Ecuador": (-78.183, -1.831),
    "尼泊尔": (84.124, 28.395), "Nepal": (84.124, 28.395),
    "秘鲁": (-75.015, -9.190), "Peru": (-75.015, -9.190),
    "埃塞俄比亚": (40.490, 9.145), "Ethiopia": (40.490, 9.145),
    "阿富汗": (67.710, 33.939), "Afghanistan": (67.710, 33.939),
    "圣文森特和格林纳丁斯": (-61.200, 13.250),
    "白俄罗斯": (27.953, 53.710),
    "塞尔维亚": (21.006, 44.016),
    "匈牙利": (19.503, 47.162),
    "智利": (-71.543, -35.675),
    "哥伦比亚": (-74.297, 4.571),
    "肯尼亚": (37.906, -0.024),
    "约旦": (36.238, 30.585),
    "斯里兰卡": (80.771, 7.873),
    "爱沙尼亚": (25.014, 58.595),
    "亚太地区": (114.0, 22.0),
    "北美地区": (-100.0, 40.0),
    "内网": (116.407, 39.904),
    "局域网": (116.407, 39.904),
    "本地": (116.407, 39.904),
    "未知": (0.0, 20.0),
    "Unknown": (0.0, 20.0),
}

DEFAULT_TARGET = (116.4074, 39.9042)  # 北京
_IP_SPLIT = re.compile(r"[：:]")


def _extract_url_stats_data(url_stats: Any) -> Dict[str, dict]:
    if not isinstance(url_stats, dict):
        return {}
    skip = {"_global_stats", "filter_applied", "_import_meta"}
    nested = url_stats.get("data") if "data" in url_stats else None
    flat = {
        k: v for k, v in url_stats.items()
        if k not in skip and k != "data" and isinstance(v, dict)
        and ("source_ips" in v or "count" in v)
    }
    if flat:
        return flat
    if isinstance(nested, dict):
        return {k: v for k, v in nested.items() if k not in skip and isinstance(v, dict)}
    return {}


def parse_ip_location(ip_key: str) -> Tuple[str, str, str]:
    """返回 (纯IP, 国家名, 省级名)。省级名为 ECharts 中国地图用短名（如 浙江）。"""
    text = (ip_key or "").strip()
    if not text:
        return "", "未知", ""
    parts = _IP_SPLIT.split(text, maxsplit=1)
    ip = parts[0].strip()
    loc = parts[1].strip() if len(parts) > 1 else ""
    if not loc or loc.lower() in ("unknown", "error", "0"):
        if ip.startswith(("10.", "192.168.", "127.")) or ip.startswith("172."):
            return ip, "内网", ""
        return ip, "未知", ""
    segs = [s.strip() for s in loc.split("-") if s.strip() and s.strip() != "0"]
    if not segs:
        return ip, "未知", ""
    country = segs[0]
    if country in ("0", "内网IP", "局域网", "本机地址", "保留地址"):
        return ip, "内网", ""
    province = ""
    if country in ("中国", "China", "香港", "Hong Kong", "澳门", "Macau", "台湾", "Taiwan"):
        if country in ("香港", "Hong Kong"):
            province = "香港"
        elif country in ("澳门", "Macau"):
            province = "澳门"
        elif country in ("台湾", "Taiwan"):
            province = "台湾"
        elif len(segs) >= 2:
            province = _normalize_province(segs[1])
    return ip, country if country not in ("香港", "Hong Kong", "澳门", "Macau", "台湾", "Taiwan") else "中国", province


def _normalize_province(raw: str) -> str:
    """ip2region 的「浙江省」等 → 地图「浙江」。"""
    if not raw:
        return ""
    s = raw.strip()
    # 直辖市区县仍归到市
    aliases = {
        "北京": "北京", "北京市": "北京",
        "上海": "上海", "上海市": "上海",
        "天津": "天津", "天津市": "天津",
        "重庆": "重庆", "重庆市": "重庆",
        "内蒙古": "内蒙古", "内蒙古自治区": "内蒙古",
        "广西": "广西", "广西壮族自治区": "广西",
        "西藏": "西藏", "西藏自治区": "西藏",
        "宁夏": "宁夏", "宁夏回族自治区": "宁夏",
        "新疆": "新疆", "新疆维吾尔自治区": "新疆",
        "香港": "香港", "香港特别行政区": "香港",
        "澳门": "澳门", "澳门特别行政区": "澳门",
        "台湾": "台湾", "台湾省": "台湾",
    }
    if s in aliases:
        return aliases[s]
    for suffix in ("特别行政区", "壮族自治区", "回族自治区", "维吾尔自治区", "自治区", "省", "市"):
        if s.endswith(suffix) and len(s) > len(suffix):
            s2 = s[: -len(suffix)]
            return aliases.get(s2, s2)
    return s


def _coords_for(country: str) -> Tuple[float, float]:
    if country in COUNTRY_COORDS:
        return COUNTRY_COORDS[country]
    for k, v in COUNTRY_COORDS.items():
        if k in country or country in k:
            return v
    return COUNTRY_COORDS["未知"]


def _map_name_for(country: str) -> str:
    """返回 ECharts world 地图用的英文名；空串表示不着色国家（如亚太地区）。"""
    if country in CN_TO_ECHARTS:
        return CN_TO_ECHARTS[country] or ""
    for k, v in CN_TO_ECHARTS.items():
        if k and (k in country or country in k):
            return v or ""
    return ""


def _danger_count(ip_stats: dict) -> int:
    if not isinstance(ip_stats, dict):
        return 0
    d = ip_stats.get("danger")
    if isinstance(d, list):
        return len([x for x in d if x and x != "未检测到安全威胁"])
    if isinstance(d, dict):
        return sum(int(v or 0) for k, v in d.items() if k and k != "未检测到安全威胁")
    return int(ip_stats.get("danger_count") or 0)


def build_globe_payload(
    url_stats: Any,
    target: Optional[Tuple[float, float]] = None,
    title: str = "TrafficEye 全球访问态势",
) -> dict:
    """聚合国家/IP，生成地球页可用的 JSON。"""
    data = _extract_url_stats_data(url_stats)
    tgt = target or DEFAULT_TARGET
    country_agg: Dict[str, dict] = defaultdict(lambda: {"count": 0, "risk": 0, "ips": set()})
    province_agg: Dict[str, dict] = defaultdict(lambda: {"count": 0, "risk": 0, "ips": set()})
    ip_rows: List[dict] = []

    for _uri, stats in data.items():
        if not isinstance(stats, dict):
            continue
        for ip_key, ip_stats in (stats.get("source_ips") or {}).items():
            if not isinstance(ip_stats, dict):
                continue
            ip, country, province = parse_ip_location(str(ip_key))
            cnt = int(ip_stats.get("count") or 0)
            risk = _danger_count(ip_stats)
            lng, lat = _coords_for(country)
            country_agg[country]["count"] += cnt
            country_agg[country]["risk"] += risk
            if ip:
                country_agg[country]["ips"].add(ip)
            if province:
                province_agg[province]["count"] += cnt
                province_agg[province]["risk"] += risk
                if ip:
                    province_agg[province]["ips"].add(ip)
            ip_rows.append({
                "ip": ip or ip_key,
                "country": country,
                "province": province,
                "count": cnt,
                "risk": risk,
                "lng": lng,
                "lat": lat,
            })

    # 合并同 IP
    ip_merged: Dict[str, dict] = {}
    for row in ip_rows:
        key = row["ip"]
        if key not in ip_merged:
            ip_merged[key] = dict(row)
        else:
            ip_merged[key]["count"] += row["count"]
            ip_merged[key]["risk"] += row["risk"]

    countries = []
    flights = []
    for name, agg in country_agg.items():
        lng, lat = _coords_for(name)
        map_name = _map_name_for(name)
        countries.append({
            "name": name,
            "map_name": map_name,
            "value": int(agg["count"]),
            "risk": int(agg["risk"]),
            "ip_count": len(agg["ips"]),
            "lng": lng,
            "lat": lat,
        })
        if name not in ("未知", "Unknown", "内网", "亚太地区", "北美地区") and agg["count"] > 0:
            # 跳过落在 (0,20) 占位的无效坐标飞线
            if not (abs(lng) < 0.01 and abs(lat - 20.0) < 0.01):
                flights.append({
                    "coords": [[lng, lat], [tgt[0], tgt[1]]],
                    "value": int(agg["count"]),
                    "risk": int(agg["risk"]) > 0,
                    "name": name,
                })

    countries.sort(key=lambda x: x["value"], reverse=True)
    # 地球页只带前 60 个国家，避免前端卡顿；完整列表仍可看 JSON
    countries_out = countries[:60]
    flights = [f for f in flights if f.get("name") in {c["name"] for c in countries_out[:24]}]
    flights.sort(key=lambda x: x.get("value") or 0, reverse=True)
    flights = flights[:24]
    ips_sorted = sorted(ip_merged.values(), key=lambda x: x["count"], reverse=True)[:200]

    provinces = []
    for name, agg in province_agg.items():
        provinces.append({
            "name": name,
            "value": int(agg["count"]),
            "risk": int(agg["risk"]),
            "ip_count": len(agg["ips"]),
        })
    provinces.sort(key=lambda x: x["value"], reverse=True)

    return {
        "title": title,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": {"lng": tgt[0], "lat": tgt[1], "name": "分析目标"},
        "summary": {
            "countries": len(countries),
            "unique_ips": len(ip_merged),
            "requests": sum(c["value"] for c in countries),
            "risk_hits": sum(c["risk"] for c in countries),
            "provinces": len(provinces),
            "china_requests": sum(p["value"] for p in provinces),
        },
        "countries": countries_out,
        "provinces": provinces,
        "flights": flights,
        "ips": ips_sorted,
    }


def _template_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "globe_access.html")


def write_globe_html(payload: dict, out_path: str, template_path: Optional[str] = None) -> str:
    import shutil

    tpl = template_path or _template_path()
    with open(tpl, "r", encoding="utf-8") as f:
        html = f.read()
    data_js = json.dumps(payload, ensure_ascii=False)
    if "%%GLOBE_DATA%%" in html:
        html = html.replace("%%GLOBE_DATA%%", data_js, 1)
    elif "__GLOBE_DATA__" in html:
        html = html.replace("__GLOBE_DATA__", data_js, 1)
    else:
        inject = f"<script>window.GLOBE_DATA = {data_js};</script>"
        html = html.replace("</head>", inject + "\n</head>", 1)

    out_abs = os.path.abspath(out_path)
    out_dir = os.path.dirname(out_abs) or "."
    os.makedirs(out_dir, exist_ok=True)
    with open(out_abs, "w", encoding="utf-8") as f:
        f.write(html)

    assets = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
    # world.js / china.js：file:// 下用 script 加载
    for name in ("world.js", "world.json", "china.js", "china.json"):
        src = os.path.join(assets, name)
        dst = os.path.join(out_dir, name)
        try:
            if os.path.isfile(src):
                if (not os.path.isfile(dst)) or os.path.getsize(dst) != os.path.getsize(src):
                    shutil.copy2(src, dst)
        except Exception:
            pass
    return out_abs


def export_globe_from_stats(
    url_stats: Any,
    out_dir: Optional[str] = None,
    title: str = "TrafficEye 全球访问态势",
) -> str:
    """生成 HTML，返回绝对路径。"""
    base = out_dir or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")
    os.makedirs(base, exist_ok=True)
    payload = build_globe_payload(url_stats, title=title)
    out = os.path.join(base, "trafficeye_globe_latest.html")
    # 同时存一份 JSON 方便调试
    with open(os.path.join(base, "trafficeye_globe_latest.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return write_globe_html(payload, out)
