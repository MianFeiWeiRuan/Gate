#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (精简版)
1. 拉 VPN Gate 原始节点 (官方 CSV, 失败回退镜像)
2. 只留带 TCP 入口的 SSTP 节点
3. 去重
4. 并发调用 Worker 检测
5. 生成 public/data.json + index.html + nodes.txt + sstp.txt
6. 优选域名: 远程 TXT 拉取, 失败回退默认列表
时间显示: 北京时间 (UTC+8)
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

import requests

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BJ_TZ = timezone(timedelta(hours=8))


def bj_now_str(fmt="%Y-%m-%d %H:%M:%S"):
    return datetime.now(BJ_TZ).strftime(fmt) + " 北京"


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))
VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
#(CF-Workers-CheckSocks5 更换域名xxxxxx,暂时不需要)
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://xxxxxx.check?sstp=vpn:vpn@")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")
# (GitHub Pages 更换地址)
NODES_URL = os.environ.get("NODES_URL", "https://MianFeiWeiRuan.github.io/Gate/nodes.txt")

DATA_CENTER_ORG_KEYWORDS = (
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
)
RESIDENTIAL_ORG_KEYWORDS = (
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
)
COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# 默认优选域名（兜底用），一行一个（内部仍以逗号连接，兼容 EDGE_HOSTS 环境变量）
_DEFAULT_EDGE_HOSTS = [
    h.strip() for h in os.environ.get(
        "EDGE_HOSTS",
        ",".join([
            "ct.cloudflare.byoip.top:443",
            "cu.cloudflare.byoip.top:443",
            "cm.cloudflare.byoip.top:443",
            "yg1.ygkkk.dpdns.org:443",
            "cf.090227.xyz:443",
            "cloudflare.182682.xyz:443",
            "skk.moe:443",
            "saas.sin.fan:443",
        ]),
    ).split(",") if h.strip()
]

# 外部 TXT 网址（一行一个 host:port），可用环境变量 EDGE_HOSTS_TXT 覆盖
EDGE_HOSTS_TXT = os.environ.get(
    "EDGE_HOSTS_TXT",
    "https://bestcf.pages.dev/domain/Domain-Asia.txt",
).strip()

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
_section = None


def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 优选域名: 远程 TXT 加载
# ---------------------------------------------------------------------------
def load_edge_hosts():
    """优先从远程 TXT 拉取优选域名, 失败或为空则回退默认列表。
    TXT 格式: 一行一个 host:port, 支持 # 注释与空行, 也支持一行逗号分隔多个。"""
    if not EDGE_HOSTS_TXT:
        return list(_DEFAULT_EDGE_HOSTS)
    try:
        log("EDGE HOSTS", f"从 TXT 拉取: {EDGE_HOSTS_TXT}")
        r = requests.get(EDGE_HOSTS_TXT, timeout=HTTP_TIMEOUT,
                         headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        r.raise_for_status()
        hosts = []
        for ln in r.text.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            for part in ln.split(","):
                part = part.strip()
                if part:
                    hosts.append(part)
        if hosts:
            log("EDGE HOSTS", f"TXT 获取到 {len(hosts)} 条优选域名")
            return hosts
        log("EDGE HOSTS", "TXT 内容为空, 回退默认列表")
    except Exception as exc:
        log("EDGE HOSTS", f"TXT 拉取失败: {exc}, 回退默认列表")
    return list(_DEFAULT_EDGE_HOSTS)


# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
def fetch_vpngate():
    try:
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        r = requests.get(VPNGATE_API, timeout=HTTP_TIMEOUT,
                         headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"})
        r.raise_for_status()
        rows = parse_csv(r.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    try:
        log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
        r = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        rows = parse_mirror_json(r.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN Gate 官方 API 与回退镜像均不可用, 数据源完全失败")


def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    hidx = next((i for i, ln in enumerate(lines) if ln.lstrip("#").startswith("HostName")), None)
    if hidx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")
    header = lines[hidx].lstrip("#").split(",")
    pos = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        pos[col] = next((i for i, h in enumerate(header) if h.strip().lstrip("*").lower() == col), None)
    if pos["openvpn_configdata_base64"] is None:
        pos["openvpn_configdata_base64"] = next(
            (i for i, h in enumerate(header) if "base64" in h.lower()), len(header) - 1)
    for col, d in (("hostname", 0), ("ip", 1), ("countrylong", 5), ("countryshort", 6)):
        if pos[col] is None:
            pos[col] = d

    rows = []
    for ln in lines[hidx + 1:]:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7:
            continue
        host, ip = fields[pos["hostname"]].strip(), fields[pos["ip"]].strip()
        if host and ip:
            rows.append({
                "host": host, "ip": ip,
                "country_long": fields[pos["countrylong"]].strip(),
                "country_short": fields[pos["countryshort"]].strip(),
                "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
            })
    return rows


def parse_mirror_json(data):
    servers = []
    for item in (data if isinstance(data, list) else [data]):
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if host and ip:
            rows.append({
                "host": host, "ip": ip,
                "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
                "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
                "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
            })
    return rows


# ---------------------------------------------------------------------------
# SSTP 筛选
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M | re.I)
_REMOTE_LINE_RE = re.compile(r"^remote\s+(\S+)\s+(\d+)", re.M | re.I)


def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        pm = _PROTO_TCP_RE.search(cfg)
        if not pm:
            continue
        remotes = list(_REMOTE_LINE_RE.finditer(cfg))
        if not remotes:
            continue
        after = [m for m in remotes if m.start() >= pm.start()]
        port = int((after[0] if after else remotes[-1]).group(2))
        if not (1 <= port <= 65535):
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({"host": host, "port": port, "ip": r["ip"],
                      "country": r["country_long"], "country_code": r["country_short"]})
    return nodes


def dedupe(nodes):
    seen, out = set(), []
    for n in nodes:
        k = (n["host"].lower(), n["port"], "sstp")
        if k not in seen:
            seen.add(k)
            out.append(n)
    return out


# ---------------------------------------------------------------------------
# Worker 检测
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    dc = None
    if is_datacenter is True or (isinstance(is_datacenter, str) and is_datacenter.strip().lower() in ("true", "1", "yes")):
        dc = True
    elif is_datacenter is False or (isinstance(is_datacenter, str) and is_datacenter.strip().lower() in ("false", "0", "no")):
        dc = False
    if dc is True:
        return "datacenter"
    if dc is False:
        return "residential"
    org = (exit_org or "").upper()
    if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
        return "datacenter"
    if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
        return "residential"
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"
    return "unknown"


def check_one(node, session):
    out = dict(node)
    out.update({
        "protocol": "sstp",
        "link": f"sstp://vpn:vpn@{node['host']}:{node['port']}",
        "status": "failed", "success": False,
        "checked_at": bj_now_str("%Y-%m-%d %H:%M"),
        "exit": None, "residential": "unknown",
    })
    try:
        r = session.get(WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe=""),
                        timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = None if ok else (j.get("error") or j.get("message") or "check failed")
        ei = j.get("exit") or {}
        if ei:
            asn = ei.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": ei.get("ip"), "country": ei.get("country"),
                "country_code": ei.get("country_code"), "city": ei.get("city"),
                "continent": ei.get("continent"), "asn": asn.get("asn"),
                "org": org, "type": asn.get("type"),
                "is_datacenter": ei.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, ei.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out


def check_all(nodes, session):
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        return [f.result() for f in as_completed([pool.submit(check_one, n, session) for n in nodes])]


# ---------------------------------------------------------------------------
# 输出生成
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count, "sstp_nodes": sstp_count, "checked": len(results),
        "success": len(available), "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }
    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    return {
        "generated_at": bj_now_str(),
        "source": source, "worker": WORKER_CHECK_URL,
        "stats": stats, "countries": by_country, "available": available,
    }


def build_nodes_text(data):
    entry = os.environ.get("HOSTS_ENTRY", "").strip()
    edge = [e.strip() for e in entry.split(",") if e.strip()] or load_edge_hosts()
    lines, idx = [], 0
    ordered = sorted(data["countries"].items(),
                     key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])))
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(grp["nodes"],
                       key=lambda n: (0 if n.get("residential") == "residential" else 1,
                                      n.get("latency_ms") is None,
                                      n.get("latency_ms") or 0,
                                      n.get("host") or ""))
        for tag, subset in (("住宅", [n for n in nodes if n.get("residential") == "residential"]),
                            ("机房", [n for n in nodes if n.get("residential") != "residential"])):
            for i, n in enumerate(subset, 1):
                lines.append(f"{edge[idx % len(edge)]}#{zh}-{tag}-{i:02d}"
                             f"$sstp://vpn:vpn@{n['host']}:{n['port']}")
                idx += 1
    return "\n".join(lines) + "\n"


def build_sstp_links_text(data):
    """只输出纯 sstp:// 链接，一行一个，供 SSTP 客户端直接导入"""
    links = []
    ordered = sorted(data["countries"].items(),
                     key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])))
    for cname, grp in ordered:
        nodes = sorted(grp["nodes"],
                       key=lambda n: (0 if n.get("residential") == "residential" else 1,
                                      n.get("latency_ms") is None,
                                      n.get("latency_ms") or 0,
                                      n.get("host") or ""))
        for n in nodes:
            links.append(f"sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(links) + "\n"


def write_outputs(data):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, encoding="utf-8") as f:
            html = f.read()
    else:
        html = ("<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
                "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
                "<script>fetch('data.json').then(r=>r.json()).then(d=>"
                "document.getElementById('out').textContent=JSON.stringify(d.stats)"
                ").catch(e=>document.getElementById('out').textContent='加载失败:'+e)</script></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(build_nodes_text(data))

    # 新增：纯 sstp:// 链接
    sstp_path = os.path.join(PUBLIC_DIR, "sstp.txt")
    with open(sstp_path, "w", encoding="utf-8") as f:
        f.write(build_sstp_links_text(data))

    return data_path, html_path, nodes_path, sstp_path


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化")
    uniq = dedupe(sstp_nodes)
    if MAX_CHECK_NODES > 0 and len(uniq) > MAX_CHECK_NODES:
        log("VPN GATE", f"MAX_CHECK_NODES={MAX_CHECK_NODES}, 截断 {len(uniq)} -> {MAX_CHECK_NODES}")
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {time.time() - t0:.1f}s")

    if uniq and not success:
        if len(worker_errors) == len(uniq):
            die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")
        die(f"提交 {len(uniq)} 个节点, 无一通过 Worker 检测 (success 全为 false) — 判定失败")

    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    data_path, html_path, nodes_path, sstp_path = write_outputs(data)
    for p in (data_path, html_path, nodes_path, sstp_path):
        log("WEBSITE", f"生成 {os.path.relpath(p, REPO_DIR)}")
    log("USAGE", f"自动轮换: 把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」框 (每 2 小时更新)")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
