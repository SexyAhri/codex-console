"""
工具函数模块
从 any-auto-register 移植
"""

import random
import secrets
import string
import time
import hashlib
import base64
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse


# 常量定义
MAX_REGISTRATION_AGE = 45
MIN_REGISTRATION_AGE = 20


def generate_random_password(length: int = 16) -> str:
    """生成随机密码"""
    charset = string.ascii_letters + string.digits + "!@#$%"
    password_chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%"),
    ]
    password_chars.extend(secrets.choice(charset) for _ in range(length - len(password_chars)))
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)


def generate_random_name() -> tuple:
    """生成随机姓名"""
    first_names = [
        "James", "Robert", "John", "Michael", "David", "William", "Richard",
        "Mary", "Jennifer", "Linda", "Elizabeth", "Susan", "Jessica", "Sarah",
        "Emily", "Emma", "Olivia", "Sophia", "Liam", "Noah", "Oliver", "Ethan",
    ]
    last_names = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
        "Davis", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Martin",
    ]
    return random.choice(first_names), random.choice(last_names)


def generate_random_birthday() -> str:
    """生成随机生日 (YYYY-MM-DD)"""
    current_year = datetime.now().year
    year = random.randint(
        current_year - MAX_REGISTRATION_AGE,
        current_year - MIN_REGISTRATION_AGE,
    )
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year:04d}-{month:02d}-{day:02d}"


def generate_datadog_trace() -> dict:
    """生成 Datadog APM 追踪头"""
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    trace_hex = format(int(trace_id), "016x")
    parent_hex = format(int(parent_id), "016x")
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def generate_pkce():
    """生成 PKCE code_verifier 和 code_challenge"""
    code_verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    )
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def seed_oai_device_cookie(session, device_id: str):
    """设置 oai-did cookie"""
    domains = [
        "chatgpt.com",
        ".chatgpt.com",
        "openai.com",
        ".openai.com",
        "auth.openai.com",
        ".auth.openai.com",
    ]
    for domain in domains:
        try:
            session.cookies.set("oai-did", device_id, domain=domain, path="/")
        except Exception:
            pass


def random_delay(low: float = 0.15, high: float = 0.45):
    """随机延迟"""
    time.sleep(random.uniform(low, high))


def decode_jwt_payload(token: str) -> dict:
    """解码 JWT payload"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {}
        
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        import json
        return json.loads(decoded)
    except Exception:
        return {}


def extract_chrome_full_version(user_agent):
    """从 UA 中提取完整的 Chrome 版本号"""
    if not user_agent:
        return ""
    match = re.search(r"Chrome/([0-9.]+)", user_agent)
    return match.group(1) if match else ""


def _registrable_domain(hostname):
    """粗略提取可注册域名，用于推断 Sec-Fetch-Site"""
    if not hostname:
        return ""
    host = hostname.split(":")[0].strip(".").lower()
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-2:])


def infer_sec_fetch_site(url, referer=None, navigation=False):
    """根据目标 URL 和 Referer 推断 Sec-Fetch-Site"""
    if not referer:
        return "none" if navigation else "same-origin"

    try:
        target = urlparse(url or "")
        source = urlparse(referer or "")

        if not target.scheme or not target.netloc or not source.netloc:
            return "none" if navigation else "same-origin"

        if (target.scheme, target.netloc) == (source.scheme, source.netloc):
            return "same-origin"

        if _registrable_domain(target.hostname) == _registrable_domain(source.hostname):
            return "same-site"
    except Exception:
        pass

    return "cross-site"


def build_sec_ch_ua_full_version_list(sec_ch_ua, chrome_full_version):
    """根据 sec-ch-ua 生成 sec-ch-ua-full-version-list"""
    if not sec_ch_ua or not chrome_full_version:
        return ""

    entries = []
    for brand, version in re.findall(r'"([^"]+)";v="([^"]+)"', sec_ch_ua):
        full_version = chrome_full_version if brand in {"Chromium", "Google Chrome"} else f"{version}.0.0.0"
        entries.append(f'"{brand}";v="{full_version}"')

    return ", ".join(entries)


def build_browser_headers(
    *,
    url,
    user_agent,
    sec_ch_ua=None,
    chrome_full_version=None,
    accept=None,
    accept_language="en-US,en;q=0.9",
    referer=None,
    origin=None,
    content_type=None,
    navigation=False,
    fetch_mode=None,
    fetch_dest=None,
    fetch_site=None,
    headed=False,
    extra_headers=None,
):
    """构造更接近真实 Chrome 有头浏览器的请求头"""
    chrome_full = chrome_full_version or extract_chrome_full_version(user_agent)
    full_version_list = build_sec_ch_ua_full_version_list(sec_ch_ua, chrome_full)

    headers = {
        "User-Agent": user_agent or "Mozilla/5.0",
        "Accept-Language": accept_language,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-arch": '"x86"',
        "sec-ch-ua-bitness": '"64"',
    }

    if accept:
        headers["Accept"] = accept
    if referer:
        headers["Referer"] = referer
    if origin:
        headers["Origin"] = origin
    if content_type:
        headers["Content-Type"] = content_type
    if sec_ch_ua:
        headers["sec-ch-ua"] = sec_ch_ua
    if chrome_full:
        headers["sec-ch-ua-full-version"] = f'"{chrome_full}"'
        headers["sec-ch-ua-platform-version"] = '"15.0.0"'
    if full_version_list:
        headers["sec-ch-ua-full-version-list"] = full_version_list

    if navigation:
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-User"] = "?1"
        headers["Upgrade-Insecure-Requests"] = "1"
        headers["Cache-Control"] = "max-age=0"
    else:
        headers["Sec-Fetch-Dest"] = fetch_dest or "empty"
        headers["Sec-Fetch-Mode"] = fetch_mode or "cors"

    headers["Sec-Fetch-Site"] = fetch_site or infer_sec_fetch_site(url, referer, navigation=navigation)

    if headed:
        headers.setdefault("Priority", "u=0, i" if navigation else "u=1, i")
        headers.setdefault("DNT", "1")
        headers.setdefault("Sec-GPC", "1")

    if extra_headers:
        for key, value in extra_headers.items():
            if value is not None:
                headers[key] = value

    return headers
