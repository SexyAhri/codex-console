"""
流程状态管理模块
从 any-auto-register 移植
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs


@dataclass
class FlowState:
    """OAuth/注册流程状态"""
    
    page_type: str = ""
    continue_url: str = ""
    method: str = "GET"
    current_url: str = ""
    source: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    
    def __bool__(self):
        return bool(self.page_type or self.continue_url or self.current_url)


def normalize_page_type(value):
    """将 page.type 归一化为便于分支判断的 snake_case"""
    return str(value or "").strip().lower().replace("-", "_").replace("/", "_").replace(" ", "_")


def normalize_flow_url(url, auth_base="https://auth.openai.com"):
    """将 continue_url / payload.url 归一化成绝对 URL"""
    value = str(url or "").strip()
    if not value:
        return ""
    if value.startswith("//"):
        return f"https:{value}"
    if value.startswith("/"):
        return f"{auth_base.rstrip('/')}{value}"
    return value


def infer_page_type_from_url(url):
    """从 URL 推断流程状态，用于服务端未返回 page.type 时兜底"""
    if not url:
        return ""

    try:
        parsed = urlparse(url)
    except Exception:
        return ""

    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()

    if "code=" in (parsed.query or ""):
        return "oauth_callback"
    if "chatgpt.com" in host and "/api/auth/callback/" in path:
        return "callback"
    if "create-account/password" in path:
        return "create_account_password"
    if "email-verification" in path or "email-otp" in path:
        return "email_otp_verification"
    if "about-you" in path:
        return "about_you"
    if "log-in/password" in path:
        return "login_password"
    if "sign-in-with-chatgpt" in path and "consent" in path:
        return "consent"
    if "workspace" in path and "select" in path:
        return "workspace_selection"
    if "organization" in path and "select" in path:
        return "organization_selection"
    if "add-phone" in path:
        return "add_phone"
    if "callback" in path:
        return "callback"
    if "chatgpt.com" in host and path in {"", "/"}:
        return "chatgpt_home"
    if path:
        return normalize_page_type(path.strip("/").replace("/", "_"))
    return ""


def extract_flow_state(data=None, current_url="", auth_base="https://auth.openai.com", default_method="GET"):
    """从 API 响应或 URL 中提取统一的流程状态"""
    raw = data if isinstance(data, dict) else {}
    page = raw.get("page") or {}
    payload = page.get("payload") or {}

    continue_url = normalize_flow_url(
        raw.get("continue_url") or payload.get("url") or "",
        auth_base=auth_base,
    )
    effective_current_url = continue_url if raw and continue_url else current_url
    current = normalize_flow_url(effective_current_url or continue_url, auth_base=auth_base)
    page_type = normalize_page_type(page.get("type")) or infer_page_type_from_url(continue_url or current)
    method = str(raw.get("method") or payload.get("method") or default_method or "GET").upper()

    return FlowState(
        page_type=page_type,
        continue_url=continue_url,
        method=method,
        current_url=current,
        source="api" if raw else "url",
        payload=payload if isinstance(payload, dict) else {},
        raw=raw,
    )


def describe_flow_state(state: FlowState) -> str:
    """生成简短的流程状态描述，便于记录日志"""
    if not state:
        return "empty"
    
    target = state.continue_url or state.current_url or "-"
    return f"page={state.page_type or '-'} method={state.method or '-'} next={target[:80]}..."


def state_is_password_registration(state: FlowState) -> bool:
    """判断是否为密码注册页面"""
    return state.page_type == "create_account_password"


def state_is_email_otp(state: FlowState) -> bool:
    """判断是否为邮箱验证码页面"""
    target = f"{state.continue_url} {state.current_url}".lower()
    return (
        state.page_type == "email_otp_verification"
        or "email-verification" in target
        or "email-otp" in target
    )


def state_is_about_you(state: FlowState) -> bool:
    """判断是否为填写信息页面"""
    target = f"{state.continue_url} {state.current_url}".lower()
    return state.page_type == "about_you" or "about-you" in target


def state_is_login_password(state: FlowState) -> bool:
    """判断是否为登录密码页面"""
    return state.page_type == "login_password"


def state_is_add_phone(state: FlowState) -> bool:
    """判断是否为添加手机号页面"""
    target = f"{state.continue_url} {state.current_url}".lower()
    return state.page_type == "add_phone" or "add-phone" in target


def state_requires_navigation(state: FlowState) -> bool:
    """判断是否需要导航到 continue_url"""
    method = (state.method or "GET").upper()
    if method != "GET":
        return False
    if (
        state.source == "api"
        and state.current_url
        and state.page_type not in {"login_password", "email_otp_verification"}
    ):
        return True
    if state.page_type == "external_url" and state.continue_url:
        return True
    if state.continue_url and state.continue_url != state.current_url:
        return True
    return False


def state_is_registration_complete(state: FlowState) -> bool:
    """判断注册是否完成"""
    # 如果 continue_url 包含 code 和 state 参数，说明已经完成
    if state.continue_url:
        parsed = urlparse(state.continue_url)
        query = parse_qs(parsed.query)
        if "code" in query and "state" in query:
            return True
    
    # 如果 page_type 为空且有 continue_url，可能已完成
    if not state.page_type and state.continue_url:
        return True
    
    return False


def extract_code_from_state(state: FlowState) -> Optional[str]:
    """从状态中提取 authorization code"""
    for candidate in (
        state.continue_url,
        state.current_url,
        (state.payload or {}).get("url", ""),
    ):
        code = extract_code_from_url(candidate)
        if code:
            return code
    return None


def extract_code_from_url(url):
    """从 URL 中提取 authorization code"""
    if not url or "code=" not in url:
        return None
    try:
        return parse_qs(urlparse(url).query).get("code", [None])[0]
    except Exception:
        return None
