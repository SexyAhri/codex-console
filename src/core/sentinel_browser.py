"""Playwright 版 Sentinel SDK token 获取辅助（可选）"""

from typing import Callable, Optional
import logging
import sys
import asyncio

logger = logging.getLogger(__name__)


def _flow_page_url(flow: str) -> str:
    """根据 flow 返回对应的页面 URL"""
    flow_name = str(flow or "").strip().lower()
    mapping = {
        "authorize_continue": "https://auth.openai.com/create-account",
        "username_password_create": "https://auth.openai.com/create-account/password",
        "password_verify": "https://auth.openai.com/log-in/password",
        "email_otp_validate": "https://auth.openai.com/email-verification",
        "oauth_create_account": "https://auth.openai.com/about-you",
    }
    return mapping.get(flow_name, "https://auth.openai.com/about-you")


def get_sentinel_token_via_browser(
    *,
    flow: str,
    proxy: Optional[str] = None,
    timeout_ms: int = 45000,
    page_url: Optional[str] = None,
    headless: bool = True,
    device_id: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Optional[str]:
    """
    通过浏览器直接调用 SentinelSDK.token(flow) 获取完整 token
    
    需要安装 playwright: pip install playwright && playwright install chromium
    """
    log = log_fn or (lambda _msg: None)

    # Windows 上修复 asyncio 事件循环策略
    if sys.platform == 'win32':
        try:
            # 设置为 WindowsProactorEventLoopPolicy 以支持子进程
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except Exception:
            pass

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log("Sentinel Browser 不可用: 未安装 playwright")
        return None
    except Exception as e:
        log(f"Sentinel Browser 不可用: {e}")
        return None

    target_url = str(page_url or _flow_page_url(flow)).strip() or _flow_page_url(flow)
    
    # 构建代理配置
    proxy_config = None
    if proxy:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(proxy)
            if parsed.scheme and parsed.hostname:
                proxy_config = {
                    "server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port or 80}"
                }
                if parsed.username:
                    proxy_config["username"] = parsed.username
                if parsed.password:
                    proxy_config["password"] = parsed.password
        except Exception:
            pass

    launch_args = {
        "headless": bool(headless),
        "args": [
            "--no-sandbox",
            "--disable-blink-features=AutomationControlled",
        ],
    }
    if proxy_config:
        launch_args["proxy"] = proxy_config

    log(f"Sentinel Browser 启动: flow={flow}, url={target_url}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(**launch_args)
            try:
                context = browser.new_context(
                    viewport={"width": 1440, "height": 900},
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/136.0.7103.92 Safari/537.36"
                    ),
                    ignore_https_errors=True,
                )
                
                # 设置 device_id cookie
                if device_id:
                    try:
                        context.add_cookies([{
                            "name": "oai-did",
                            "value": str(device_id),
                            "url": "https://auth.openai.com/",
                            "path": "/",
                            "secure": True,
                            "sameSite": "Lax",
                        }])
                    except Exception:
                        pass

                page = context.new_page()
                page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)
                
                # 等待 SentinelSDK 加载
                page.wait_for_function(
                    "() => typeof window.SentinelSDK !== 'undefined' && typeof window.SentinelSDK.token === 'function'",
                    timeout=min(timeout_ms, 15000),
                )

                # 调用 SentinelSDK.token()
                result = page.evaluate(
                    """
                    async ({ flow }) => {
                        try {
                            const token = await window.SentinelSDK.token(flow);
                            return { success: true, token };
                        } catch (e) {
                            return {
                                success: false,
                                error: (e && (e.message || String(e))) || "unknown",
                            };
                        }
                    }
                    """,
                    {"flow": flow},
                )

                if not result or not result.get("success") or not result.get("token"):
                    log(f"Sentinel Browser 获取失败: {result.get('error') if result else 'no result'}")
                    return None

                token = str(result["token"] or "").strip()
                if not token:
                    log("Sentinel Browser 返回空 token")
                    return None

                try:
                    import json
                    parsed = json.loads(token)
                    log(
                        f"Sentinel Browser 成功: "
                        f"p={'✓' if parsed.get('p') else '✗'} "
                        f"t={'✓' if parsed.get('t') else '✗'} "
                        f"c={'✓' if parsed.get('c') else '✗'}"
                    )
                except Exception:
                    log(f"Sentinel Browser 成功: len={len(token)}")

                return token
                
            except Exception as e:
                log(f"Sentinel Browser 异常: {e}")
                return None
            finally:
                browser.close()
                
    except Exception as e:
        log(f"Sentinel Browser 启动失败: {e}")
        return None
