"""
ChatGPT 注册客户端
从 any-auto-register 移植，使用状态机驱动注册流程
"""

import json
import random
import time
import uuid
from typing import Optional, Tuple
from urllib.parse import urlparse

from curl_cffi import requests as curl_requests

from .flow_state import (
    FlowState,
    extract_flow_state,
    describe_flow_state,
    state_is_password_registration,
    state_is_email_otp,
    state_is_about_you,
    state_requires_navigation,
    state_is_registration_complete,
)
from .utils import (
    generate_datadog_trace,
    seed_oai_device_cookie,
    random_delay,
)
from .sentinel_token import build_sentinel_token
from ..sentinel_browser import get_sentinel_token_via_browser
from ...config.constants import OPENAI_API_ENDPOINTS


class ChatGPTClient:
    """ChatGPT 注册客户端（状态机驱动）"""
    
    BASE = "https://chatgpt.com"
    AUTH = "https://auth.openai.com"
    
    def __init__(self, proxy=None, verbose=True, browser_mode="protocol"):
        """
        初始化客户端
        
        Args:
            proxy: 代理地址
            verbose: 是否输出详细日志
            browser_mode: protocol | headless | headed
        """
        self.proxy = proxy
        self.verbose = verbose
        self.browser_mode = browser_mode or "protocol"
        self.device_id = str(uuid.uuid4())
        
        # 随机 User-Agent
        chrome_version = random.choice(["131.0.6778.139", "133.0.6943.88", "136.0.7103.122"])
        self.ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36"
        self.sec_ch_ua = f'"Google Chrome";v="{chrome_version.split(".")[0]}", "Chromium";v="{chrome_version.split(".")[0]}", "Not_A Brand";v="24"'
        
        # 创建 session
        impersonate = random.choice(["chrome131", "chrome133a", "chrome136"])
        self.impersonate = impersonate
        self.session = curl_requests.Session(impersonate=impersonate)
        
        if self.proxy:
            self.session.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }
        
        # 设置基础 headers
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        })
        
        # 设置 device ID cookie
        seed_oai_device_cookie(self.session, self.device_id)
        
        self.last_registration_state = FlowState()
    
    def _log(self, msg):
        """输出日志"""
        if self.verbose:
            print(f"  {msg}")
    
    def _get_sentinel_token(self, flow: str, page_url: Optional[str] = None) -> Optional[str]:
        """获取 Sentinel Token"""
        # 对于密码注册和创建账户，优先使用浏览器
        prefer_browser = flow in {"username_password_create", "oauth_create_account"}
        
        if prefer_browser:
            token = get_sentinel_token_via_browser(
                flow=flow,
                proxy=self.proxy,
                page_url=page_url,
                headless=self.browser_mode != "headed",
                device_id=self.device_id,
                log_fn=lambda msg: self._log(msg),
            )
            if token:
                self._log(f"{flow}: 已通过 Playwright 获取 Sentinel token")
                return token
        
        # 使用纯 Python 实现
        token = build_sentinel_token(
            self.session,
            self.device_id,
            flow=flow,
            user_agent=self.ua,
            sec_ch_ua=self.sec_ch_ua,
            impersonate=self.impersonate,
        )
        if token:
            self._log(f"{flow}: 已通过 HTTP PoW 获取 Sentinel token")
        return token
    
    def _reset_session(self):
        """重置 session（保持 device_id）"""
        self.session.close()
        self.session = curl_requests.Session(impersonate=self.impersonate)
        
        if self.proxy:
            self.session.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }
        
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        })
        
        seed_oai_device_cookie(self.session, self.device_id)
    
    def _state_from_url(self, url: str) -> FlowState:
        """从 URL 创建状态"""
        state = FlowState()
        state.current_url = url
        
        path = urlparse(url).path
        
        if "/create-account/password" in path:
            state.page_type = "create_account_password"
        elif "/email-verification" in path:
            state.page_type = "email_otp_verification"
        elif "/about-you" in path:
            state.page_type = "about_you"
        elif "/log-in/password" in path:
            state.page_type = "login_password"
        elif "/add-phone" in path:
            state.page_type = "add_phone"
        
        return state
    
    def _state_signature(self, state: FlowState) -> str:
        """生成状态签名（用于检测循环）"""
        return f"{state.page_type}|{urlparse(state.continue_url or '').path}|{urlparse(state.current_url or '').path}"
    
    def _state_is_password_registration(self, state: FlowState) -> bool:
        """判断是否为密码注册页面"""
        return state_is_password_registration(state)
    
    def _state_is_email_otp(self, state: FlowState) -> bool:
        """判断是否为邮箱验证码页面"""
        return state_is_email_otp(state)
    
    def _state_is_about_you(self, state: FlowState) -> bool:
        """判断是否为填写信息页面"""
        return state_is_about_you(state)
    
    def _state_requires_navigation(self, state: FlowState) -> bool:
        """判断是否需要导航"""
        return state_requires_navigation(state)
    
    def _is_registration_complete_state(self, state: FlowState) -> bool:
        """判断注册是否完成"""
        return state_is_registration_complete(state)

    
    def visit_homepage(self) -> bool:
        """访问首页"""
        try:
            self._log("访问 ChatGPT 首页...")
            response = self.session.get(
                self.BASE,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": self.BASE,
                },
                timeout=30,
            )
            return response.status_code == 200
        except Exception as e:
            self._log(f"访问首页失败: {e}")
            return False
    
    def get_csrf_token(self) -> Optional[str]:
        """获取 CSRF token"""
        try:
            self._log("获取 CSRF token...")
            response = self.session.get(
                f"{self.BASE}/api/auth/csrf",
                headers={
                    "Accept": "application/json",
                    "Referer": self.BASE,
                },
                timeout=30,
            )
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            csrf_token = data.get("csrfToken")
            if csrf_token:
                self._log(f"CSRF token: {csrf_token[:20]}...")
            return csrf_token
        except Exception as e:
            self._log(f"获取 CSRF token 失败: {e}")
            return None
    
    def signin(self, email: str, csrf_token: str) -> Optional[str]:
        """提交邮箱，获取 authorize URL"""
        try:
            self._log(f"提交邮箱: {email}")
            response = self.session.post(
                f"{self.BASE}/api/auth/signin/openai",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": self.BASE,
                },
                data={
                    "csrfToken": csrf_token,
                    "email": email,
                    "callbackUrl": "/",
                    "json": "true",
                },
                timeout=30,
            )
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            auth_url = data.get("url")
            if auth_url:
                self._log(f"Authorize URL: {auth_url[:80]}...")
            return auth_url
        except Exception as e:
            self._log(f"提交邮箱失败: {e}")
            return None
    
    def authorize(self, auth_url: str) -> Optional[str]:
        """访问 authorize URL"""
        try:
            self._log("访问 authorize URL...")
            response = self.session.get(
                auth_url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": self.BASE,
                },
                allow_redirects=True,
                timeout=30,
            )
            
            final_url = str(response.url)
            self._log(f"Authorize 完成: {urlparse(final_url).path}")
            return final_url
        except Exception as e:
            self._log(f"Authorize 失败: {e}")
            return None
    
    def authorize_continue(self, email: str, screen_hint: str = "signup") -> Tuple[bool, FlowState]:
        """
        调用 authorize/continue 提交邮箱，获取下一步状态
        这是关键步骤！必须在 authorize 之后调用
        """
        try:
            self._log(f"提交 authorize/continue (screen_hint={screen_hint})...")
            
            # 获取 Sentinel token
            sen_token = self._get_sentinel_token("authorize_continue")
            
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Referer": f"{self.AUTH}/create-account" if screen_hint == "signup" else f"{self.AUTH}/log-in",
                "Origin": self.AUTH,
                "oai-device-id": self.device_id,
            }
            headers.update(generate_datadog_trace())
            
            if sen_token:
                headers["openai-sentinel-token"] = sen_token
            
            payload = {
                "username": {
                    "kind": "email",
                    "value": email,
                }
            }
            if screen_hint:
                payload["screen_hint"] = screen_hint
            
            response = self.session.post(
                OPENAI_API_ENDPOINTS["signup"],  # 这就是 /api/accounts/authorize/continue
                headers=headers,
                data=json.dumps(payload),
                timeout=30,
            )
            
            self._log(f"authorize/continue 状态: {response.status_code}")
            
            if response.status_code != 200:
                error_text = response.text[:200]
                return False, FlowState()
            
            # 解析响应
            try:
                response_data = response.json()
                state = extract_flow_state(response_data, f"{self.AUTH}/authorize/continue")
                self._log(f"authorize/continue 后状态: {describe_flow_state(state)}")
                return True, state
            except Exception:
                return False, FlowState()
        except Exception as e:
            self._log(f"authorize/continue 失败: {e}")
            return False, FlowState()
    
    def register_user(self, email: str, password: str) -> Tuple[bool, str]:
        """注册用户（提交密码）"""
        try:
            self._log("提交注册密码...")
            
            # 获取 Sentinel token
            sen_token = self._get_sentinel_token(
                "username_password_create",
                page_url=f"{self.AUTH}/create-account/password"
            )
            
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Referer": f"{self.AUTH}/create-account/password",
                "Origin": self.AUTH,
                "oai-device-id": self.device_id,
            }
            headers.update(generate_datadog_trace())
            
            if sen_token:
                headers["openai-sentinel-token"] = sen_token
            
            response = self.session.post(
                OPENAI_API_ENDPOINTS["register"],
                headers=headers,
                data=json.dumps({
                    "password": password,
                    "username": email,
                }),
                timeout=30,
            )
            
            self._log(f"注册密码状态: {response.status_code}")
            
            if response.status_code != 200:
                error_text = response.text[:200]
                return False, f"HTTP {response.status_code}: {error_text}"
            
            return True, "注册密码成功"
        except Exception as e:
            return False, str(e)
    
    def send_email_otp(self, referer: str) -> bool:
        """发送邮箱验证码"""
        try:
            self._log("发送验证码...")
            response = self.session.get(
                OPENAI_API_ENDPOINTS["send_otp"],
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": referer,
                },
                timeout=30,
            )
            
            success = response.status_code == 200
            if success:
                self._log("验证码已发送")
            else:
                self._log(f"发送验证码失败: HTTP {response.status_code}")
            return success
        except Exception as e:
            self._log(f"发送验证码异常: {e}")
            return False
    
    def verify_email_otp(self, code: str, return_state: bool = False):
        """验证邮箱验证码"""
        try:
            self._log(f"验证验证码: {code}")
            
            # 获取 Sentinel token
            sen_token = self._get_sentinel_token("email_otp_validate")
            
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Referer": f"{self.AUTH}/email-verification",
                "Origin": self.AUTH,
                "oai-device-id": self.device_id,
            }
            headers.update(generate_datadog_trace())
            
            if sen_token:
                headers["openai-sentinel-token"] = sen_token
            
            response = self.session.post(
                OPENAI_API_ENDPOINTS["validate_otp"],
                headers=headers,
                data=json.dumps({"code": code}),
                timeout=30,
            )
            
            self._log(f"验证码校验状态: {response.status_code}")
            
            if response.status_code != 200:
                error_msg = f"HTTP {response.status_code}"
                if return_state:
                    return False, error_msg
                return False
            
            # 解析响应
            try:
                response_data = response.json()
                state = extract_flow_state(response_data, f"{self.AUTH}/email-verification")
                self._log(f"验证码校验后状态: {describe_flow_state(state)}")
                
                if return_state:
                    return True, state
                return True
            except Exception:
                if return_state:
                    return True, self._state_from_url(f"{self.AUTH}/about-you")
                return True
        except Exception as e:
            error_msg = str(e)
            if return_state:
                return False, error_msg
            return False
    
    def create_account(self, first_name: str, last_name: str, birthdate: str, return_state: bool = False):
        """创建账户（提交姓名和生日）"""
        try:
            self._log(f"创建账户: {first_name} {last_name}, {birthdate}")
            
            # 获取 Sentinel token
            sen_token = self._get_sentinel_token(
                "oauth_create_account",
                page_url=f"{self.AUTH}/about-you"
            )
            
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Referer": f"{self.AUTH}/about-you",
                "Origin": self.AUTH,
                "oai-device-id": self.device_id,
            }
            headers.update(generate_datadog_trace())
            
            if sen_token:
                headers["openai-sentinel-token"] = sen_token
            
            response = self.session.post(
                OPENAI_API_ENDPOINTS["create_account"],
                headers=headers,
                data=json.dumps({
                    "name": f"{first_name} {last_name}",
                    "birthdate": birthdate,
                }),
                timeout=30,
            )
            
            self._log(f"创建账户状态: {response.status_code}")
            
            if response.status_code != 200:
                error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
                if return_state:
                    return False, error_msg
                return False
            
            # 解析响应
            try:
                response_data = response.json()
                state = extract_flow_state(response_data, f"{self.AUTH}/about-you")
                self._log(f"创建账户后状态: {describe_flow_state(state)}")
                
                if return_state:
                    return True, state
                return True
            except Exception:
                if return_state:
                    return True, FlowState()
                return True
        except Exception as e:
            error_msg = str(e)
            if return_state:
                return False, error_msg
            return False
    
    def _follow_flow_state(self, state: FlowState, referer: str):
        """跟随流程状态（访问 continue_url）"""
        if not state.continue_url:
            return False, self._state_from_url(state.current_url or referer)
        
        try:
            self._log(f"跟随流程: {urlparse(state.continue_url).path}")
            response = self.session.get(
                state.continue_url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": referer,
                },
                allow_redirects=True,
                timeout=30,
            )
            
            final_url = str(response.url)
            next_state = self._state_from_url(final_url)
            return True, next_state
        except Exception as e:
            self._log(f"跟随流程失败: {e}")
            return False, self._state_from_url(state.current_url or referer)

    
    def register_complete_flow(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        birthdate: str,
        skymail_client,
        stop_before_about_you_submission=False,
        otp_wait_timeout=600,
        otp_resend_wait_timeout=300,
    ) -> Tuple[bool, str]:
        """
        完整的注册流程（状态机驱动）
        
        Args:
            email: 邮箱
            password: 密码
            first_name: 名
            last_name: 姓
            birthdate: 生日 (YYYY-MM-DD)
            skymail_client: 邮箱客户端（用于获取验证码）
            stop_before_about_you_submission: 是否在 about_you 页面停止
            otp_wait_timeout: 验证码等待超时（秒）
            otp_resend_wait_timeout: 重发验证码后等待超时（秒）
        
        Returns:
            tuple: (success, message)
        """
        self._log(
            f"注册状态机启动: stop_before_about_you={'on' if stop_before_about_you_submission else 'off'}, "
            f"otp_wait={otp_wait_timeout}s, otp_resend_wait={otp_resend_wait_timeout}s"
        )
        
        max_auth_attempts = 3
        final_url = ""
        
        # 预授权阶段（获取 authorize URL）
        for auth_attempt in range(max_auth_attempts):
            if auth_attempt > 0:
                self._log(f"预授权重试 {auth_attempt + 1}/{max_auth_attempts}...")
                self._reset_session()
            
            # 1. 访问首页
            if not self.visit_homepage():
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "访问首页失败"
            
            # 2. 获取 CSRF token
            csrf_token = self.get_csrf_token()
            if not csrf_token:
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "获取 CSRF token 失败"
            
            # 3. 提交邮箱
            auth_url = self.signin(email, csrf_token)
            if not auth_url:
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "提交邮箱失败"
            
            # 4. 访问 authorize URL
            final_url = self.authorize(auth_url)
            if not final_url:
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "Authorize 失败"
            
            final_path = urlparse(final_url).path
            self._log(f"Authorize → {final_path}")
            
            # 检查是否被 Cloudflare 拦截
            if "api/accounts/authorize" in final_path or final_path == "/error":
                self._log(f"检测到 Cloudflare 拦截，准备重试: {final_url[:160]}...")
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, f"预授权被拦截: {final_path}"
            
            # 5. 调用 authorize/continue 提交邮箱（关键步骤！）
            success, state = self.authorize_continue(email, screen_hint="signup")
            if not success:
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "authorize/continue 失败"
            
            # 检查返回的状态
            if not state or not state.page_type:
                self._log("authorize/continue 未返回有效状态，准备重试...")
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "authorize/continue 未返回有效状态"
            
            break
        
        # 注册状态机
        self._log(f"注册状态起点: {describe_flow_state(state)}")
        
        register_submitted = False
        otp_verified = False
        account_created = False
        seen_states = {}
        otp_send_attempts = 0
        
        for step in range(12):
            signature = self._state_signature(state)
            seen_states[signature] = seen_states.get(signature, 0) + 1
            self._log(
                f"状态推进[{step + 1}/12]: {describe_flow_state(state)} (seen={seen_states[signature]})"
            )
            
            # 检测循环
            if seen_states[signature] > 2:
                return False, f"状态卡住: {describe_flow_state(state)}"
            
            # 检查是否完成
            if self._is_registration_complete_state(state):
                self.last_registration_state = state
                self._log("✅ 注册流程完成")
                return True, "注册成功"
            
            # 密码注册页面
            if self._state_is_password_registration(state):
                self._log("进入密码注册流程")
                if register_submitted:
                    return False, "密码注册阶段重复进入"
                
                success, msg = self.register_user(email, password)
                if not success:
                    return False, f"注册失败: {msg}"
                
                register_submitted = True
                otp_send_attempts += 1
                self._log(f"发送注册验证码: attempt={otp_send_attempts}")
                
                if not self.send_email_otp(
                    referer=state.current_url or state.continue_url or f"{self.AUTH}/create-account/password"
                ):
                    self._log("发送验证码接口返回失败，继续等待邮箱中的验证码...")
                else:
                    self._log("发送注册验证码成功")
                
                state = self._state_from_url(f"{self.AUTH}/email-verification")
                continue
            
            # 邮箱验证码页面
            if self._state_is_email_otp(state):
                self._log(f"等待邮箱验证码 ({otp_wait_timeout}s)...")
                otp_code = skymail_client.wait_for_verification_code(
                    email, timeout=otp_wait_timeout
                )
                
                if not otp_code:
                    self._log(f"首次等待未收到验证码，尝试重发后再等待 {otp_resend_wait_timeout}s")
                    otp_send_attempts += 1
                    resend_ok = self.send_email_otp(
                        referer=state.current_url or state.continue_url or f"{self.AUTH}/email-verification"
                    )
                    if resend_ok:
                        self._log(f"重发验证码成功: attempt={otp_send_attempts}")
                    else:
                        self._log(f"重发验证码失败: attempt={otp_send_attempts}")
                    
                    otp_code = skymail_client.wait_for_verification_code(
                        email, timeout=otp_resend_wait_timeout
                    )
                
                if not otp_code:
                    return False, "未收到验证码"
                
                success, next_state = self.verify_email_otp(otp_code, return_state=True)
                if not success:
                    return False, f"验证码失败: {next_state}"
                
                otp_verified = True
                state = next_state
                self.last_registration_state = state
                continue
            
            # about_you 页面
            if self._state_is_about_you(state):
                if stop_before_about_you_submission:
                    self.last_registration_state = state
                    self._log("注册链路已到 about_you，按 interrupt 流程停止")
                    self._log("下一步交由 OAuth 新会话提交姓名+生日")
                    return True, "pending_about_you_submission"
                
                if account_created:
                    return False, "填写信息阶段重复进入"
                
                success, next_state = self.create_account(
                    first_name,
                    last_name,
                    birthdate,
                    return_state=True,
                )
                if not success:
                    return False, f"创建账号失败: {next_state}"
                
                account_created = True
                state = next_state
                self.last_registration_state = state
                continue
            
            # 需要导航
            if self._state_requires_navigation(state):
                success, next_state = self._follow_flow_state(
                    state,
                    referer=state.current_url or f"{self.AUTH}/about-you",
                )
                if not success:
                    return False, f"跳转失败: {next_state}"
                
                state = next_state
                self.last_registration_state = state
                continue
            
            # 未知状态，回退到密码注册
            if not register_submitted and not otp_verified and not account_created:
                self._log(f"未知起始状态，回退为全新注册流程: {describe_flow_state(state)}")
                state = self._state_from_url(f"{self.AUTH}/create-account/password")
                continue
            
            return False, f"未支持的注册状态: {describe_flow_state(state)}"
        
        return False, "注册状态机超出最大步数"
