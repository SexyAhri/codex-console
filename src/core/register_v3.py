"""
注册引擎 V3 - 从 any-auto-register 完整移植
使用状态机驱动的注册和登录流程
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Optional

from .anyauto.chatgpt_client import ChatGPTClient
from .anyauto.oauth_client import OAuthClient
from .anyauto.utils import (
    generate_random_birthday,
    generate_random_name,
    generate_random_password,
)

logger = logging.getLogger(__name__)


@dataclass
class RegistrationResultV3:
    """注册结果"""
    success: bool
    email: str = ""
    password: str = ""
    account_id: str = ""
    workspace_id: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    session_token: str = ""
    device_id: str = ""
    error_message: str = ""
    logs: list = None
    metadata: dict = None
    source: str = "register"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "email": self.email,
            "password": self.password,
            "account_id": self.account_id,
            "workspace_id": self.workspace_id,
            "access_token": self.access_token[:20] + "..." if self.access_token else "",
            "refresh_token": self.refresh_token[:20] + "..." if self.refresh_token else "",
            "id_token": self.id_token[:20] + "..." if self.id_token else "",
            "session_token": self.session_token[:20] + "..." if self.session_token else "",
            "device_id": self.device_id,
            "error_message": self.error_message,
            "logs": self.logs or [],
            "metadata": self.metadata or {},
            "source": self.source,
        }


class EmailServiceAdapter:
    """
    邮箱服务适配器
    
    将我们项目的邮箱服务适配给 ChatGPTClient / OAuthClient 状态机。
    注意：我们的邮箱服务不支持 exclude_codes 参数，所以在这里处理。
    """
    
    def __init__(self, email_service, email: str, log_fn: Callable[[str], None]):
        self.email_service = email_service
        self.email = email
        self.log_fn = log_fn
        self._used_codes = set()
    
    def wait_for_verification_code(
        self,
        email: str,
        timeout: int = 90,
        otp_sent_at: float = None,
        exclude_codes=None,
    ):
        """
        等待验证码
        
        Args:
            email: 邮箱地址
            timeout: 超时时间（秒）
            otp_sent_at: OTP 发送时间戳
            exclude_codes: 要排除的验证码集合（在这里处理，不传递给底层服务）
        
        Returns:
            验证码字符串，如果超时或收到已使用的验证码则返回 None
        """
        # 合并外部排除的验证码和已使用的验证码
        excluded = set(exclude_codes or set()) | set(self._used_codes)
        
        self.log_fn(f"正在等待邮箱 {email} 的验证码 ({timeout}s)...")
        
        # 调用邮箱服务获取验证码（不传递 exclude_codes，因为我们的服务不支持）
        code = self.email_service.get_verification_code(
            email=email,
            timeout=timeout,
            otp_sent_at=otp_sent_at,
        )
        
        if code:
            code = str(code).strip()
            
            # 检查是否是需要排除的验证码
            if code in excluded:
                self.log_fn(f"收到已使用的验证码: {code}，忽略")
                return None
            
            # 记录为已使用
            self._used_codes.add(code)
            self.log_fn(f"成功获取验证码: {code}")
        
        return code


class RegistrationEngineV3:
    """注册引擎 V3 - 完整移植 any-auto-register 方案"""
    
    def __init__(
        self,
        email_service,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None,
        browser_mode: str = "protocol",
        extra_config: Optional[dict] = None,
    ):
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid
        self.browser_mode = str(browser_mode or "protocol").strip().lower() or "protocol"
        self.extra_config = dict(extra_config or {})
        
        self.email = None
        self.password = None
        self.email_info = None
        self.logs = []
    
    def _log(self, message: str, level: str = "info"):
        """记录日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        self.logs.append(log_message)
        
        if self.callback_logger:
            self.callback_logger(log_message)
        
        if level == "error":
            logger.error(log_message)
        elif level == "warning":
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    def _create_email(self) -> bool:
        """创建邮箱"""
        try:
            self._log(f"正在创建 {self.email_service.service_type.value} 邮箱...")
            self.email_info = self.email_service.create_email()
            
            email_value = str(
                self.email
                or (self.email_info or {}).get("email")
                or ""
            ).strip()
            
            if not email_value:
                self._log(
                    f"创建邮箱失败: {self.email_service.service_type.value} 返回空邮箱地址",
                    "error",
                )
                return False
            
            if self.email_info is None:
                self.email_info = {}
            self.email_info["email"] = email_value
            self.email = email_value
            self._log(f"成功创建邮箱: {self.email}")
            return True
        except Exception as e:
            self._log(f"创建邮箱失败: {e}", "error")
            return False
    
    @staticmethod
    def _should_switch_to_login_after_register_failure(message: str) -> bool:
        """判断是否应该切换到登录流程"""
        text = str(message or "").lower()
        markers = (
            "user_already_exists",
            "account already exists",
            "please login instead",
            "add_phone",
            "add-phone",
        )
        return any(marker in text for marker in markers)
    
    def _read_int_config(
        self,
        primary_key: str,
        *,
        fallback_keys: tuple = (),
        default: int,
        minimum: int,
        maximum: int,
    ) -> int:
        """读取整数配置"""
        keys = (primary_key, *tuple(fallback_keys or ()))
        for key in keys:
            if key not in self.extra_config:
                continue
            value = self.extra_config.get(key)
            try:
                parsed = int(value)
            except Exception:
                continue
            return max(minimum, min(parsed, maximum))
        return max(minimum, min(int(default), maximum))
    
    def _build_chatgpt_client(self) -> ChatGPTClient:
        """构建 ChatGPT 客户端"""
        client = ChatGPTClient(
            proxy=self.proxy_url,
            verbose=False,
            browser_mode=self.browser_mode,
        )
        client._log = lambda msg: self._log(f"[注册] {msg}")
        return client
    
    def _build_oauth_client(self) -> OAuthClient:
        """构建 OAuth 客户端"""
        client = OAuthClient(
            self.extra_config,
            proxy=self.proxy_url,
            verbose=False,
            browser_mode=self.browser_mode,
        )
        client._log = lambda msg: self._log(f"[登录] {msg}")
        return client
    
    def run(self) -> RegistrationResultV3:
        """
        执行完整的注册流程
        
        策略：
        1. 使用 ChatGPTClient 执行注册状态机（到 about_you 停止）
        2. 创建全新的 OAuth 会话
        3. 使用 OAuthClient 执行登录状态机（完成 about_you + 获取 token）
        
        Returns:
            RegistrationResultV3: 注册结果
        """
        result = RegistrationResultV3(success=False, logs=self.logs)
        
        # 读取配置
        register_otp_wait_seconds = self._read_int_config(
            "chatgpt_register_otp_wait_seconds",
            fallback_keys=("chatgpt_otp_wait_seconds",),
            default=600,
            minimum=30,
            maximum=3600,
        )
        register_otp_resend_wait_seconds = self._read_int_config(
            "chatgpt_register_otp_resend_wait_seconds",
            fallback_keys=("chatgpt_register_otp_wait_seconds", "chatgpt_otp_wait_seconds"),
            default=300,
            minimum=30,
            maximum=3600,
        )
        
        try:
            registration_message = ""
            source = "register"
            
            self._log("=" * 60)
            self._log("ChatGPT V3 注册引擎启动")
            self._log(f"请求模式: {self.browser_mode}")
            self._log("实现策略: 注册状态机 + 全新 OAuth 会话 + 登录状态机")
            self._log("=" * 60)
            
            # 1. 创建邮箱
            self._log("1. 创建邮箱...")
            if not self._create_email():
                result.error_message = "创建邮箱失败"
                return result
            
            result.email = self.email or ""
            self.password = self.password or generate_random_password(16)
            result.password = self.password
            
            first_name, last_name = generate_random_name()
            birthdate = generate_random_birthday()
            self._log(f"邮箱: {result.email}")
            self._log(f"密码: {self.password}")
            self._log(f"注册信息: {first_name} {last_name}, 生日: {birthdate}")
            self._log(
                f"验证码等待策略: register_wait={register_otp_wait_seconds}s, "
                f"register_resend_wait={register_otp_resend_wait_seconds}s"
            )
            
            # 创建邮箱适配器
            email_adapter = EmailServiceAdapter(
                self.email_service,
                result.email,
                self._log,
            )
            
            # 2. 执行注册状态机
            register_client = self._build_chatgpt_client()
            self._log("2. 执行注册状态机（interrupt 模式：在 about_you 停止）...")
            registered, registration_message = register_client.register_complete_flow(
                result.email,
                self.password,
                first_name,
                last_name,
                birthdate,
                email_adapter,
                stop_before_about_you_submission=True,
                otp_wait_timeout=register_otp_wait_seconds,
                otp_resend_wait_timeout=register_otp_resend_wait_seconds,
            )
            
            if not registered:
                if not self._should_switch_to_login_after_register_failure(registration_message):
                    result.error_message = f"注册状态机失败: {registration_message}"
                    return result
                
                source = "login"
                self._log("注册阶段命中可恢复终态，切换到 OAuth 登录链路", "warning")
                self._log(f"切换原因: {registration_message}")
            else:
                if registration_message == "pending_about_you_submission":
                    self._log("注册状态机已推进至 about_you，符合预期")
                else:
                    self._log("注册状态机返回成功但未停在 about_you")
            
            # 3. 创建全新 OAuth 会话并登录
            oauth_client = self._build_oauth_client()
            use_login_front_half = registration_message == "pending_about_you_submission"
            
            if use_login_front_half:
                self._log("3. 新开 OAuth session，复刻 login_and_get_tokens 登录链路")
                self._log("4. 本轮仅共享邮箱+密码，其它会话数据全新")
                self._log("5. 登录成功后提交 about_you，并继续 workspace/token 流程")
                tokens = oauth_client.login_and_get_tokens(
                    result.email,
                    self.password,
                    device_id="",
                    user_agent=None,
                    sec_ch_ua=None,
                    impersonate=None,
                    skymail_client=email_adapter,
                    prefer_passwordless_login=False,
                    allow_phone_verification=False,
                    force_new_browser=True,
                    force_chatgpt_entry=False,
                    screen_hint="login",
                    force_password_login=True,
                    complete_about_you_if_needed=True,
                    first_name=first_name,
                    last_name=last_name,
                    birthdate=birthdate,
                    login_source=(
                        "existing_account_recovery"
                        if source == "login"
                        else "post_register_workspace_recovery"
                    ),
                    stop_after_login=False,
                )
            else:
                self._log("3. 新开 OAuth session，按 screen_hint=login + passwordless OTP 登录...")
                self._log("4. 若命中 about_you，则在 OAuth 会话内提交姓名+生日")
                tokens = oauth_client.login_and_get_tokens(
                    result.email,
                    self.password,
                    device_id="",
                    user_agent=getattr(register_client, "ua", None),
                    sec_ch_ua=getattr(register_client, "sec_ch_ua", None),
                    impersonate=getattr(register_client, "impersonate", None),
                    skymail_client=email_adapter,
                    prefer_passwordless_login=True,
                    allow_phone_verification=False,
                    force_new_browser=True,
                    force_chatgpt_entry=False,
                    screen_hint="login",
                    force_password_login=False,
                    complete_about_you_if_needed=True,
                    first_name=first_name,
                    last_name=last_name,
                    birthdate=birthdate,
                    login_source=(
                        "existing_account_recovery"
                        if source == "login"
                        else "post_register_workspace_recovery"
                    ),
                )
            
            if not tokens:
                result.error_message = oauth_client.last_error or "OAuth 登录状态机失败"
                return result
            
            # 填充结果
            result.success = True
            result.access_token = str(tokens.get("access_token") or "").strip()
            result.refresh_token = str(tokens.get("refresh_token") or "").strip()
            result.id_token = str(tokens.get("id_token") or "").strip()
            result.account_id = str(tokens.get("account_id") or "").strip()
            result.workspace_id = str(getattr(oauth_client, "last_workspace_id", "") or "").strip()
            result.session_token = str(getattr(oauth_client, "_extract_session_token", lambda: "")() or "").strip()
            result.device_id = getattr(register_client, "device_id", "")
            result.source = source
            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now().isoformat(),
                "registration_message": registration_message or "register_complete_flow:ok",
                "registration_flow": "chatgpt_client.register_complete_flow",
                "token_flow": "oauth_client.login_and_get_tokens",
                "browser_mode": self.browser_mode,
            }
            
            self._log("5. V3 主链路完成")
            self._log(f"Account ID: {result.account_id}")
            self._log(f"Workspace ID: {result.workspace_id}")
            self._log("=" * 60)
            return result
        
        except Exception as e:
            self._log(f"V3 注册主链路异常: {e}", "error")
            import traceback
            self._log(traceback.format_exc(), "error")
            result.error_message = str(e)
            return result
