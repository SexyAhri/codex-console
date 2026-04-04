"""
注册引擎 - 统一入口
负责协调邮箱服务和注册流程
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Optional

from .register_v3 import RegistrationEngineV3, RegistrationResultV3

logger = logging.getLogger(__name__)


@dataclass
class RegistrationResult:
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
    source: str = "register"  # 'register' 或 'login'，区分账号来源

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
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


class RegistrationEngine:
    """
    注册引擎 - 统一入口
    内部使用 V3 引擎（从 any-auto-register 完整移植）
    """

    def __init__(
        self,
        email_service,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None
    ):
        """
        初始化注册引擎

        Args:
            email_service: 邮箱服务实例
            proxy_url: 代理 URL
            callback_logger: 日志回调函数
            task_uuid: 任务 UUID（用于数据库记录）
        """
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid
        self.logs: list = []

    def _log(self, message: str, level: str = "info"):
        """记录日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        self.logs.append(log_message)

        if self.callback_logger:
            self.callback_logger(log_message)

        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)

    def run(self) -> RegistrationResult:
        """
        执行注册流程

        Returns:
            RegistrationResult: 注册结果
        """
        try:
            self._log("=" * 80)
            self._log("使用 V3 注册引擎（从 any-auto-register 完整移植）")
            self._log("=" * 80)

            # 创建 V3 引擎
            engine_v3 = RegistrationEngineV3(
                email_service=self.email_service,
                proxy_url=self.proxy_url,
                callback_logger=self.callback_logger,
                task_uuid=self.task_uuid,
                browser_mode="protocol",  # 使用 protocol 模式（纯 HTTP）
                extra_config={},
            )

            # 执行完整流程（注册 + 登录 + 获取 token）
            v3_result: RegistrationResultV3 = engine_v3.run()

            # 转换结果
            result = RegistrationResult(success=v3_result.success, logs=self.logs + v3_result.logs)
            result.email = v3_result.email
            result.password = v3_result.password
            result.account_id = v3_result.account_id
            result.workspace_id = v3_result.workspace_id
            result.access_token = v3_result.access_token
            result.refresh_token = v3_result.refresh_token
            result.id_token = v3_result.id_token
            result.session_token = v3_result.session_token
            result.device_id = v3_result.device_id
            result.error_message = v3_result.error_message
            result.metadata = v3_result.metadata
            result.source = v3_result.source

            if result.success:
                self._log("=" * 80)
                self._log("✅ 注册成功！")
                self._log(f"邮箱: {result.email}")
                self._log(f"Account ID: {result.account_id}")
                self._log(f"Workspace ID: {result.workspace_id}")
                self._log(f"Device ID: {result.device_id or '-'}")
                self._log("=" * 80)
            else:
                self._log("=" * 80)
                self._log(f"❌ 注册失败: {result.error_message}")
                self._log("=" * 80)

            return result

        except Exception as e:
            import traceback
            self._log("=" * 80)
            self._log(f"注册引擎异常: {e}", "error")
            self._log(traceback.format_exc(), "error")
            self._log("=" * 80)
            result = RegistrationResult(success=False, logs=self.logs)
            result.error_message = f"注册引擎异常: {e}"
            return result
