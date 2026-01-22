import re
from loguru import logger
from .policy_engine import PolicyEngine
from .decision_hub import DecisionHub
from .model_engine import ModelEngine

class InputInspector:
    def __init__(self, asset_id: str = "default"):
        self.asset_id = asset_id
        self.policy_engine = PolicyEngine(asset_id)
        self.decision_hub = DecisionHub()
        self.model_engine = ModelEngine()
    
    async def inspect(self, text: str) -> dict:
        """检测输入文本的安全性"""
        if not text:
            return self.decision_hub.pass_decision()
        
        # 1. 首先使用模型进行检测（核心检测）
        model_result = await self.model_engine.detect_with_model(text, "input")
        if model_result["suggestion"] != "pass":
            logger.info(f"模型检测结果: {model_result}")
            return model_result
        
        # 2. 模型检测通过后，使用规则检测作为辅助（可选）
        violations = []
        actions = {}
        
        # 指令注入检测
        if self.policy_engine.is_rule_enabled("input", "prompt_injection"):
            rule = self.policy_engine.get_rule("input", "prompt_injection")
            if self._check_prompt_injection(text, rule):
                violations.append("prompt_injection")
                actions["prompt_injection"] = rule
        
        # 敏感信息检测
        if self.policy_engine.is_rule_enabled("input", "sensitive_info"):
            rule = self.policy_engine.get_rule("input", "sensitive_info")
            if self._check_sensitive_info(text, rule):
                violations.append("sensitive_info")
                actions["sensitive_info"] = rule
        
        # 合规性检查
        if self.policy_engine.is_rule_enabled("input", "compliance"):
            rule = self.policy_engine.get_rule("input", "compliance")
            if self._check_compliance(text, rule):
                violations.append("compliance")
                actions["compliance"] = rule
        
        # 如果规则检测有违规，生成裁决结果
        if violations:
            return self.decision_hub.generate_decision(violations, actions)
        
        # 无违规，通过
        return self.decision_hub.pass_decision()
    
    def _check_prompt_injection(self, text: str, rule: dict) -> bool:
        """检测指令注入（规则辅助）"""
        keywords = rule.get("keywords", [])
        for keyword in keywords:
            if keyword in text:
                logger.warning(f"规则检测到指令注入: {keyword}")
                return True
        return False
    
    def _check_sensitive_info(self, text: str, rule: dict) -> bool:
        """检测敏感信息（规则辅助）"""
        patterns = rule.get("patterns", [])
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                logger.warning(f"规则检测到敏感信息: {pattern}")
                return True
        return False
    
    def _check_compliance(self, text: str, rule: dict) -> bool:
        """检测合规性（规则辅助）"""
        keywords = rule.get("keywords", [])
        for keyword in keywords:
            if keyword in text:
                logger.warning(f"规则检测到违规内容: {keyword}")
                return True
        return False
