from loguru import logger
from .policy_engine import PolicyEngine
from .decision_hub import DecisionHub
from .model_engine import ModelEngine

class OutputInspector:
    def __init__(self, asset_id: str = "default"):
        self.asset_id = asset_id
        self.policy_engine = PolicyEngine(asset_id)
        self.decision_hub = DecisionHub()
        self.model_engine = ModelEngine()
    
    async def inspect(self, text: str) -> dict:
        """检测输出文本的安全性"""
        if not text:
            return self.decision_hub.pass_decision()
        
        # 1. 首先使用模型进行检测（核心检测）
        model_result = await self.model_engine.detect_with_model(text, "output")
        if model_result["suggestion"] != "pass":
            logger.info(f"模型检测结果: {model_result}")
            return model_result
        
        # 2. 模型检测通过后，使用规则检测作为辅助（可选）
        violations = []
        actions = {}
        
        # 输出合规性检测
        if self.policy_engine.is_rule_enabled("output", "output_compliance"):
            rule = self.policy_engine.get_rule("output", "output_compliance")
            if self._check_output_compliance(text, rule):
                violations.append("output_compliance")
                actions["output_compliance"] = rule
        
        # 模型幻觉检测（规则辅助）
        if self.policy_engine.is_rule_enabled("output", "hallucination"):
            rule = self.policy_engine.get_rule("output", "hallucination")
            if self._check_hallucination(text, rule):
                violations.append("hallucination")
                actions["hallucination"] = rule
        
        # 如果规则检测有违规，生成裁决结果
        if violations:
            return self.decision_hub.generate_decision(violations, actions)
        
        # 无违规，通过
        return self.decision_hub.pass_decision()
    
    def _check_output_compliance(self, text: str, rule: dict) -> bool:
        """检测输出合规性（规则辅助）"""
        keywords = rule.get("keywords", [])
        for keyword in keywords:
            if keyword in text:
                logger.warning(f"规则检测到输出违规: {keyword}")
                return True
        return False
    
    def _check_hallucination(self, text: str, rule: dict) -> bool:
        """检测模型幻觉（规则辅助）"""
        # 简单的幻觉检测规则（基于关键词）
        hallucination_keywords = ["据报道", "据说", "可能", "大概", "推测", "疑似", "据称"]
        for keyword in hallucination_keywords:
            if keyword in text:
                logger.warning(f"规则检测到幻觉内容: {keyword}")
                return True
        return False
