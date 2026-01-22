from loguru import logger
from .policy_engine import PolicyEngine
from .decision_hub import DecisionHub

class OutputInspector:
    def __init__(self, asset_id: str = "default"):
        self.asset_id = asset_id
        self.policy_engine = PolicyEngine(asset_id)
        self.decision_hub = DecisionHub()
    
    def inspect(self, text: str) -> dict:
        """检测输出文本的安全性"""
        if not text:
            return self.decision_hub.pass_decision()
        
        # 初始化结果
        violations = []
        actions = {}
        
        # 1. 输出合规性检测
        if self.policy_engine.is_rule_enabled("output", "output_compliance"):
            rule = self.policy_engine.get_rule("output", "output_compliance")
            if self._check_output_compliance(text, rule):
                violations.append("output_compliance")
                actions["output_compliance"] = rule
        
        # 2. 模型幻觉检测（暂未实现）
        if self.policy_engine.is_rule_enabled("output", "hallucination"):
            rule = self.policy_engine.get_rule("output", "hallucination")
            # 幻觉检测逻辑待实现
            # if self._check_hallucination(text, rule):
            #     violations.append("hallucination")
            #     actions["hallucination"] = rule
        
        # 如果有违规，生成裁决结果
        if violations:
            return self.decision_hub.generate_decision(violations, actions)
        
        # 无违规，通过
        return self.decision_hub.pass_decision()
    
    def _check_output_compliance(self, text: str, rule: dict) -> bool:
        """检测输出合规性"""
        keywords = rule.get("keywords", [])
        for keyword in keywords:
            if keyword in text:
                logger.warning(f"检测到输出违规: {keyword}")
                return True
        return False
    
    def _check_hallucination(self, text: str, rule: dict) -> bool:
        """检测模型幻觉"""
        # 幻觉检测逻辑待实现
        # 可以基于关键词、事实核查等方式实现
        return False
