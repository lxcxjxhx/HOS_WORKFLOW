import yaml
import os
from loguru import logger

class PolicyEngine:
    def __init__(self, asset_id: str = "default"):
        self.asset_id = asset_id
        self.policy = self._load_policy()
    
    def _load_policy(self):
        """加载策略配置文件"""
        policy_path = os.path.join(os.path.dirname(__file__), "../config/policy.yaml")
        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                policy = yaml.safe_load(f)
            # 使用资产特定策略或默认策略
            return policy.get(self.asset_id, policy.get("default", {}))
        except Exception as e:
            logger.error(f"加载策略文件失败: {e}")
            return {}
    
    def get_rules(self, detection_type: str):
        """获取指定检测类型的规则"""
        return self.policy.get(detection_type, {})
    
    def get_rule(self, detection_type: str, rule_name: str):
        """获取指定规则"""
        rules = self.get_rules(detection_type)
        return rules.get(rule_name, {})
    
    def is_rule_enabled(self, detection_type: str, rule_name: str):
        """检查规则是否启用"""
        rule = self.get_rule(detection_type, rule_name)
        return rule.get("enabled", False)
    
    def reload_policy(self):
        """重新加载策略"""
        self.policy = self._load_policy()
        logger.info(f"策略已重新加载: {self.asset_id}")
