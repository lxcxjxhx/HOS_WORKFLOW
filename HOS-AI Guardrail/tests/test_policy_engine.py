import pytest
from src.core.policy_engine import PolicyEngine

class TestPolicyEngine:
    def test_load_policy(self):
        """测试加载策略"""
        engine = PolicyEngine("default")
        policy = engine.policy
        assert isinstance(policy, dict)
        assert "input" in policy
        assert "output" in policy
    
    def test_get_rules(self):
        """测试获取规则"""
        engine = PolicyEngine("default")
        input_rules = engine.get_rules("input")
        output_rules = engine.get_rules("output")
        
        assert isinstance(input_rules, dict)
        assert isinstance(output_rules, dict)
        assert "prompt_injection" in input_rules
        assert "output_compliance" in output_rules
    
    def test_get_rule(self):
        """测试获取特定规则"""
        engine = PolicyEngine("default")
        rule = engine.get_rule("input", "prompt_injection")
        
        assert isinstance(rule, dict)
        assert rule.get("enabled") is True
        assert isinstance(rule.get("keywords"), list)
    
    def test_is_rule_enabled(self):
        """测试规则是否启用"""
        engine = PolicyEngine("default")
        
        # 启用的规则
        assert engine.is_rule_enabled("input", "prompt_injection") is True
        
        # 禁用的规则
        assert engine.is_rule_enabled("output", "hallucination") is False
        
        # 不存在的规则
        assert engine.is_rule_enabled("input", "non_existent_rule") is False
    
    def test_reload_policy(self):
        """测试重新加载策略"""
        engine = PolicyEngine("default")
        original_policy = engine.policy.copy()
        
        engine.reload_policy()
        reloaded_policy = engine.policy
        
        assert original_policy == reloaded_policy
