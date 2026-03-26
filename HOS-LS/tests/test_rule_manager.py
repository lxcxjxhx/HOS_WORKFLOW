#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则管理模块测试
"""

import os
import sys
import unittest

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from rules.rule_manager import RuleManager

class TestRuleManager(unittest.TestCase):
    """规则管理模块测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.manager = RuleManager()
    
    def test_load_rules(self):
        """测试加载规则功能"""
        # 验证规则是否加载成功
        rules = self.manager.get_rules()
        self.assertGreater(len(rules), 0)
    
    def test_get_rules(self):
        """测试获取规则功能"""
        # 获取所有规则
        all_rules = self.manager.get_rules()
        self.assertGreater(len(all_rules), 0)
        
        # 按类别获取规则
        code_rules = self.manager.get_rules(category='code_security')
        self.assertGreater(len(code_rules), 0)
        
        # 按严重程度获取规则
        high_rules = self.manager.get_high_severity_rules()
        self.assertGreater(len(high_rules), 0)
    
    def test_translate_rules(self):
        """测试翻译规则功能"""
        # 测试翻译到Cursor格式
        cursor_prompt = self.manager.translate_rules('cursor')
        self.assertGreater(len(cursor_prompt), 0)
        
        # 测试翻译到Trae格式
        trae_prompt = self.manager.translate_rules('trae')
        self.assertGreater(len(trae_prompt), 0)
        
        # 测试翻译到Kiro格式
        kiro_prompt = self.manager.translate_rules('kiro')
        self.assertGreater(len(kiro_prompt), 0)
    
    def test_get_openclaw_rules(self):
        """测试获取OpenClaw规则功能"""
        openclaw_rules = self.manager.get_openclaw_rules()
        self.assertGreater(len(openclaw_rules), 0)
    
    def test_get_cursor_rules(self):
        """测试获取Cursor规则功能"""
        cursor_rules = self.manager.get_cursor_rules()
        self.assertGreater(len(cursor_rules), 0)
    
    def test_list_rule_sets(self):
        """测试列出规则集功能"""
        rule_sets = self.manager.list_rule_sets()
        self.assertGreater(len(rule_sets), 0)

if __name__ == '__main__':
    unittest.main()