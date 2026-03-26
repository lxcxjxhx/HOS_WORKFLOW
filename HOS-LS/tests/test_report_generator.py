#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告生成模块测试
"""

import os
import sys
import tempfile
import unittest

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.report_generator import ReportGenerator

class TestReportGenerator(unittest.TestCase):
    """报告生成模块测试"""
    
    def setUp(self):
        """设置测试环境"""
        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()
        
        # 模拟扫描结果
        self.scan_results = {
            'code_security': [
                {'file': 'test.py', 'issue': '硬编码的敏感信息', 'severity': 'high', 'details': '发现API密钥'},
                {'file': 'test.py', 'issue': '潜在的后门代码', 'severity': 'high', 'details': '发现exec函数'}
            ],
            'permission_security': [
                {'file': 'model.pt', 'issue': '模型文件权限过于宽松', 'severity': 'high', 'details': '权限为777'}
            ],
            'network_security': [
                {'file': 'server.py', 'issue': '端口暴露到公网', 'severity': 'medium', 'details': '监听0.0.0.0'}
            ],
            'dependency_security': [
                {'file': 'requirements.txt', 'issue': '依赖库版本未固定', 'severity': 'medium', 'details': '未使用=='}
            ],
            'config_security': [
                {'file': 'config.json', 'issue': '配置文件包含敏感信息', 'severity': 'high', 'details': '发现密码'}
            ],
            'project_type': 'openclaw',
            'rule_set': 'openclaw'
        }
    
    def tearDown(self):
        """清理测试环境"""
        # 删除临时目录
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_generate_html(self):
        """测试生成HTML报告"""
        generator = ReportGenerator(self.scan_results, 'test_target', self.temp_dir)
        report_path = generator.generate_html()
        
        # 验证报告文件存在
        self.assertTrue(os.path.exists(report_path))
        
        # 验证报告内容
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn('HOS-LS 安全检测报告', content)
        self.assertIn('test_target', content)
        self.assertIn('openclaw', content)
        self.assertIn('高风险', content)
        self.assertIn('中风险', content)
    
    def test_generate_docx(self):
        """测试生成DOCX报告"""
        generator = ReportGenerator(self.scan_results, 'test_target', self.temp_dir)
        report_path = generator.generate_docx()
        
        # 验证报告文件存在
        self.assertTrue(os.path.exists(report_path))
    
    def test_generate_md(self):
        """测试生成MD报告"""
        generator = ReportGenerator(self.scan_results, 'test_target', self.temp_dir)
        report_path = generator.generate_md()
        
        # 验证报告文件存在
        self.assertTrue(os.path.exists(report_path))
        
        # 验证报告内容
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn('# HOS-LS 安全检测报告', content)
        self.assertIn('test_target', content)
        self.assertIn('高风险', content)
        self.assertIn('中风险', content)

if __name__ == '__main__':
    unittest.main()