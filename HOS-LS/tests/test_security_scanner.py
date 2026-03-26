#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全扫描模块测试
"""

import os
import sys
import tempfile
import unittest

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.security_scanner import SecurityScanner

class TestSecurityScanner(unittest.TestCase):
    """安全扫描模块测试"""
    
    def setUp(self):
        """设置测试环境"""
        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()
        
        # 创建测试文件
        self.create_test_files()
    
    def tearDown(self):
        """清理测试环境"""
        # 删除临时目录
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def create_test_files(self):
        """创建测试文件"""
        # 创建包含硬编码敏感信息的文件
        with open(os.path.join(self.temp_dir, 'test_secrets.py'), 'w') as f:
            f.write('api_key = "secret_key_123"\n')
            f.write('password = "my_password"\n')
        
        # 创建包含后门代码的文件
        with open(os.path.join(self.temp_dir, 'test_backdoor.py'), 'w') as f:
            f.write('import os\n')
            f.write('exec("print(\"Hello\")")\n')
        
        # 创建包含网络访问代码的文件
        with open(os.path.join(self.temp_dir, 'test_network.py'), 'w') as f:
            f.write('import requests\n')
            f.write('response = requests.get("https://example.com")\n')
        
        # 创建配置文件
        with open(os.path.join(self.temp_dir, 'config.json'), 'w') as f:
            f.write('{"api_key": "secret_key_123"}\n')
        
        # 创建依赖文件
        with open(os.path.join(self.temp_dir, 'requirements.txt'), 'w') as f:
            f.write('requests\n')
            f.write('numpy\n')
    
    def test_scan(self):
        """测试扫描功能"""
        scanner = SecurityScanner(self.temp_dir)
        results = scanner.scan()
        
        # 验证扫描结果结构
        self.assertIn('code_security', results)
        self.assertIn('permission_security', results)
        self.assertIn('network_security', results)
        self.assertIn('dependency_security', results)
        self.assertIn('config_security', results)
        
        # 验证扫描结果内容
        code_security = results['code_security']
        self.assertTrue(any('硬编码的' in item.get('issue', '') for item in code_security))
        self.assertTrue(any('潜在的后门代码' in item.get('issue', '') for item in code_security))
        self.assertTrue(any('网络访问代码' in item.get('issue', '') for item in code_security))
        
        config_security = results['config_security']
        self.assertTrue(any('敏感信息' in item.get('issue', '') for item in config_security))
        
        dependency_security = results['dependency_security']
        self.assertTrue(any('依赖库' in item.get('issue', '') for item in dependency_security))

if __name__ == '__main__':
    unittest.main()