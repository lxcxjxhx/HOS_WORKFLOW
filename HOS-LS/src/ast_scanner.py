#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AST 分析检测模块

功能：
1. 使用 Python AST 模块解析代码
2. 识别危险函数调用
3. 追踪数据流
4. 检测变量赋值和使用
5. 提供比正则更精确的检测
"""

import ast
import os
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class SecurityVisitor(ast.NodeVisitor):
    """AST 安全访问者"""
    
    def __init__(self, filename: str, source_code: str):
        self.filename = filename
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.issues = []
        self.dangerous_functions = {
            'eval': '使用 eval() 可能导致代码注入',
            'exec': '使用 exec() 可能导致代码注入',
            'compile': '使用 compile() 可能执行动态代码',
            'open': '文件操作需要验证路径',
            'input': '用户输入需要验证',
            '__import__': '动态导入可能存在风险',
        }
        self.dangerous_methods = {
            'system': 'os.system() 可能执行系统命令',
            'popen': 'os.popen() 可能执行系统命令',
            'spawn': 'os.spawn* 可能执行系统命令',
            'call': 'subprocess.call 可能执行系统命令',
            'run': 'subprocess.run 可能执行系统命令',
            'Popen': 'subprocess.Popen 可能执行系统命令',
            'load': 'pickle.load 可能反序列化恶意数据',
            'loads': 'pickle.loads 可能反序列化恶意数据',
        }
        self.dangerous_modules = ['pickle', 'marshal', 'shelve', 'commands']
    
    def visit_Call(self, node):
        """访问函数调用节点"""
        # 检查危险函数
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.dangerous_functions:
                self._report_issue(
                    node.lineno,
                    'HIGH' if func_name in ['eval', 'exec', 'compile'] else 'MEDIUM',
                    f"危险函数调用：{func_name}()",
                    self.dangerous_functions[func_name],
                    self._get_code_snippet(node.lineno)
                )
            
            # 检查输入函数
            if func_name == 'input':
                # 检查是否有验证
                if not self._has_validation_nearby(node.lineno):
                    self._report_issue(
                        node.lineno,
                        'MEDIUM',
                        '用户输入缺少验证',
                        'input() 获取的用户输入应该进行验证和过滤',
                        self._get_code_snippet(node.lineno)
                    )
        
        # 检查危险方法调用
        elif isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            
            # 检查 os.system, os.popen 等
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                if module_name in ['os', 'subprocess', 'pickle', 'marshal', 'commands']:
                    if method_name in self.dangerous_methods:
                        # 特殊检查：subprocess 的 shell=True
                        if method_name in ['call', 'run', 'Popen']:
                            if self._has_shell_true(node):
                                self._report_issue(
                                    node.lineno,
                                    'HIGH',
                                    f'危险方法调用：{module_name}.{method_name}() with shell=True',
                                    'subprocess 使用 shell=True 可能导致命令注入',
                                    self._get_code_snippet(node.lineno)
                                )
                        else:
                            self._report_issue(
                                node.lineno,
                                'HIGH' if module_name in ['os', 'commands'] else 'MEDIUM',
                                f'危险方法调用：{module_name}.{method_name}()',
                                self.dangerous_methods[method_name],
                                self._get_code_snippet(node.lineno)
                            )
            
            # 检查 requests 调用
            if method_name in ['get', 'post', 'put', 'delete', 'patch', 'request']:
                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'requests':
                    # 检查是否有 timeout 和 verify
                    has_timeout = any(
                        isinstance(kw, ast.keyword) and kw.arg == 'timeout'
                        for kw in node.keywords
                    )
                    has_verify = any(
                        isinstance(kw, ast.keyword) and kw.arg == 'verify'
                        for kw in node.keywords
                    )
                    
                    if not has_timeout:
                        self._report_issue(
                            node.lineno,
                            'LOW',
                            '网络请求缺少超时设置',
                            'requests 请求应该设置 timeout 参数',
                            self._get_code_snippet(node.lineno)
                        )
                    
                    if not has_verify:
                        self._report_issue(
                            node.lineno,
                            'MEDIUM',
                            '网络请求缺少 SSL 验证',
                            'requests 请求应该设置 verify=True',
                            self._get_code_snippet(node.lineno)
                        )
        
        self.generic_visit(node)
    
    def visit_Import(self, node):
        """访问导入语句"""
        for alias in node.names:
            if alias.name in self.dangerous_modules:
                self._report_issue(
                    node.lineno,
                    'MEDIUM',
                    f'导入危险模块：{alias.name}',
                    f'{alias.name} 模块可能带来安全风险，请谨慎使用',
                    self._get_code_snippet(node.lineno)
                )
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """访问 from 导入语句"""
        if node.module in self.dangerous_modules:
            self._report_issue(
                node.lineno,
                'MEDIUM',
                f'从危险模块导入：{node.module}',
                f'{node.module} 模块可能带来安全风险',
                self._get_code_snippet(node.lineno)
            )
        self.generic_visit(node)
    
    def visit_Assign(self, node):
        """访问赋值语句"""
        # 检查敏感信息赋值
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(secret in var_name for secret in ['password', 'passwd', 'pwd', 'secret', 'api_key', 'token', 'private_key']):
                    # 检查是否是字符串字面量赋值
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        # 排除示例和占位符
                        value = node.value.value
                        if not self._is_placeholder(value):
                            self._report_issue(
                                node.lineno,
                                'HIGH',
                                f'硬编码敏感信息：{target.id}',
                                '敏感信息应该存储在环境变量或配置文件中',
                                self._get_code_snippet(node.lineno)
                            )
        self.generic_visit(node)
    
    def visit_BinOp(self, node):
        """访问二元操作（检测字符串拼接）"""
        # 检查 SQL 查询拼接
        if isinstance(node.op, (ast.Add, ast.Mod)):
            if self._is_sql_query(node):
                self._report_issue(
                    node.lineno,
                    'HIGH',
                    'SQL 查询字符串拼接',
                    '使用参数化查询替代字符串拼接',
                    self._get_code_snippet(node.lineno)
                )
        self.generic_visit(node)
    
    def _is_sql_query(self, node) -> bool:
        """检查是否是 SQL 查询"""
        # 检查左操作数是否包含 SQL 关键字
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE']
            return any(kw in node.left.value.upper() for kw in sql_keywords)
        return False
    
    def _has_shell_true(self, node) -> bool:
        """检查 subprocess 调用是否有 shell=True"""
        for kw in node.keywords:
            if kw.arg == 'shell':
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
                elif isinstance(kw.value, ast.Name) and kw.value.id == 'True':
                    return True
        return False
    
    def _has_validation_nearby(self, lineno: int) -> bool:
        """检查附近是否有验证代码"""
        start = max(0, lineno - 5)
        end = min(len(self.source_lines), lineno + 5)
        context = '\n'.join(self.source_lines[start:end])
        
        validation_patterns = [
            'validate', 'check', 'verify', 'sanitize', 'filter',
            'if len', 'isinstance', 'try:', 'except'
        ]
        
        return any(pattern in context.lower() for pattern in validation_patterns)
    
    def _is_placeholder(self, value: str) -> bool:
        """检查是否是占位符值"""
        placeholders = [
            'your_', 'example', 'placeholder', 'xxx', 'change_me',
            'todo', 'fixme', 'test', 'demo', 'sample'
        ]
        return any(p in value.lower() for p in placeholders)
    
    def _get_code_snippet(self, lineno: int) -> str:
        """获取代码片段"""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ''
    
    def _report_issue(self, lineno: int, severity: str, issue: str, 
                     details: str, code_snippet: str):
        """报告问题"""
        self.issues.append({
            'line_number': lineno,
            'severity': severity,
            'issue': issue,
            'details': details,
            'code_snippet': code_snippet,
            'category': 'ast_analysis'
        })


class ASTScanner:
    """AST 扫描器类"""
    
    def __init__(self):
        self.results = []
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """扫描单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            
            # 解析 AST
            try:
                tree = ast.parse(source_code)
            except SyntaxError as e:
                logger.debug(f"AST 解析失败 {file_path}: {e}")
                return []
            
            # 创建访问者并遍历
            visitor = SecurityVisitor(file_path, source_code)
            visitor.visit(tree)
            
            # 添加文件信息到每个问题
            for issue in visitor.issues:
                issue['file'] = file_path
            
            return visitor.issues
        
        except Exception as e:
            logger.error(f"AST 扫描文件 {file_path} 时出错：{e}")
            return []
    
    def scan_directory(self, directory: str, extensions: List[str] = None) -> List[Dict[str, Any]]:
        """扫描目录"""
        if extensions is None:
            extensions = ['.py', '.pyw']
        
        results = []
        
        for root, dirs, files in os.walk(directory):
            # 跳过常见忽略目录
            dirs[:] = [d for d in dirs if d not in [
                'node_modules', 'venv', '.venv', '__pycache__',
                '.git', 'dist', 'build', 'target'
            ]]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    issues = self.scan_file(file_path)
                    results.extend(issues)
        
        return results
    
    def analyze(self, target: str) -> List[Dict[str, Any]]:
        """分析目标（文件或目录）"""
        if os.path.isfile(target):
            return self.scan_file(target)
        elif os.path.isdir(target):
            return self.scan_directory(target)
        else:
            logger.warning(f"目标不存在：{target}")
            return []


def scan_with_ast(target: str) -> List[Dict[str, Any]]:
    """便捷函数：使用 AST 扫描目标"""
    scanner = ASTScanner()
    return scanner.analyze(target)


if __name__ == '__main__':
    # 测试 AST 扫描器
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = '.'
    
    print(f"开始 AST 安全扫描：{target}")
    results = scan_with_ast(target)
    
    if results:
        print(f"\n发现 {len(results)} 个潜在安全问题:\n")
        for issue in results:
            print(f"[{issue['severity']}] {issue['file']}:{issue['line_number']}")
            print(f"  问题：{issue['issue']}")
            print(f"  详情：{issue['details']}")
            print(f"  代码：{issue['code_snippet']}\n")
    else:
        print("\n未发现 AST 级别的安全问题")
