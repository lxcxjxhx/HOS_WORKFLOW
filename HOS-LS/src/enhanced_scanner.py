#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
核心安全检测模块 - 增强版

功能：
1. 正则表达式检测
2. AST 抽象语法树分析
3. 上下文感知检测
4. 误报过滤机制
5. 置信度评分
6. 行号和代码片段提取
"""

import os
import re
import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from colorama import Fore, Style

try:
    from .ast_scanner import ASTScanner
except ImportError:
    ASTScanner = None

logger = logging.getLogger(__name__)


class EnhancedSecurityScanner:
    """增强型安全扫描器"""
    
    def __init__(self, target: str, rules_file: str = None, silent: bool = False):
        """初始化扫描器
        
        Args:
            target: 要扫描的目标路径
            rules_file: 规则文件路径（可选）
            silent: 是否启用静默模式
        """
        self.target = target
        self.silent = silent
        self.rules_file = rules_file
        self.rules = self._load_rules()
        self.false_positive_filters = self._load_fp_filters()
        
        self.results = {
            "target": target,
            "code_security": [],
            "injection_security": [],
            "ai_security": [],
            "container_security": [],
            "cloud_security": [],
            "privacy_security": [],
            "permission_security": [],
            "network_security": [],
            "dependency_security": [],
            "config_security": []
        }
        self.high_risk = 0
        self.medium_risk = 0
        self.low_risk = 0
        
        # 初始化 AST 扫描器
        self.ast_scanner = ASTScanner() if ASTScanner else None
    
    def _load_rules(self) -> Dict[str, Any]:
        """加载规则配置"""
        if self.rules_file is None:
            self.rules_file = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'rules',
                'security_rules.json'
            )
        
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('rules', {})
        except Exception as e:
            logger.error(f"加载规则文件失败：{e}")
            return {}
    
    def _load_fp_filters(self) -> Dict[str, Any]:
        """加载误报过滤配置"""
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('false_positive_filters', {})
        except Exception as e:
            logger.error(f"加载误报过滤配置失败：{e}")
            return {}
    
    def scan(self) -> Dict[str, Any]:
        """执行完整扫描"""
        if not self.silent:
            print(f'{Fore.BLUE}开始增强安全扫描...{Style.RESET_ALL}')
        
        # 1. AST 分析（如果可用）
        if self.ast_scanner:
            self._scan_with_ast()
        
        # 2. 正则检测
        self._scan_with_regex()
        
        # 3. 上下文分析
        self._analyze_context()
        
        # 4. 误报过滤
        self._filter_false_positives()
        
        # 5. 计算置信度
        self._calculate_confidence()
        
        if not self.silent:
            print(f'{Fore.GREEN}扫描完成!{Style.RESET_ALL}')
            print(f'{Fore.RED}高风险：{self.high_risk}{Style.RESET_ALL}')
            print(f'{Fore.YELLOW}中风险：{self.medium_risk}{Style.RESET_ALL}')
            print(f'{Fore.GREEN}低风险：{self.low_risk}{Style.RESET_ALL}')
        
        return self.results
    
    def _scan_with_ast(self):
        """使用 AST 分析扫描"""
        if not self.silent:
            print(f'{Fore.CYAN}AST 分析...{Style.RESET_ALL}')
        
        try:
            ast_results = self.ast_scanner.analyze(self.target)
            
            for issue in ast_results:
                category = 'code_security'
                self.results[category].append({
                    'file': issue['file'],
                    'line_number': issue['line_number'],
                    'issue': issue['issue'],
                    'severity': issue['severity'].lower(),
                    'details': issue['details'],
                    'code_snippet': issue['code_snippet'],
                    'detection_method': 'ast',
                    'confidence': 0.9,
                    'category': category
                })
                
                if issue['severity'] == 'HIGH':
                    self.high_risk += 1
                elif issue['severity'] == 'MEDIUM':
                    self.medium_risk += 1
                else:
                    self.low_risk += 1
        except Exception as e:
            logger.error(f"AST 扫描失败：{e}")
    
    def _scan_with_regex(self):
        """使用正则表达式扫描"""
        if not self.silent:
            print(f'{Fore.CYAN}正则检测...{Style.RESET_ALL}')
        
        # 遍历所有规则类别
        for category, rules in self.rules.items():
            if not self.silent:
                print(f'{Fore.CYAN}扫描 {category}...{Style.RESET_ALL}')
            
            for rule_name, rule in rules.items():
                patterns = rule.get('patterns', [])
                if not patterns:
                    continue
                
                self._apply_rule(category, rule_name, rule, patterns)
    
    def _apply_rule(self, category: str, rule_name: str, rule: Dict, patterns: List[str]):
        """应用单个规则"""
        severity = rule.get('severity', 'MEDIUM').lower()
        exclude_patterns = rule.get('exclude_patterns', [])
        
        # 遍历目标文件
        for root, dirs, files in os.walk(self.target):
            # 跳过忽略目录
            dirs[:] = [d for d in dirs if d not in [
                'node_modules', 'venv', '.venv', '__pycache__',
                '.git', 'dist', 'build', 'target', '.trae'
            ]]
            
            for file in files:
                if not file.endswith(('.py', '.js', '.json', '.yaml', '.yml', '.env', '.tf', '.toml', '.ini')):
                    continue
                
                file_path = os.path.join(root, file)
                
                # 检查是否在误报路径中
                if self._is_fp_path(file_path):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.splitlines()
                    
                    # 应用所有模式
                    for pattern in patterns:
                        try:
                            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                            
                            for match in matches:
                                # 获取匹配的行号
                                line_number = content[:match.start()].count('\n') + 1
                                code_snippet = lines[line_number - 1] if line_number <= len(lines) else ''
                                
                                # 检查排除模式
                                if self._matches_exclude(content, line_number, exclude_patterns):
                                    continue
                                
                                # 创建问题记录
                                issue = {
                                    'file': file_path,
                                    'line_number': line_number,
                                    'issue': rule.get('name', rule_name),
                                    'severity': severity,
                                    'details': rule.get('description', ''),
                                    'code_snippet': code_snippet.strip(),
                                    'match': match.group(0),
                                    'detection_method': 'regex',
                                    'confidence': rule.get('confidence', 0.7),
                                    'weight': rule.get('weight', 1.0),
                                    'cwe': rule.get('cwe', ''),
                                    'owasp': rule.get('owasp', ''),
                                    'fix': rule.get('fix', ''),
                                    'category': category
                                }
                                
                                self.results[category].append(issue)
                                
                                # 统计风险
                                if severity == 'high':
                                    self.high_risk += 1
                                elif severity == 'medium':
                                    self.medium_risk += 1
                                else:
                                    self.low_risk += 1
                        
                        except re.error as e:
                            logger.debug(f"正则表达式错误 {pattern}: {e}")
                
                except Exception as e:
                    logger.error(f"读取文件 {file_path} 时出错：{e}")
    
    def _is_fp_path(self, file_path: str) -> bool:
        """检查是否是误报路径"""
        path_patterns = self.false_positive_filters.get('path_patterns', [])
        
        for pattern in path_patterns:
            if pattern in file_path:
                return True
        
        return False
    
    def _matches_exclude(self, content: str, line_number: int, exclude_patterns: List[str]) -> bool:
        """检查是否匹配排除模式"""
        if not exclude_patterns:
            return False
        
        # 获取上下文（前后 5 行）
        lines = content.splitlines()
        start = max(0, line_number - 5)
        end = min(len(lines), line_number + 5)
        context = '\n'.join(lines[start:end])
        
        for pattern in exclude_patterns:
            try:
                if re.search(pattern, context, re.IGNORECASE):
                    return True
            except re.error:
                if pattern in context:
                    return True
        
        return False
    
    def _analyze_context(self):
        """分析上下文，调整风险等级"""
        if not self.silent:
            print(f'{Fore.CYAN}上下文分析...{Style.RESET_ALL}')
        
        for category, issues in self.results.items():
            if not isinstance(issues, list):
                continue
            
            for issue in issues:
                # 获取文件内容
                try:
                    with open(issue['file'], 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.splitlines()
                    
                    line_number = issue.get('line_number', 1)
                    
                    # 获取上下文
                    start = max(0, line_number - 5)
                    end = min(len(lines), line_number + 5)
                    context = '\n'.join(lines[start:end])
                    
                    # 检查是否有安全处理
                    if self._has_safe_context(context, issue):
                        # 降低风险等级
                        if issue['severity'] == 'high':
                            issue['severity'] = 'medium'
                            self.high_risk -= 1
                            self.medium_risk += 1
                        elif issue['severity'] == 'medium':
                            issue['severity'] = 'low'
                            self.medium_risk -= 1
                            self.low_risk += 1
                        
                        issue['context_analysis'] = '检测到安全处理代码'
                
                except Exception as e:
                    logger.debug(f"上下文分析失败：{e}")
    
    def _has_safe_context(self, context: str, issue: Dict) -> bool:
        """检查是否有安全的上下文"""
        safe_patterns = [
            r'os\.environ\.get',
            r'getenv',
            r'load_dotenv',
            r'validate',
            r'sanitize',
            r'filter',
            r'check',
            r'verify',
            r'timeout\s*=',
            r'verify\s*=\s*True',
            r'ast\.literal_eval',
            r'yaml\.safe_load',
            r'parameterized',
            r'prepared\s+statement'
        ]
        
        for pattern in safe_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _filter_false_positives(self):
        """过滤误报"""
        if not self.silent:
            print(f'{Fore.CYAN}过滤误报...{Style.RESET_ALL}')
        
        file_patterns = self.false_positive_filters.get('file_patterns', [])
        code_patterns = self.false_positive_filters.get('code_patterns', [])
        
        for category, issues in self.results.items():
            if not isinstance(issues, list):
                continue
            
            # 过滤文件模式
            filtered_issues = []
            for issue in issues:
                file_name = os.path.basename(issue['file'])
                is_fp = False
                
                # 检查文件模式
                for pattern in file_patterns:
                    # 转换为正则
                    regex_pattern = pattern.replace('*', '.*').replace('?', '.')
                    if re.match(regex_pattern, file_name, re.IGNORECASE):
                        is_fp = True
                        break
                
                # 检查代码模式
                if not is_fp and code_patterns:
                    code_snippet = issue.get('code_snippet', '')
                    for pattern in code_patterns:
                        try:
                            if re.search(pattern, code_snippet, re.IGNORECASE):
                                is_fp = True
                                break
                        except re.error:
                            if pattern in code_snippet:
                                is_fp = True
                                break
                
                if not is_fp:
                    filtered_issues.append(issue)
                else:
                    # 从统计中移除
                    severity = issue.get('severity', 'low')
                    if severity == 'high':
                        self.high_risk -= 1
                    elif severity == 'medium':
                        self.medium_risk -= 1
                    else:
                        self.low_risk -= 1
            
            self.results[category] = filtered_issues
    
    def _calculate_confidence(self):
        """计算置信度评分"""
        for category, issues in self.results.items():
            if not isinstance(issues, list):
                continue
            
            for issue in issues:
                # 基础置信度
                base_confidence = issue.get('confidence', 0.7)
                
                # 根据检测方法调整
                if issue.get('detection_method') == 'ast':
                    base_confidence += 0.1
                
                # 根据是否有代码片段调整
                if issue.get('code_snippet'):
                    base_confidence += 0.05
                
                # 根据 CWE/OWASP 信息调整
                if issue.get('cwe') or issue.get('owasp'):
                    base_confidence += 0.05
                
                # 限制在 0-1 范围
                issue['final_confidence'] = min(max(base_confidence, 0.0), 1.0)
    
    def get_summary(self) -> Dict[str, Any]:
        """获取扫描摘要"""
        total_issues = sum(
            len(issues) if isinstance(issues, list) else 0
            for issues in self.results.values()
        )
        
        return {
            'target': self.target,
            'total_issues': total_issues,
            'high_risk': self.high_risk,
            'medium_risk': self.medium_risk,
            'low_risk': self.low_risk,
            'categories': {
                category: len(issues) if isinstance(issues, list) else 0
                for category, issues in self.results.items()
            }
        }


# 兼容旧版本的 SecurityScanner 类
class SecurityScanner(EnhancedSecurityScanner):
    """兼容旧版本的扫描器（继承自增强版）"""
    pass


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = '.'
    
    scanner = EnhancedSecurityScanner(target)
    results = scanner.scan()
    
    # 显示摘要
    summary = scanner.get_summary()
    print(f"\n{Fore.BLUE}=== 扫描摘要 ==={Style.RESET_ALL}")
    print(f"目标：{summary['target']}")
    print(f"总问题数：{summary['total_issues']}")
    print(f"{Fore.RED}高风险：{summary['high_risk']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}中风险：{summary['medium_risk']}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}低风险：{summary['low_risk']}{Style.RESET_ALL}")
    
    # 显示前 10 个问题
    print(f"\n{Fore.BLUE}=== 问题详情（前 10 个）=== {Style.RESET_ALL}")
    count = 0
    for category, issues in results.items():
        if not isinstance(issues, list) or not issues:
            continue
        
        for issue in issues[:10 - count]:
            print(f"\n[{issue['severity'].upper()}] {issue['file']}:{issue['line_number']}")
            print(f"  问题：{issue['issue']}")
            print(f"  详情：{issue['details']}")
            print(f"  代码：{issue['code_snippet']}")
            print(f"  置信度：{issue.get('final_confidence', 0.7):.2f}")
            if issue.get('fix'):
                print(f"  修复：{issue['fix']}")
        
        count += len(issues)
        if count >= 10:
            break
