#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
核心安全检测模块 - 增强版 (优化版)

功能：
1. 正则表达式检测 (预编译优化)
2. AST 抽象语法树分析
3. 上下文感知检测
4. 误报过滤机制
5. 置信度评分
6. 行号和代码片段提取
7. 并行扫描支持
8. 智能文件过滤 (.gitignore)
9. 缓存机制
"""

import os
import re
import json
import logging
import time
from typing import List, Dict, Any, Optional, Tuple, Set
from colorama import Fore, Style

try:
    from .ast_scanner import ASTScanner
except ImportError:
    ASTScanner = None

try:
    from .parallel_scanner import ParallelSecurityScanner, ScanConfig
except ImportError:
    ParallelSecurityScanner = None

logger = logging.getLogger(__name__)


class EnhancedSecurityScanner:
    """增强型安全扫描器 (优化版)"""
    
    def __init__(self, target: str, rules_file: str = None, silent: bool = False, 
                 use_parallel: bool = True, max_workers: int = 4):
        """初始化扫描器
        
        Args:
            target: 要扫描的目标路径
            rules_file: 规则文件路径（可选）
            silent: 是否启用静默模式
            use_parallel: 是否使用并行扫描
            max_workers: 最大工作进程数
        """
        self.target = target
        self.silent = silent
        self.rules_file = rules_file
        self.use_parallel = use_parallel
        self.max_workers = max_workers
        
        self.rules = self._load_rules()
        self.false_positive_filters = self._load_fp_filters()
        self.compiled_rules = self._compile_rules()
        
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
            "config_security": [],
            "supply_chain_security": [],
            "compliance_governance": []
        }
        self.high_risk = 0
        self.medium_risk = 0
        self.low_risk = 0
        
        self.ast_scanner = ASTScanner() if ASTScanner else None
        self.stats = {
            'total_files': 0,
            'scanned_files': 0,
            'scan_time': 0.0,
            'method': 'parallel' if use_parallel else 'sequential'
        }
    
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
    
    def _compile_rules(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """预编译正则表达式规则"""
        compiled = {}
        
        for category, rules in self.rules.items():
            if not isinstance(rules, dict):
                continue
            
            compiled[category] = {}
            for rule_name, rule in rules.items():
                patterns = rule.get('patterns', [])
                if not patterns:
                    continue
                
                compiled[category][rule_name] = {
                    'compiled_patterns': [],
                    'rule': rule
                }
                
                for pattern_str in patterns:
                    try:
                        compiled_pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                        compiled[category][rule_name]['compiled_patterns'].append(compiled_pattern)
                    except re.error as e:
                        logger.debug(f"编译规则失败 {pattern_str}: {e}")
        
        return compiled
    
    def scan(self) -> Dict[str, Any]:
        """执行完整扫描"""
        start_time = time.time()
        
        if not self.silent:
            print(f'{Fore.BLUE}开始增强安全扫描...{Style.RESET_ALL}')
            print(f'{Fore.CYAN}扫描模式：{"并行" if self.use_parallel else "串行"}{Style.RESET_ALL}')
        
        # 使用并行扫描器 (如果可用且启用)
        if self.use_parallel and ParallelSecurityScanner:
            try:
                return self._parallel_scan()
            except Exception as e:
                logger.warning(f"并行扫描失败，回退到串行扫描：{e}")
                return self._sequential_scan()
        else:
            return self._sequential_scan()
    
    def _parallel_scan(self) -> Dict[str, Any]:
        """使用并行扫描器"""
        if not self.silent:
            print(f'{Fore.CYAN}使用并行扫描器 (工作进程：{self.max_workers})...{Style.RESET_ALL}')
        
        config = ScanConfig(
            target=self.target,
            max_workers=self.max_workers,
            use_gitignore=True,
            use_cache=True
        )
        
        scanner = ParallelSecurityScanner(config)
        results = scanner.scan()
        summary = scanner.get_summary()
        
        self.results = results
        self.high_risk = summary['high_risk']
        self.medium_risk = summary['medium_risk']
        self.low_risk = summary['low_risk']
        self.stats = {
            'total_files': summary.get('total_files', 0),
            'scanned_files': summary.get('scanned_files', 0),
            'scan_time': summary.get('scan_time', 0.0),
            'method': 'parallel'
        }
        
        if not self.silent:
            print(f'{Fore.GREEN}扫描完成!{Style.RESET_ALL}')
            print(f'{Fore.RED}高风险：{self.high_risk}{Style.RESET_ALL}')
            print(f'{Fore.YELLOW}中风险：{self.medium_risk}{Style.RESET_ALL}')
            print(f'{Fore.GREEN}低风险：{self.low_risk}{Style.RESET_ALL}')
            print(f'{Fore.CYAN}扫描耗时：{self.stats["scan_time"]:.2f}秒{Style.RESET_ALL}')
        
        return self.results
    
    def _sequential_scan(self) -> Dict[str, Any]:
        """串行扫描 (向后兼容)"""
        if not self.silent:
            print(f'{Fore.CYAN}使用串行扫描器...{Style.RESET_ALL}')
        
        # 1. AST 分析（如果可用）
        if self.ast_scanner:
            self._scan_with_ast()
        
        # 2. 正则检测 (使用预编译规则)
        self._scan_with_regex()
        
        # 3. 上下文分析
        self._analyze_context()
        
        # 4. 误报过滤
        self._filter_false_positives()
        
        # 5. 计算置信度
        self._calculate_confidence()
        
        self.stats['scan_time'] = time.time() - start_time if 'start_time' in locals() else 0.0
        
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
        """使用预编译正则表达式扫描"""
        if not self.silent:
            print(f'{Fore.CYAN}正则检测...{Style.RESET_ALL}')
        
        for category, rules in self.compiled_rules.items():
            if not self.silent:
                print(f'{Fore.CYAN}扫描 {category}...{Style.RESET_ALL}')
            
            for rule_name, rule_data in rules.items():
                compiled_patterns = rule_data['compiled_patterns']
                rule = rule_data['rule']
                
                self._apply_compiled_rule(category, rule_name, rule, compiled_patterns)
    
    def _apply_compiled_rule(self, category: str, rule_name: str, rule: Dict, compiled_patterns: List[re.Pattern]):
        """应用预编译规则"""
        severity = rule.get('severity', 'MEDIUM').lower()
        exclude_patterns = rule.get('exclude_patterns', [])
        
        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in [
                'node_modules', 'venv', '.venv', '__pycache__',
                '.git', 'dist', 'build', 'target', '.trae'
            ]]
            
            for file in files:
                if not file.endswith(('.py', '.js', '.json', '.yaml', '.yml', '.env', '.tf', '.toml', '.ini')):
                    continue
                
                file_path = os.path.join(root, file)
                
                if self._is_fp_path(file_path):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.splitlines()
                    
                    for compiled_pattern in compiled_patterns:
                        try:
                            matches = compiled_pattern.finditer(content)
                            
                            for match in matches:
                                line_number = content[:match.start()].count('\n') + 1
                                code_snippet = lines[line_number - 1] if line_number <= len(lines) else ''
                                
                                if self._matches_exclude(content, line_number, exclude_patterns):
                                    continue
                                
                                issue = {
                                    'file': file_path,
                                    'line_number': line_number,
                                    'issue': rule.get('name', rule_name),
                                    'severity': severity,
                                    'details': rule.get('description', ''),
                                    'code_snippet': code_snippet.strip(),
                                    'match': match.group(0),
                                    'detection_method': 'compiled_regex',
                                    'confidence': rule.get('confidence', 0.7),
                                    'weight': rule.get('weight', 1.0),
                                    'cwe': rule.get('cwe', ''),
                                    'owasp': rule.get('owasp', ''),
                                    'fix': rule.get('fix', ''),
                                    'category': category
                                }
                                
                                self.results[category].append(issue)
                                
                                if severity == 'high':
                                    self.high_risk += 1
                                elif severity == 'medium':
                                    self.medium_risk += 1
                                else:
                                    self.low_risk += 1
                        
                        except re.error as e:
                            logger.debug(f"正则表达式错误：{e}")
                
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
                try:
                    with open(issue['file'], 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.splitlines()
                    
                    line_number = issue.get('line_number', 1)
                    start = max(0, line_number - 5)
                    end = min(len(lines), line_number + 5)
                    context = '\n'.join(lines[start:end])
                    
                    if self._has_safe_context(context, issue):
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
            
            filtered_issues = []
            for issue in issues:
                file_name = os.path.basename(issue['file'])
                is_fp = False
                
                for pattern in file_patterns:
                    regex_pattern = pattern.replace('*', '.*').replace('?', '.')
                    if re.match(regex_pattern, file_name, re.IGNORECASE):
                        is_fp = True
                        break
                
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
                base_confidence = issue.get('confidence', 0.7)
                
                if issue.get('detection_method') == 'ast':
                    base_confidence += 0.1
                
                if issue.get('code_snippet'):
                    base_confidence += 0.05
                
                if issue.get('cwe') or issue.get('owasp'):
                    base_confidence += 0.05
                
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
            'scan_time': self.stats.get('scan_time', 0.0),
            'scan_method': self.stats.get('method', 'sequential'),
            'categories': {
                category: len(issues) if isinstance(issues, list) else 0
                for category, issues in self.results.items()
            }
        }


class SecurityScanner(EnhancedSecurityScanner):
    """兼容旧版本的扫描器"""
    pass


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = '.'
    
    scanner = EnhancedSecurityScanner(target, use_parallel=True, max_workers=4)
    results = scanner.scan()
    
    summary = scanner.get_summary()
    print(f"\n{Fore.BLUE}=== 扫描摘要 ==={Style.RESET_ALL}")
    print(f"目标：{summary['target']}")
    print(f"扫描模式：{summary['scan_method']}")
    print(f"扫描耗时：{summary['scan_time']:.2f}秒")
    print(f"总问题数：{summary['total_issues']}")
    print(f"{Fore.RED}高风险：{summary['high_risk']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}中风险：{summary['medium_risk']}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}低风险：{summary['low_risk']}{Style.RESET_ALL}")
