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

# 尝试相对导入
try:
    from .ast_scanner import ASTScanner
except ImportError:
    # 尝试绝对导入
    try:
        from ast_scanner import ASTScanner
    except ImportError:
        ASTScanner = None

try:
    from .parallel_scanner import ParallelSecurityScanner, ScanConfig
except ImportError:
    try:
        from parallel_scanner import ParallelSecurityScanner, ScanConfig
    except ImportError:
        ParallelSecurityScanner = None

# 尝试相对导入
try:
    from .attack_surface_analyzer import AttackSurfaceAnalyzer
except ImportError:
    # 尝试绝对导入
    try:
        from attack_surface_analyzer import AttackSurfaceAnalyzer
    except ImportError:
        AttackSurfaceAnalyzer = None

try:
    from .attack_planner import AttackPlanner
except ImportError:
    try:
        from attack_planner import AttackPlanner
    except ImportError:
        AttackPlanner = None

try:
    from .dynamic_executor import DynamicExecutor, HttpRequest
except ImportError:
    try:
        from dynamic_executor import DynamicExecutor, HttpRequest
    except ImportError:
        DynamicExecutor = None
        HttpRequest = None

try:
    from .vulnerability_assessor import VulnerabilityAssessor, VulnerabilityAssessment
except ImportError:
    try:
        from vulnerability_assessor import VulnerabilityAssessor, VulnerabilityAssessment
    except ImportError:
        VulnerabilityAssessor = None
        VulnerabilityAssessment = None

try:
    from .api_crawler import APICrawler, APIEndpoint
except ImportError:
    try:
        from api_crawler import APICrawler, APIEndpoint
    except ImportError:
        APICrawler = None
        APIEndpoint = None

try:
    from .self_learning import SelfLearningEngine, AttackRecord
except ImportError:
    try:
        from self_learning import SelfLearningEngine, AttackRecord
    except ImportError:
        SelfLearningEngine = None
        AttackRecord = None

try:
    from .ai_security_detector import AISecurityDetector, AISecurityIssue
except ImportError:
    try:
        from ai_security_detector import AISecurityDetector, AISecurityIssue
    except ImportError:
        AISecurityDetector = None
        AISecurityIssue = None

try:
    from .core_integration import CoreIntegration, LLMResponse, EmbeddingResult
except ImportError:
    try:
        from core_integration import CoreIntegration, LLMResponse, EmbeddingResult
    except ImportError:
        CoreIntegration = None
        LLMResponse = None
        EmbeddingResult = None

logger = logging.getLogger(__name__)

# 导出模块
__all__ = ['EnhancedSecurityScanner', 'SecurityScanner', 'ASTScanner', 'ParallelSecurityScanner', 'ScanConfig', 'AttackSurfaceAnalyzer', 'AttackPlanner', 'DynamicExecutor', 'HttpRequest']


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
        self.attack_surface_analyzer = AttackSurfaceAnalyzer() if AttackSurfaceAnalyzer else None
        self.attack_planner = AttackPlanner() if AttackPlanner else None
        self.dynamic_executor = DynamicExecutor() if DynamicExecutor else None
        self.vulnerability_assessor = VulnerabilityAssessor() if VulnerabilityAssessor else None
        self.api_crawler = APICrawler(self.target) if APICrawler and self.target.startswith(('http://', 'https://')) else None
        self.self_learning_engine = SelfLearningEngine() if SelfLearningEngine else None
        self.ai_security_detector = AISecurityDetector() if AISecurityDetector else None
        self.core_integration = CoreIntegration() if CoreIntegration else None
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
        start_time = time.time()
        
        if not self.silent:
            print(f'{Fore.CYAN}使用串行扫描器...{Style.RESET_ALL}')
        
        # 1. API爬虫（如果目标是URL）
        if self.api_crawler:
            self._crawl_api_endpoints()
        
        # 2. AST 分析（如果可用）
        if self.ast_scanner:
            self._scan_with_ast()
        
        # 3. 攻击面分析（如果可用）
        if self.attack_surface_analyzer:
            self._scan_with_attack_surface()
        
        # 4. 攻击策略生成（如果可用）
        if self.attack_planner:
            self._generate_attack_strategy()
        
        # 5. 动态执行攻击（如果可用）
        if self.dynamic_executor and 'attack_strategies' in self.results:
            self._execute_attacks()
        
        # 5. 正则检测 (使用预编译规则)
        self._scan_with_regex()
        
        # 3. 上下文分析
        self._analyze_context()
        
        # 4. 误报过滤
        self._filter_false_positives()
        
        # 5. 计算置信度
        self._calculate_confidence()
        
        # 6. 核心技术集成（如果可用）
        if self.core_integration:
            self._integrate_core_technologies()
        
        # 7. AI安全检测（如果可用）
        if self.ai_security_detector:
            self._detect_ai_security_issues()
        
        # 8. 自学习（如果可用）
        if self.self_learning_engine:
            self._perform_self_learning()
        
        # 9. 权限安全扫描
        self._scan_permission_security()
        
        self.stats['scan_time'] = time.time() - start_time
        
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
    
    def _scan_with_attack_surface(self):
        """使用攻击面分析扫描"""
        if not self.silent:
            print(f'{Fore.CYAN}攻击面分析...{Style.RESET_ALL}')
        
        try:
            attack_surface_result = self.attack_surface_analyzer.analyze(self.target)
            
            # 添加攻击面分析结果到扫描结果
            self.results['attack_surface'] = attack_surface_result
            
            # 处理高风险的 Prompt 注入点
            for injection_point in attack_surface_result.get('prompt_injection_points', []):
                self.results['ai_security'].append({
                    'file': injection_point['file'],
                    'line_number': injection_point['line_number'],
                    'issue': 'Prompt 注入点',
                    'severity': 'high',
                    'details': f"发现 Prompt 注入点: {injection_point['prompt_content']}",
                    'code_snippet': injection_point['prompt_content'],
                    'detection_method': 'attack_surface',
                    'confidence': 0.85,
                    'category': 'ai_security'
                })
                self.high_risk += 1
            
            # 处理 Tool 调用
            for tool_call in attack_surface_result.get('tool_calls', []):
                self.results['ai_security'].append({
                    'file': tool_call['file'],
                    'line_number': tool_call['line_number'],
                    'issue': f"Tool 调用: {tool_call['tool_name']}",
                    'severity': 'medium',
                    'details': f"发现 Tool 调用: {tool_call['tool_name']}",
                    'code_snippet': f"tool.call('{tool_call['tool_name']}')",
                    'detection_method': 'attack_surface',
                    'confidence': 0.75,
                    'category': 'ai_security'
                })
                self.medium_risk += 1
            
            # 处理 API 依赖
            for api_endpoint in attack_surface_result.get('api_dependencies', {}).get('apis', []):
                self.results['network_security'].append({
                    'file': 'API 依赖',
                    'line_number': 0,
                    'issue': f'API 调用: {api_endpoint}',
                    'severity': 'medium',
                    'details': f"发现 API 调用: {api_endpoint}",
                    'code_snippet': api_endpoint,
                    'detection_method': 'attack_surface',
                    'confidence': 0.7,
                    'category': 'network_security'
                })
                self.medium_risk += 1
                
        except Exception as e:
            logger.error(f"攻击面分析失败：{e}")
    
    def _generate_attack_strategy(self):
        """生成攻击策略"""
        if not self.silent:
            print(f'{Fore.CYAN}攻击策略生成...{Style.RESET_ALL}')
        
        try:
            # 收集目标信息
            target_info = {
                'target': self.target,
                'attack_surface': self.results.get('attack_surface', {}),
                'vulnerabilities': []
            }
            
            # 收集已发现的漏洞
            for category, issues in self.results.items():
                if isinstance(issues, list):
                    for issue in issues:
                        target_info['vulnerabilities'].append({
                            'type': issue.get('issue', 'unknown'),
                            'severity': issue.get('severity', 'medium'),
                            'file': issue.get('file', 'unknown')
                        })
            
            # 生成三种模式的攻击策略
            strategies = {
                'template': self.attack_planner.generate_strategy(target_info, 'template'),
                'llm': self.attack_planner.generate_strategy(target_info, 'llm'),
                'agent': self.attack_planner.generate_strategy(target_info, 'agent')
            }
            
            # 添加攻击策略到扫描结果
            self.results['attack_strategies'] = strategies
            
            # 分析目标代码，生成更具体的攻击建议
            if os.path.isfile(self.target):
                with open(self.target, 'r', encoding='utf-8', errors='ignore') as f:
                    code_content = f.read()
                target_analysis = self.attack_planner.analyze_target(code_content)
                self.results['target_analysis'] = target_analysis
            elif os.path.isdir(self.target):
                # 分析目录中的关键文件
                for root, dirs, files in os.walk(self.target):
                    for file in files:
                        if file.endswith(('.py', '.js', '.ts')):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    code_content = f.read()
                                if len(code_content) > 1000:
                                    target_analysis = self.attack_planner.analyze_target(code_content[:1000])
                                    if target_analysis['vulnerabilities']:
                                        if 'target_analysis' not in self.results:
                                            self.results['target_analysis'] = target_analysis
                                        else:
                                            self.results['target_analysis']['vulnerabilities'].extend(target_analysis['vulnerabilities'])
                            except Exception:
                                pass
            
        except Exception as e:
            logger.error(f"攻击策略生成失败：{e}")
    
    def _crawl_api_endpoints(self):
        """爬取API端点"""
        if not self.silent:
            print(f'{Fore.CYAN}爬取API端点...{Style.RESET_ALL}')
        
        try:
            # 执行API爬虫
            endpoints = self.api_crawler.crawl()
            analyzed_endpoints = self.api_crawler.analyze_api_endpoints()
            
            # 存储API端点信息
            api_info = {
                'endpoints': [],
                'summary': {
                    'total_endpoints': len(analyzed_endpoints),
                    'high_risk': sum(1 for ep in analyzed_endpoints if ep.risk_level == 'high'),
                    'medium_risk': sum(1 for ep in analyzed_endpoints if ep.risk_level == 'medium'),
                    'low_risk': sum(1 for ep in analyzed_endpoints if ep.risk_level == 'low')
                }
            }
            
            # 转换API端点为字典格式
            for endpoint in analyzed_endpoints:
                api_info['endpoints'].append({
                    'url': endpoint.url,
                    'method': endpoint.method,
                    'params': endpoint.params,
                    'headers': endpoint.headers,
                    'body': endpoint.body,
                    'description': endpoint.description,
                    'risk_level': endpoint.risk_level
                })
            
            # 添加到扫描结果
            self.results['api_endpoints'] = api_info
            
            # 为高风险API端点生成安全建议
            for endpoint in analyzed_endpoints:
                if endpoint.risk_level in ['high', 'medium']:
                    # 添加到扫描结果中
                    self.results['network_security'].append({
                        'file': 'api_analysis',
                        'line_number': 0,
                        'issue': f'API endpoint with {endpoint.risk_level} risk',
                        'severity': endpoint.risk_level,
                        'details': f'API endpoint: {endpoint.url} - {endpoint.description}',
                        'code_snippet': f'Method: {endpoint.method}, Params: {endpoint.params}',
                        'detection_method': 'api_crawler',
                        'confidence': 0.8,
                        'category': 'network_security'
                    })
            
            if not self.silent:
                print(f'{Fore.GREEN}API爬虫完成，发现 {len(analyzed_endpoints)} 个API端点{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"API爬虫失败：{e}")
    
    def _integrate_core_technologies(self):
        """集成核心技术"""
        if not self.silent:
            print(f'{Fore.CYAN}集成核心技术...{Style.RESET_ALL}')
        
        try:
            # 遍历所有文件，执行核心技术集成
            for file_path in self.files_to_scan:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # 优化AST解析
                    ast_result = self.core_integration.optimize_ast_parsing(content)
                    
                    # 处理危险函数调用
                    for call in ast_result['dangerous_calls']:
                        self.results['code_security'].append({
                            'file': file_path,
                            'line_number': call['line_number'],
                            'issue': f"Dangerous function call: {call['function']}",
                            'severity': 'high',
                            'details': f"Dangerous function {call['function']} detected",
                            'code_snippet': content.split('\n')[call['line_number']-1].strip(),
                            'detection_method': 'ast_optimized',
                            'confidence': 0.9,
                            'category': 'code_security'
                        })
                        self.high_risk += 1
                    
                    # 增强污点分析
                    taint_issues = self.core_integration.enhance_taint_analysis(content)
                    for issue in taint_issues:
                        self.results['code_security'].append({
                            'file': file_path,
                            'line_number': issue['sink_line'],
                            'issue': 'Taint vulnerability',
                            'severity': issue['severity'],
                            'details': issue['message'],
                            'code_snippet': content.split('\n')[issue['sink_line']-1].strip(),
                            'detection_method': 'taint_enhanced',
                            'confidence': 0.85,
                            'category': 'code_security'
                        })
                        if issue['severity'] == 'high':
                            self.high_risk += 1
                        elif issue['severity'] == 'medium':
                            self.medium_risk += 1
                        else:
                            self.low_risk += 1
                    
                except Exception as e:
                    logger.debug(f"核心技术集成失败：{e}")
            
            if not self.silent:
                print(f'{Fore.GREEN}核心技术集成完成{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"核心技术集成失败：{e}")
    
    def _detect_ai_security_issues(self):
        """检测AI安全问题"""
        if not self.silent:
            print(f'{Fore.CYAN}检测AI安全问题...{Style.RESET_ALL}')
        
        try:
            # 遍历所有文件，检测AI安全问题
            for file_path in self.files_to_scan:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # 检测AI安全问题
                    issues = self.ai_security_detector.detect_ai_security_issues(content, file_path)
                    
                    # 处理检测结果
                    for issue in issues:
                        # 添加到扫描结果中
                        self.results['ai_security'].append({
                            'file': issue.file_path,
                            'line_number': issue.line_number,
                            'issue': issue.issue_type,
                            'severity': issue.severity,
                            'details': issue.details['description'],
                            'code_snippet': issue.code_snippet,
                            'detection_method': 'ai_security',
                            'confidence': issue.confidence,
                            'category': 'ai_security'
                        })
                        
                        # 更新风险计数
                        if issue.severity == 'high':
                            self.high_risk += 1
                        elif issue.severity == 'medium':
                            self.medium_risk += 1
                        else:
                            self.low_risk += 1
                    
                except Exception as e:
                    logger.debug(f"检测 {file_path} 的AI安全问题失败：{e}")
            
            if not self.silent:
                ai_security_issues = self.results.get('ai_security', [])
                if ai_security_issues:
                    print(f'{Fore.GREEN}检测到 {len(ai_security_issues)} 个AI安全问题{Style.RESET_ALL}')
                else:
                    print(f'{Fore.GREEN}未检测到AI安全问题{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"AI安全检测失败：{e}")
    
    def _perform_self_learning(self):
        """执行自学习"""
        if not self.silent:
            print(f'{Fore.CYAN}执行自学习...{Style.RESET_ALL}')
        
        try:
            # 从执行结果中提取攻击记录
            execution_results = self.results.get('execution_results', {})
            
            # 处理HTTP请求结果
            for http_request in execution_results.get('http_requests', []):
                # 创建攻击记录
                record = AttackRecord(
                    attack_type=http_request['attack_type'],
                    payload=http_request['payload'],
                    target=http_request['url'],
                    is_successful=http_request['status_code'] in [200, 201, 204],
                    response=str(http_request['status_code']) + (f" - {http_request['error']}" if http_request['error'] else ""),
                    timestamp=time.time(),
                    severity='high' if http_request['attack_type'] in ['sql_injection', 'command_injection'] else 'medium',
                    confidence=0.7,
                    details=http_request
                )
                self.self_learning_engine.add_attack_record(record)
            
            # 处理命令执行结果
            for cmd_exec in execution_results.get('command_execution', []):
                # 创建攻击记录
                record = AttackRecord(
                    attack_type='command_injection',
                    payload=cmd_exec['payload'],
                    target='local',
                    is_successful=cmd_exec['exit_code'] == 0,
                    response=cmd_exec.get('stdout', '') + cmd_exec.get('stderr', ''),
                    timestamp=time.time(),
                    severity='high',
                    confidence=0.8,
                    details=cmd_exec
                )
                self.self_learning_engine.add_attack_record(record)
            
            # 分析攻击模式
            self.self_learning_engine.analyze_attack_patterns()
            
            # 生成Payload模板
            self.self_learning_engine.generate_payload_templates()
            
            # 生成新规则
            new_rules = self.self_learning_engine.generate_new_rules()
            if new_rules:
                # 保存新规则
                rules_file = os.path.join(os.path.dirname(__file__), '..', 'rules', 'auto_generated_rules.json')
                with open(rules_file, 'w', encoding='utf-8') as f:
                    json.dump(new_rules, f, indent=2, ensure_ascii=False)
                if not self.silent:
                    print(f'{Fore.GREEN}生成了 {len(new_rules)} 个新规则并保存到 {rules_file}{Style.RESET_ALL}')
            
            # 优化Payload
            for attack_type in ['sql_injection', 'xss', 'command_injection']:
                optimized_payloads = self.self_learning_engine.optimize_payloads(attack_type, 3)
                if optimized_payloads:
                    if not self.silent:
                        print(f'{Fore.GREEN}为 {attack_type} 优化了 {len(optimized_payloads)} 个Payload{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"自学习失败：{e}")
    
    def _execute_attacks(self):
        """执行攻击策略"""
        if not self.silent:
            print(f'{Fore.CYAN}动态执行攻击...{Style.RESET_ALL}')
        
        try:
            execution_results = {
                'http_requests': [],
                'fuzzing': [],
                'xss_tests': [],
                'command_execution': [],
                'vulnerability_assessments': []
            }
            
            # 从攻击策略中提取攻击链
            strategies = self.results.get('attack_strategies', {})
            for strategy_name, strategy in strategies.items():
                if 'attack_chain' in strategy:
                    attack_chain = strategy['attack_chain']
                    for step in attack_chain.get('steps', []):
                        attack_type = step.get('attack_type')
                        payload = step.get('payload')
                        target_param = step.get('target')
                        
                        # 生成测试请求
                        if attack_type in ['sql_injection', 'xss', 'ssrf']:
                            # 构建测试URL（使用示例URL）
                            test_url = f"http://localhost:8080/test"
                            
                            # 发送HTTP请求
                            request = HttpRequest(
                                method="GET",
                                url=test_url,
                                params={target_param: payload}
                            )
                            
                            result = self.dynamic_executor.send_http_request(request)
                            http_result = {
                                'strategy': strategy_name,
                                'attack_type': attack_type,
                                'payload': payload,
                                'url': test_url,
                                'status_code': result.status_code,
                                'response_time': result.response_time,
                                'error': result.error
                            }
                            execution_results['http_requests'].append(http_result)
                            
                            # 执行漏洞评估
                            if self.vulnerability_assessor:
                                response_content = result.error if result.error else str(result.status_code)
                                assessment = self.vulnerability_assessor.assess_response(
                                    response_content,
                                    attack_type,
                                    payload
                                )
                                if assessment.is_vulnerable:
                                    execution_results['vulnerability_assessments'].append({
                                        'strategy': strategy_name,
                                        'attack_type': attack_type,
                                        'payload': payload,
                                        'severity': assessment.severity,
                                        'confidence': assessment.confidence,
                                        'details': assessment.details
                                    })
                                    
                                    # 添加到扫描结果中
                                    category = 'injection_security' if attack_type in ['sql_injection', 'xss'] else 'network_security'
                                    self.results[category].append({
                                        'file': 'dynamic_analysis',
                                        'line_number': 0,
                                        'issue': f'{attack_type} vulnerability',
                                        'severity': assessment.severity,
                                        'details': assessment.details.get('evidence', 'Vulnerability detected'),
                                        'code_snippet': f'Payload: {payload}',
                                        'detection_method': 'dynamic',
                                        'confidence': assessment.confidence,
                                        'category': category
                                    })
                            
                            # 执行Fuzzing
                            if attack_type == 'sql_injection':
                                fuzz_payloads = self.dynamic_executor.generate_fuzz_payloads(attack_type, 5)
                                fuzz_results = self.dynamic_executor.fuzz_api(
                                    url=test_url,
                                    params={target_param: "test"},
                                    payloads=fuzz_payloads
                                )
                                for fr in fuzz_results:
                                    fuzz_result = {
                                        'strategy': strategy_name,
                                        'attack_type': attack_type,
                                        'payload': fr.payload,
                                        'status_code': fr.status_code,
                                        'is_vulnerable': fr.is_vulnerable
                                    }
                                    execution_results['fuzzing'].append(fuzz_result)
                                    
                                    # 执行漏洞评估
                                    if self.vulnerability_assessor and fr.is_vulnerable:
                                        response_content = str(fr.status_code)
                                        assessment = self.vulnerability_assessor.assess_response(
                                            response_content,
                                            attack_type,
                                            fr.payload
                                        )
                                        if assessment.is_vulnerable:
                                            execution_results['vulnerability_assessments'].append({
                                                'strategy': strategy_name,
                                                'attack_type': attack_type,
                                                'payload': fr.payload,
                                                'severity': assessment.severity,
                                                'confidence': assessment.confidence,
                                                'details': assessment.details
                                            })
                            
                            # 执行XSS测试
                            if attack_type == 'xss':
                                xss_results = self.dynamic_executor.test_xss(
                                    url=test_url,
                                    param=target_param
                                )
                                for xr in xss_results:
                                    xss_result = {
                                        'strategy': strategy_name,
                                        'payload': xr['payload'],
                                        'url': xr['url'],
                                        'is_vulnerable': xr['is_vulnerable']
                                    }
                                    execution_results['xss_tests'].append(xss_result)
                                    
                                    # 执行漏洞评估
                                    if self.vulnerability_assessor and xr['is_vulnerable']:
                                        response_content = xr['url']  # 简化处理
                                        assessment = self.vulnerability_assessor.assess_response(
                                            response_content,
                                            attack_type,
                                            xr['payload']
                                        )
                                        if assessment.is_vulnerable:
                                            execution_results['vulnerability_assessments'].append({
                                                'strategy': strategy_name,
                                                'attack_type': attack_type,
                                                'payload': xr['payload'],
                                                'severity': assessment.severity,
                                                'confidence': assessment.confidence,
                                                'details': assessment.details
                                            })
                        
                        # 模拟命令执行
                        elif attack_type == 'command_injection':
                            command_result = self.dynamic_executor.simulate_command_execution(payload)
                            cmd_result = {
                                'strategy': strategy_name,
                                'payload': payload,
                                'exit_code': command_result.get('exit_code'),
                                'stdout': command_result.get('stdout'),
                                'stderr': command_result.get('stderr')
                            }
                            execution_results['command_execution'].append(cmd_result)
                            
                            # 执行漏洞评估
                            if self.vulnerability_assessor:
                                response_content = command_result.get('stdout', '') + command_result.get('stderr', '')
                                assessment = self.vulnerability_assessor.assess_response(
                                    response_content,
                                    attack_type,
                                    payload
                                )
                                if assessment.is_vulnerable:
                                    execution_results['vulnerability_assessments'].append({
                                        'strategy': strategy_name,
                                        'attack_type': attack_type,
                                        'payload': payload,
                                        'severity': assessment.severity,
                                        'confidence': assessment.confidence,
                                        'details': assessment.details
                                    })
                                    
                                    # 添加到扫描结果中
                                    self.results['injection_security'].append({
                                        'file': 'dynamic_analysis',
                                        'line_number': 0,
                                        'issue': 'Command injection vulnerability',
                                        'severity': assessment.severity,
                                        'details': assessment.details.get('evidence', 'Vulnerability detected'),
                                        'code_snippet': f'Payload: {payload}',
                                        'detection_method': 'dynamic',
                                        'confidence': assessment.confidence,
                                        'category': 'injection_security'
                                    })
            
            # 添加执行结果到扫描结果
            self.results['execution_results'] = execution_results
            
        except Exception as e:
            logger.error(f"攻击执行失败：{e}")
    
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
                    start = max(0, line_number - 10)
                    end = min(len(lines), line_number + 10)
                    context = '\n'.join(lines[start:end])
                    
                    # 1. 检查安全上下文
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
                    
                    # 2. 检查危险上下文
                    elif self._has_dangerous_context(context, issue):
                        if issue['severity'] == 'low':
                            issue['severity'] = 'medium'
                            self.low_risk -= 1
                            self.medium_risk += 1
                        elif issue['severity'] == 'medium':
                            issue['severity'] = 'high'
                            self.medium_risk -= 1
                            self.high_risk += 1
                        
                        issue['context_analysis'] = '检测到危险处理代码'
                    
                    # 3. 检查AI特定的上下文
                    elif 'ai_security' in category:
                        if self._has_ai_safe_context(context, issue):
                            if issue['severity'] == 'high':
                                issue['severity'] = 'medium'
                                self.high_risk -= 1
                                self.medium_risk += 1
                            elif issue['severity'] == 'medium':
                                issue['severity'] = 'low'
                                self.medium_risk -= 1
                                self.low_risk += 1
                            
                            issue['context_analysis'] = '检测到AI安全处理代码'
                
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
    
    def _has_dangerous_context(self, context: str, issue: Dict) -> bool:
        """检查是否有危险的上下文"""
        dangerous_patterns = [
            r'exec\s*\(',
            r'eval\s*\(',
            r'compile\s*\(',
            r'os\.system\s*\(',
            r'subprocess\..*shell\s*=\s*True',
            r'pickle\.load',
            r'yaml\.load\s*\([^)]*\)',
            r'input\s*\(',
            r'open\s*\([^)]*request\.',
            r'os\.path\.join\s*\([^)]*request\.'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _has_ai_safe_context(self, context: str, issue: Dict) -> bool:
        """检查是否有AI安全的上下文"""
        ai_safe_patterns = [
            r'prompt\s*template',
            r'system\s*prompt',
            r'input\s*validation',
            r'sanitize\s*input',
            r'filter\s*prompt',
            r'validate\s*user\s*input',
            r'limit\s*prompt\s*length',
            r'token\s*limit',
            r'content\s*filter',
            r'safety\s*check',
            r'rate\s*limit',
            r'throttle',
            r'context\s*isolation'
        ]
        
        for pattern in ai_safe_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _filter_false_positives(self):
        """过滤误报"""
        if not self.silent:
            print(f'{Fore.CYAN}过滤误报...{Style.RESET_ALL}')
        
        file_patterns = self.false_positive_filters.get('file_patterns', [])
        code_patterns = self.false_positive_filters.get('code_patterns', [])
        path_patterns = self.false_positive_filters.get('path_patterns', [])
        context_patterns = self.false_positive_filters.get('context_patterns', [])
        
        for category, issues in self.results.items():
            if not isinstance(issues, list):
                continue
            
            filtered_issues = []
            for issue in issues:
                is_fp = False
                
                # 1. 检查文件路径模式
                file_path = issue.get('file', '')
                file_name = os.path.basename(file_path)
                
                # 检查路径模式
                for pattern in path_patterns:
                    if pattern in file_path:
                        is_fp = True
                        break
                
                # 2. 检查文件名称模式
                if not is_fp:
                    for pattern in file_patterns:
                        regex_pattern = pattern.replace('*', '.*').replace('?', '.')
                        if re.match(regex_pattern, file_name, re.IGNORECASE):
                            is_fp = True
                            break
                
                # 3. 检查代码模式
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
                
                # 4. 检查上下文模式
                if not is_fp and context_patterns:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            lines = content.splitlines()
                        
                        line_number = issue.get('line_number', 1)
                        start = max(0, line_number - 10)
                        end = min(len(lines), line_number + 10)
                        context = '\n'.join(lines[start:end])
                        
                        for pattern in context_patterns:
                            try:
                                if re.search(pattern, context, re.IGNORECASE):
                                    is_fp = True
                                    break
                            except re.error:
                                if pattern in context:
                                    is_fp = True
                                    break
                    except Exception:
                        pass
                
                # 5. 检查特定类型的误报
                if not is_fp:
                    # 检查硬编码敏感信息的误报
                    if issue.get('issue', '').startswith('硬编码敏感信息'):
                        code_snippet = issue.get('code_snippet', '')
                        # 排除示例和占位符
                        placeholders = ['your_', 'example', 'placeholder', 'xxx', 'change_me', 'todo', 'fixme', 'test', 'demo', 'sample']
                        if any(p in code_snippet.lower() for p in placeholders):
                            is_fp = True
                    
                    # 检查网络访问的误报
                    elif issue.get('issue', '').startswith('网络访问代码'):
                        code_snippet = issue.get('code_snippet', '')
                        # 检查是否有超时和验证设置
                        if 'timeout' in code_snippet.lower() and 'verify' in code_snippet.lower():
                            is_fp = True
                    
                    # 检查命令注入的误报
                    elif '命令注入' in issue.get('issue', ''):
                        code_snippet = issue.get('code_snippet', '')
                        # 检查是否使用了安全的参数列表
                        if 'shell=False' in code_snippet or '[' in code_snippet and ']' in code_snippet:
                            is_fp = True
                
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
    
    def _scan_permission_security(self):
        """扫描权限安全"""
        if not self.silent:
            print(f'{Fore.CYAN}扫描权限安全...{Style.RESET_ALL}')
        
        # 检查文件权限
        for root, dirs, files in os.walk(self.target):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # 检查执行权限
                    if os.access(file_path, os.X_OK):
                        self.results["permission_security"].append({
                            "file": file_path,
                            "issue": "文件具有执行权限",
                            "severity": "medium",
                            "details": "建议仅对必要的脚本设置执行权限",
                            "code_snippet": "",
                            "detection_method": "permission_scan",
                            "confidence": 0.8,
                            "category": "permission_security"
                        })
                        self.medium_risk += 1
                    
                    # 检查AI模型文件权限
                    if file.endswith(('.pt', '.pth', '.onnx', '.h5', '.pb', '.tflite', '.safetensors', '.bin')):
                        # 获取文件权限
                        import stat
                        file_stat = os.stat(file_path)
                        permissions = oct(file_stat.st_mode)[-3:]
                        
                        # 检查是否过于宽松
                        if '7' in permissions:
                            self.results["permission_security"].append({
                                "file": file_path,
                                "issue": "AI模型文件权限过于宽松",
                                "severity": "high",
                                "details": f"当前权限: {permissions}，建议设置为 640",
                                "code_snippet": "",
                                "detection_method": "permission_scan",
                                "confidence": 0.9,
                                "category": "permission_security"
                            })
                            self.high_risk += 1
                except Exception as e:
                    logger.error(f"检查文件权限 {file_path} 时出错: {e}")
    
    def scan_code(self, code: str) -> List[Dict[str, Any]]:
        """扫描代码内容
        
        Args:
            code: 要扫描的代码内容
            
        Returns:
            扫描结果列表
        """
        issues = []
        
        # 应用预编译规则
        for category, rules in self.compiled_rules.items():
            for rule_name, rule_data in rules.items():
                compiled_patterns = rule_data['compiled_patterns']
                rule = rule_data['rule']
                severity = rule.get('severity', 'MEDIUM').lower()
                exclude_patterns = rule.get('exclude_patterns', [])
                
                lines = code.splitlines()
                
                for compiled_pattern in compiled_patterns:
                    try:
                        matches = compiled_pattern.finditer(code)
                        
                        for match in matches:
                            line_number = code[:match.start()].count('\n') + 1
                            code_snippet = lines[line_number - 1] if line_number <= len(lines) else ''
                            
                            if self._matches_exclude(code, line_number, exclude_patterns):
                                continue
                            
                            issue = {
                                'rule_id': f"{category}.{rule_name}",
                                'file': 'code_content',
                                'line_number': line_number,
                                'issue': rule.get('name', rule_name),
                                'severity': severity,
                                'details': rule.get('description', ''),
                                'code_snippet': code_snippet.strip(),
                                'match': match.group(0),
                                'detection_method': 'compiled_regex',
                                'confidence': rule.get('confidence', 0.7),
                                'category': category
                            }
                            
                            issues.append(issue)
                    except re.error as e:
                        logger.debug(f"正则表达式错误：{e}")
        
        # 过滤误报
        code_patterns = self.false_positive_filters.get('code_patterns', [])
        filtered_issues = []
        
        for issue in issues:
            is_fp = False
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
        
        return filtered_issues

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
