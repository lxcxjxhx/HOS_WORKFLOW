#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
并行安全扫描模块

功能:
1. 多进程并行文件扫描
2. 智能文件过滤 (.gitignore 支持)
3. 规则预编译和分组
4. 增量扫描支持
"""

import os
import re
import json
import logging
import hashlib
import time
from typing import List, Dict, Any, Optional, Tuple, Set
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict

try:
    from .ast_scanner import ASTScanner
except ImportError:
    try:
        from ast_scanner import ASTScanner
    except ImportError:
        ASTScanner = None

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """扫描配置"""
    target: str
    max_workers: int = 4
    use_gitignore: bool = True
    use_cache: bool = True
    cache_file: str = ".hos_ls_cache.json"
    file_extensions: List[str] = field(default_factory=lambda: [
        '.py', '.js', '.ts', '.jsx', '.tsx', '.json', '.yaml', '.yml', 
        '.env', '.tf', '.toml', '.ini', '.sh', '.bash', '.md'
    ])
    exclude_dirs: Set[str] = field(default_factory=lambda: {
        'node_modules', 'venv', '.venv', '__pycache__', '.git', 
        'dist', 'build', 'target', '.trae', 'vendor', 
        '.pytest_cache', '.eggs', '*.egg-info'
    })
    max_file_size: int = 10 * 1024 * 1024  # 10MB


@dataclass
class FileTask:
    """文件扫描任务"""
    file_path: str
    file_hash: str
    rules: Dict[str, Any]
    line_count: int = 0


class GitIgnoreParser:
    """.gitignore 解析器"""
    
    def __init__(self, root_dir: str):
        self.root_dir = root_dir
        self.patterns: List[Tuple[re.Pattern, bool]] = []
        self.negations: List[re.Pattern] = []
        self._load_gitignore()
    
    def _load_gitignore(self):
        """加载.gitignore 文件"""
        gitignore_path = os.path.join(self.root_dir, '.gitignore')
        if not os.path.exists(gitignore_path):
            return
        
        try:
            with open(gitignore_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # 处理否定模式
                    is_negation = line.startswith('!')
                    if is_negation:
                        line = line[1:]
                    
                    # 转换为正则表达式
                    pattern = self._pattern_to_regex(line)
                    compiled = re.compile(pattern)
                    
                    if is_negation:
                        self.negations.append(compiled)
                    else:
                        self.patterns.append((compiled, is_negation))
        except Exception as e:
            logger.debug(f"加载.gitignore 失败：{e}")
    
    def _pattern_to_regex(self, pattern: str) -> str:
        """将 gitignore 模式转换为正则表达式"""
        # 转义特殊字符
        regex = re.escape(pattern)
        
        # 处理通配符
        regex = regex.replace(r'\*\*', '.*')  # ** 匹配任意目录
        regex = regex.replace(r'\*', '[^/]*')  # * 匹配任意字符 (不含/)
        regex = regex.replace(r'\?', '.')  # ? 匹配单个字符
        
        # 处理目录匹配
        if pattern.endswith('/'):
            regex = regex + '.*'
        
        # 处理根目录模式
        if pattern.startswith('/'):
            regex = '^' + regex[1:]
        else:
            regex = '(^|/)' + regex
        
        return regex + '$'
    
    def should_ignore(self, file_path: str) -> bool:
        """检查文件是否应该被忽略"""
        rel_path = os.path.relpath(file_path, self.root_dir)
        
        # 检查否定模式 (即使匹配也要包含)
        for neg_pattern in self.negations:
            if neg_pattern.search(rel_path):
                return False
        
        # 检查正常模式
        for pattern, _ in self.patterns:
            if pattern.search(rel_path):
                return True
        
        return False


class ScanCache:
    """扫描缓存管理"""
    
    def __init__(self, cache_file: str):
        self.cache_file = cache_file
        self.cache: Dict[str, Dict[str, Any]] = {}
        self._load_cache()
    
    def _load_cache(self):
        """加载缓存"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
                logger.debug(f"加载缓存成功：{len(self.cache)} 条记录")
            except Exception as e:
                logger.debug(f"加载缓存失败：{e}")
                self.cache = {}
    
    def _save_cache(self):
        """保存缓存"""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=2)
            logger.debug(f"保存缓存成功：{len(self.cache)} 条记录")
        except Exception as e:
            logger.debug(f"保存缓存失败：{e}")
    
    def get(self, file_path: str, file_hash: str) -> Optional[Dict[str, Any]]:
        """获取缓存的扫描结果"""
        if file_path in self.cache:
            cached = self.cache[file_path]
            if cached.get('hash') == file_hash:
                return cached.get('results')
        return None
    
    def set(self, file_path: str, file_hash: str, results: List[Dict[str, Any]]):
        """设置缓存的扫描结果"""
        self.cache[file_path] = {
            'hash': file_hash,
            'results': results,
            'timestamp': time.time()
        }
        self._save_cache()
    
    def invalidate(self, file_path: str):
        """使缓存失效"""
        if file_path in self.cache:
            del self.cache[file_path]
            self._save_cache()
    
    def clear(self):
        """清空缓存"""
        self.cache = {}
        if os.path.exists(self.cache_file):
            os.remove(self.cache_file)


def compute_file_hash(file_path: str) -> str:
    """计算文件哈希"""
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logger.debug(f"计算文件哈希失败 {file_path}: {e}")
        return ""


def scan_single_file(task: FileTask) -> Dict[str, List[Dict[str, Any]]]:
    """扫描单个文件 (用于进程池)"""
    results = defaultdict(list)
    
    try:
        with open(task.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()
        
        # 应用所有规则
        for category, rules in task.rules.items():
            if not isinstance(rules, dict):
                continue
            
            for rule_name, rule in rules.items():
                patterns = rule.get('patterns', [])
                if not patterns:
                    continue
                
                severity = rule.get('severity', 'MEDIUM').lower()
                exclude_patterns = rule.get('exclude_patterns', [])
                
                for pattern_str in patterns:
                    try:
                        pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                        matches = pattern.finditer(content)
                        
                        for match in matches:
                            line_number = content[:match.start()].count('\n') + 1
                            code_snippet = lines[line_number - 1] if line_number <= len(lines) else ''
                            
                            # 检查排除模式
                            is_excluded = False
                            if exclude_patterns:
                                start = max(0, line_number - 5)
                                end = min(len(lines), line_number + 5)
                                context = '\n'.join(lines[start:end])
                                
                                for exclude_pattern in exclude_patterns:
                                    if re.search(exclude_pattern, context, re.IGNORECASE):
                                        is_excluded = True
                                        break
                            
                            if is_excluded:
                                continue
                            
                            # 创建问题记录
                            issue = {
                                'file': task.file_path,
                                'line_number': line_number,
                                'issue': rule.get('name', rule_name),
                                'severity': severity,
                                'details': rule.get('description', ''),
                                'code_snippet': code_snippet.strip(),
                                'match': match.group(0),
                                'detection_method': 'parallel_regex',
                                'confidence': rule.get('confidence', 0.7),
                                'category': category
                            }
                            
                            results[category].append(issue)
                    
                    except re.error as e:
                        logger.debug(f"正则表达式错误 {pattern_str}: {e}")
        
        return dict(results)
    
    except Exception as e:
        logger.error(f"扫描文件 {task.file_path} 时出错：{e}")
        return {}


class ParallelSecurityScanner:
    """并行安全扫描器"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.results = defaultdict(list)
        self.high_risk = 0
        self.medium_risk = 0
        self.low_risk = 0
        
        # 加载规则
        self.rules = self._load_rules()
        
        # 预编译规则
        self.compiled_rules = self._compile_rules()
        
        # 初始化组件
        self.gitignore_parser = GitIgnoreParser(config.target) if config.use_gitignore else None
        self.cache = ScanCache(config.cache_file) if config.use_cache else None
        self.ast_scanner = ASTScanner() if ASTScanner else None
        
        # 统计信息
        self.stats = {
            'total_files': 0,
            'scanned_files': 0,
            'cached_files': 0,
            'skipped_files': 0,
            'scan_time': 0.0
        }
    
    def _load_rules(self) -> Dict[str, Any]:
        """加载规则配置"""
        rules_file = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'rules',
            'security_rules.json'
        )
        
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('rules', {})
        except Exception as e:
            logger.error(f"加载规则文件失败：{e}")
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
    
    def _collect_files(self) -> List[str]:
        """收集要扫描的文件"""
        files_to_scan = []
        
        for root, dirs, files in os.walk(self.config.target):
            # 跳过排除目录
            dirs[:] = [d for d in dirs if d not in self.config.exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # 检查扩展名
                if not any(file.endswith(ext) for ext in self.config.file_extensions):
                    continue
                
                # 检查.gitignore
                if self.gitignore_parser and self.gitignore_parser.should_ignore(file_path):
                    self.stats['skipped_files'] += 1
                    continue
                
                # 检查文件大小
                try:
                    if os.path.getsize(file_path) > self.config.max_file_size:
                        self.stats['skipped_files'] += 1
                        continue
                except Exception:
                    continue
                
                files_to_scan.append(file_path)
        
        self.stats['total_files'] = len(files_to_scan)
        return files_to_scan
    
    def _create_tasks(self, file_paths: List[str]) -> List[FileTask]:
        """创建扫描任务"""
        tasks = []
        
        for file_path in file_paths:
            file_hash = compute_file_hash(file_path)
            
            # 检查缓存
            if self.cache:
                cached_results = self.cache.get(file_path, file_hash)
                if cached_results:
                    self.stats['cached_files'] += 1
                    # 合并缓存结果
                    for category, issues in cached_results.items():
                        self.results[category].extend(issues)
                        for issue in issues:
                            severity = issue.get('severity', 'low')
                            if severity == 'high':
                                self.high_risk += 1
                            elif severity == 'medium':
                                self.medium_risk += 1
                            else:
                                self.low_risk += 1
                    continue
            
            # 创建新任务
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    line_count = len(f.readlines())
            except Exception:
                line_count = 0
            
            task = FileTask(
                file_path=file_path,
                file_hash=file_hash,
                rules=self.rules,
                line_count=line_count
            )
            tasks.append(task)
        
        return tasks
    
    def scan(self) -> Dict[str, Any]:
        """执行并行扫描"""
        start_time = time.time()
        
        logger.info(f"开始并行扫描：{self.config.target}")
        logger.info(f"使用 {self.config.max_workers} 个工作进程")
        
        # 收集文件
        file_paths = self._collect_files()
        logger.info(f"找到 {len(file_paths)} 个文件待扫描")
        
        if not file_paths:
            return self._build_results(start_time)
        
        # 创建任务
        tasks = self._create_tasks(file_paths)
        logger.info(f"创建 {len(tasks)} 个扫描任务 (已跳过 {self.stats['cached_files']} 个缓存文件)")
        
        if not tasks:
            return self._build_results(start_time)
        
        # 并行扫描
        scanned_count = 0
        with ProcessPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {executor.submit(scan_single_file, task): task for task in tasks}
            
            for future in as_completed(futures):
                try:
                    task_results = future.result()
                    
                    # 合并结果
                    for category, issues in task_results.items():
                        self.results[category].extend(issues)
                        for issue in issues:
                            severity = issue.get('severity', 'low')
                            if severity == 'high':
                                self.high_risk += 1
                            elif severity == 'medium':
                                self.medium_risk += 1
                            else:
                                self.low_risk += 1
                    
                    # 更新缓存
                    if self.cache:
                        task = futures[future]
                        self.cache.set(task.file_path, task.file_hash, task_results)
                    
                    scanned_count += 1
                    if scanned_count % 50 == 0:
                        logger.debug(f"已扫描 {scanned_count}/{len(tasks)} 个文件")
                
                except Exception as e:
                    logger.error(f"扫描任务失败：{e}")
        
        self.stats['scanned_files'] = scanned_count
        
        # AST 分析 (如果可用)
        if self.ast_scanner:
            logger.info("执行 AST 分析...")
            self._run_ast_scan()
        
        return self._build_results(start_time)
    
    def _run_ast_scan(self):
        """执行 AST 扫描"""
        try:
            ast_results = self.ast_scanner.analyze(self.config.target)
            
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
    
    def _build_results(self, start_time: float) -> Dict[str, Any]:
        """构建扫描结果"""
        end_time = time.time()
        self.stats['scan_time'] = end_time - start_time
        
        return {
            'target': self.config.target,
            'code_security': self.results.get('code_security', []),
            'injection_security': self.results.get('injection_security', []),
            'ai_security': self.results.get('ai_security', []),
            'container_security': self.results.get('container_security', []),
            'cloud_security': self.results.get('cloud_security', []),
            'privacy_security': self.results.get('privacy_security', []),
            'permission_security': self.results.get('permission_security', []),
            'network_security': self.results.get('network_security', []),
            'dependency_security': self.results.get('dependency_security', []),
            'config_security': self.results.get('config_security', []),
            'supply_chain_security': self.results.get('supply_chain_security', []),
            'compliance_governance': self.results.get('compliance_governance', []),
            'stats': self.stats,
            'summary': {
                'high_risk': self.high_risk,
                'medium_risk': self.medium_risk,
                'low_risk': self.low_risk,
                'total_issues': self.high_risk + self.medium_risk + self.low_risk,
                'scan_time': self.stats['scan_time'],
                'files_scanned': self.stats['scanned_files'],
                'files_cached': self.stats['cached_files'],
                'files_skipped': self.stats['skipped_files']
            }
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """获取扫描摘要"""
        return {
            'target': self.config.target,
            'total_files': self.stats['total_files'],
            'scanned_files': self.stats['scanned_files'],
            'cached_files': self.stats['cached_files'],
            'skipped_files': self.stats['skipped_files'],
            'total_issues': self.high_risk + self.medium_risk + self.low_risk,
            'high_risk': self.high_risk,
            'medium_risk': self.medium_risk,
            'low_risk': self.low_risk,
            'scan_time': self.stats['scan_time'],
            'categories': {
                category: len(issues) if isinstance(issues, list) else 0
                for category, issues in self.results.items()
            }
        }


def create_parallel_scanner(
    target: str,
    max_workers: int = 4,
    use_gitignore: bool = True,
    use_cache: bool = True
) -> ParallelSecurityScanner:
    """创建并行扫描器的便捷函数"""
    config = ScanConfig(
        target=target,
        max_workers=max_workers,
        use_gitignore=use_gitignore,
        use_cache=use_cache
    )
    return ParallelSecurityScanner(config)


if __name__ == '__main__':
    import sys
    from colorama import Fore, Style, init
    
    init(autoreset=True)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = '.'
    
    print(f"{Fore.BLUE}开始并行扫描：{target}{Style.RESET_ALL}")
    
    scanner = create_parallel_scanner(
        target=target,
        max_workers=4,
        use_gitignore=True,
        use_cache=True
    )
    
    results = scanner.scan()
    summary = scanner.get_summary()
    
    print(f"\n{Fore.BLUE}=== 扫描摘要 ==={Style.RESET_ALL}")
    print(f"目标：{summary['target']}")
    print(f"扫描文件数：{summary['scanned_files']}")
    print(f"缓存文件数：{summary['cached_files']}")
    print(f"跳过文件数：{summary['skipped_files']}")
    print(f"扫描耗时：{summary['scan_time']:.2f}秒")
    print(f"总问题数：{summary['total_issues']}")
    print(f"{Fore.RED}高风险：{summary['high_risk']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}中风险：{summary['medium_risk']}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}低风险：{summary['low_risk']}{Style.RESET_ALL}")
    
    print(f"\n{Fore.BLUE}=== 各类别问题数 ==={Style.RESET_ALL}")
    for category, count in summary['categories'].items():
        if count > 0:
            print(f"  {category}: {count}")
