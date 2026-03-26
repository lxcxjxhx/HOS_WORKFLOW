#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
核心安全检测模块
"""

import os
import re
import json
import yaml
import logging
from colorama import Fore, Style

logger = logging.getLogger(__name__)

class SecurityScanner:
    """安全扫描器类"""
    
    def __init__(self, target, silent=False):
        """初始化扫描器
        
        Args:
            target: 要扫描的目标路径
            silent: 是否启用静默模式
        """
        self.target = target
        self.silent = silent
        self.results = {
            "code_security": [],
            "permission_security": [],
            "network_security": [],
            "dependency_security": [],
            "config_security": []
        }
        self.high_risk = 0
        self.medium_risk = 0
        self.low_risk = 0
    
    def scan(self):
        """执行完整扫描"""
        if not self.silent:
            print(f'{Fore.BLUE}开始安全扫描...{Style.RESET_ALL}')
        
        # 扫描代码安全
        self.scan_code_security()
        
        # 扫描权限安全
        self.scan_permission_security()
        
        # 扫描网络安全
        self.scan_network_security()
        
        # 扫描依赖安全
        self.scan_dependency_security()
        
        # 扫描配置安全
        self.scan_config_security()
        
        if not self.silent:
            print(f'{Fore.GREEN}扫描完成!{Style.RESET_ALL}')
            print(f'{Fore.RED}高风险: {self.high_risk}{Style.RESET_ALL}')
            print(f'{Fore.YELLOW}中风险: {self.medium_risk}{Style.RESET_ALL}')
            print(f'{Fore.GREEN}低风险: {self.low_risk}{Style.RESET_ALL}')
        
        return self.results
    
    def scan_code_security(self):
        """扫描代码安全"""
        if not self.silent:
            print(f'{Fore.CYAN}扫描代码安全...{Style.RESET_ALL}')
        
        # 敏感信息正则表达式
        patterns = {
            "api_key": r'(?i)(api[_\s-]?key|api[_\s-]?token)\s*[:=]\s*["\']([^"\']+)["\']',
            "password": r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']',
            "secret": r'(?i)(secret|private[_\s-]?key)\s*[:=]\s*["\']([^"\']+)["\']',
            "token": r'(?i)(token|auth[_\s-]?token)\s*[:=]\s*["\']([^"\']+)["\']',
            "backdoor": r'(?i)(exec\(|eval\(|system\(|os\.system\(|subprocess\.call\()',
            "network_access": r'(?i)(requests\.|urllib\.|socket\.|http\.|https\.)',
            "ai_model_loading": r'(?i)(torch\.load|torch\.jit\.load|tf\.keras\.models\.load_model|onnxruntime\.InferenceSession|transformers\.AutoModel|transformers\.AutoTokenizer)',
            "ai_input_validation": r'(?i)(input|prompt|query)',
            "ai_output_processing": r'(?i)(output|response|result)',
            "ai_inference": r'(?i)(model\.predict|model\.forward|model\()',
            "ai_data_processing": r'(?i)(data\.load|dataset|dataloader)'
        }
        
        # 遍历文件
        for root, dirs, files in os.walk(self.target):
            for file in files:
                if file.endswith(('.py', '.js', '.json', '.yaml', '.yml', '.env')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for pattern_name, pattern in patterns.items():
                                matches = re.findall(pattern, content)
                                for match in matches:
                                    if pattern_name in ["api_key", "password", "secret", "token"]:
                                        self.results["code_security"].append({
                                            "file": file_path,
                                            "issue": f"发现硬编码的{pattern_name}",
                                            "severity": "high",
                                            "details": f"匹配到: {match[0]}"
                                        })
                                        self.high_risk += 1
                                    elif pattern_name == "backdoor":
                                        self.results["code_security"].append({
                                            "file": file_path,
                                            "issue": "发现潜在的后门代码",
                                            "severity": "high",
                                            "details": f"匹配到: {match}"
                                        })
                                        self.high_risk += 1
                                    elif pattern_name == "network_access":
                                        self.results["code_security"].append({
                                            "file": file_path,
                                            "issue": "发现网络访问代码",
                                            "severity": "medium",
                                            "details": f"匹配到: {match}"
                                        })
                                        self.medium_risk += 1
                                    elif pattern_name == "ai_model_loading":
                                        self.results["code_security"].append({
                                            "file": file_path,
                                            "issue": "发现AI模型加载代码",
                                            "severity": "medium",
                                            "details": f"匹配到: {match}"
                                        })
                                        self.medium_risk += 1
                                    elif pattern_name == "ai_input_validation":
                                        # 检查是否有输入验证
                                        if not re.search(r'(?i)(validate|sanitize|check)', content):
                                            self.results["code_security"].append({
                                                "file": file_path,
                                                "issue": "发现AI输入处理代码，可能缺少输入验证",
                                                "severity": "medium",
                                                "details": f"匹配到: {match}"
                                            })
                                            self.medium_risk += 1
                                    elif pattern_name == "ai_output_processing":
                                        # 检查是否有输出过滤
                                        if not re.search(r'(?i)(filter|sanitize|validate)', content):
                                            self.results["code_security"].append({
                                                "file": file_path,
                                                "issue": "发现AI输出处理代码，可能缺少输出过滤",
                                                "severity": "medium",
                                                "details": f"匹配到: {match}"
                                            })
                                            self.medium_risk += 1
                                    elif pattern_name == "ai_inference":
                                        self.results["code_security"].append({
                                            "file": file_path,
                                            "issue": "发现AI推理代码",
                                            "severity": "medium",
                                            "details": f"匹配到: {match}"
                                        })
                                        self.medium_risk += 1
                                    elif pattern_name == "ai_data_processing":
                                        self.results["code_security"].append({
                                            "file": file_path,
                                            "issue": "发现AI数据处理代码",
                                            "severity": "medium",
                                            "details": f"匹配到: {match}"
                                        })
                                        self.medium_risk += 1
                    except Exception as e:
                        logger.error(f"读取文件 {file_path} 时出错: {e}")
    
    def scan_permission_security(self):
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
                            "details": "建议仅对必要的脚本设置执行权限"
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
                                "details": f"当前权限: {permissions}，建议设置为 640"
                            })
                            self.high_risk += 1
                except Exception as e:
                    logger.error(f"检查文件权限 {file_path} 时出错: {e}")
    
    def scan_network_security(self):
        """扫描网络安全"""
        if not self.silent:
            print(f'{Fore.CYAN}扫描网络安全...{Style.RESET_ALL}')
        
        # 检查网络连接代码
        for root, dirs, files in os.walk(self.target):
            for file in files:
                if file.endswith(('.py', '.js')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # 检查硬编码的IP和端口
                            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                            port_pattern = r':\d{1,5}\b'
                            
                            ip_matches = re.findall(ip_pattern, content)
                            for ip in ip_matches:
                                self.results["network_security"].append({
                                    "file": file_path,
                                    "issue": "发现硬编码的IP地址",
                                    "severity": "medium",
                                    "details": f"IP地址: {ip}"
                                })
                                self.medium_risk += 1
                            
                            port_matches = re.findall(port_pattern, content)
                            for port in port_matches:
                                self.results["network_security"].append({
                                    "file": file_path,
                                    "issue": "发现硬编码的端口号",
                                    "severity": "low",
                                    "details": f"端口: {port}"
                                })
                                self.low_risk += 1
                            
                            # 检查监听地址
                            listen_pattern = r'(?i)(listen|bind)\s*\(.*?(0\.0\.0\.0|)' 
                            if re.search(listen_pattern, content):
                                self.results["network_security"].append({
                                    "file": file_path,
                                    "issue": "发现服务监听在所有网络接口",
                                    "severity": "high",
                                    "details": "服务可能暴露到公网，建议监听在 127.0.0.1"
                                })
                                self.high_risk += 1
                    except Exception as e:
                        logger.error(f"检查网络安全 {file_path} 时出错: {e}")
    
    def scan_dependency_security(self):
        """扫描依赖安全"""
        if not self.silent:
            print(f'{Fore.CYAN}扫描依赖安全...{Style.RESET_ALL}')
        
        # 检查requirements.txt或package.json
        dependency_files = [
            os.path.join(self.target, 'requirements.txt'),
            os.path.join(self.target, 'package.json'),
            os.path.join(self.target, 'pyproject.toml')
        ]
        
        for dep_file in dependency_files:
            if os.path.exists(dep_file):
                try:
                    if dep_file.endswith('requirements.txt'):
                        with open(dep_file, 'r', encoding='utf-8') as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    self.results["dependency_security"].append({
                                        "file": dep_file,
                                        "issue": "发现依赖包",
                                        "severity": "low",
                                        "details": f"依赖: {line}"
                                    })
                                    self.low_risk += 1
                                    
                                    # 检查依赖版本是否固定
                                    if '==' not in line:
                                        self.results["dependency_security"].append({
                                            "file": dep_file,
                                            "issue": "依赖库版本未固定",
                                            "severity": "medium",
                                            "details": f"依赖: {line}，建议固定版本号"
                                        })
                                        self.medium_risk += 1
                                    
                                    # 检查AI相关依赖
                                    ai_deps = ['tensorflow', 'keras', 'pytorch', 'torch', 'transformers', 'onnx', 'onnxruntime', 'scikit-learn', 'numpy', 'pandas']
                                    for ai_dep in ai_deps:
                                        if ai_dep in line.lower():
                                            self.results["dependency_security"].append({
                                                "file": dep_file,
                                                "issue": "发现AI相关依赖库",
                                                "severity": "medium",
                                                "details": f"依赖: {line}"
                                            })
                                            self.medium_risk += 1
                                            break
                    elif dep_file.endswith('package.json'):
                        with open(dep_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            if 'dependencies' in data:
                                for dep, version in data['dependencies'].items():
                                    self.results["dependency_security"].append({
                                        "file": dep_file,
                                        "issue": "发现依赖包",
                                        "severity": "low",
                                        "details": f"依赖: {dep}@{version}"
                                    })
                                    self.low_risk += 1
                                    
                                    # 检查依赖版本是否固定
                                    if version.startswith('^') or version.startswith('~') or version == '*':
                                        self.results["dependency_security"].append({
                                            "file": dep_file,
                                            "issue": "依赖库版本未固定",
                                            "severity": "medium",
                                            "details": f"依赖: {dep}@{version}，建议固定版本号"
                                        })
                                        self.medium_risk += 1
                except Exception as e:
                    logger.error(f"检查依赖文件 {dep_file} 时出错: {e}")
    
    def scan_config_security(self):
        """扫描配置安全"""
        if not self.silent:
            print(f'{Fore.CYAN}扫描配置安全...{Style.RESET_ALL}')
        
        # 检查配置文件
        config_files = [
            os.path.join(self.target, 'config.json'),
            os.path.join(self.target, 'config.yaml'),
            os.path.join(self.target, 'config.yml'),
            os.path.join(self.target, '.env'),
            os.path.join(self.target, 'model_config.json'),
            os.path.join(self.target, 'model_config.yaml'),
            os.path.join(self.target, 'model_config.yml')
        ]
        
        for config_file in config_files:
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # 检查敏感配置
                        sensitive_patterns = [
                            r'(?i)api[_\s-]?key',
                            r'(?i)password',
                            r'(?i)secret',
                            r'(?i)token',
                            r'(?i)database[_\s-]?url'
                        ]
                        
                        for pattern in sensitive_patterns:
                            if re.search(pattern, content):
                                self.results["config_security"].append({
                                    "file": config_file,
                                    "issue": "配置文件中可能包含敏感信息",
                                    "severity": "high",
                                    "details": f"匹配到敏感模式: {pattern}"
                                })
                                self.high_risk += 1
                        
                        # 检查AI特定配置
                        ai_config_patterns = [
                            r'(?i)model_path',
                            r'(?i)model_name',
                            r'(?i)model_dir',
                            r'(?i)api_key',
                            r'(?i)api_token',
                            r'(?i)endpoint',
                            r'(?i)url'
                        ]
                        
                        for pattern in ai_config_patterns:
                            if re.search(pattern, content):
                                self.results["config_security"].append({
                                    "file": config_file,
                                    "issue": "发现AI特定配置",
                                    "severity": "medium",
                                    "details": f"匹配到: {pattern}"
                                })
                                self.medium_risk += 1
                except Exception as e:
                    logger.error(f"检查配置文件 {config_file} 时出错: {e}")
