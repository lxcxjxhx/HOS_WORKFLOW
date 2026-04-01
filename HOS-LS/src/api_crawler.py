#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API爬虫模块

功能：
1. 自动抓取Web项目的接口
2. 识别API参数
3. 构建API调用链
4. 生成API文档
"""

import os
import re
import json
import logging
import requests
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs

# 尝试导入BeautifulSoup
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    BeautifulSoup = None
    HAS_BS4 = False

logger = logging.getLogger(__name__)

@dataclass
class APIEndpoint:
    """API端点信息"""
    url: str
    method: str
    params: Dict[str, List[str]]
    headers: Dict[str, str]
    body: Optional[Dict[str, Any]] = None
    description: str = ""
    risk_level: str = "low"  # high, medium, low

class APICrawler:
    """API爬虫"""
    
    def __init__(self, base_url: str, max_depth: int = 3, timeout: int = 10):
        """初始化API爬虫
        
        Args:
            base_url: 基础URL
            max_depth: 最大爬取深度
            timeout: 请求超时时间
        """
        self.base_url = base_url
        self.max_depth = max_depth
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.visited_urls = set()
        self.api_endpoints = []
    
    def crawl(self) -> List[APIEndpoint]:
        """开始爬取API端点
        
        Returns:
            List[APIEndpoint]: 发现的API端点列表
        """
        self._crawl_recursive(self.base_url, 0)
        return self.api_endpoints
    
    def _crawl_recursive(self, url: str, depth: int):
        """递归爬取URL
        
        Args:
            url: 当前URL
            depth: 当前爬取深度
        """
        if depth >= self.max_depth:
            return
        
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            # 检测是否为API响应
            if self._is_api_response(response):
                self._extract_api_endpoint(url, response)
            
            # 解析HTML，提取链接
            if 'text/html' in response.headers.get('Content-Type', '') and HAS_BS4:
                soup = BeautifulSoup(response.text, 'html.parser')
                self._extract_links(soup, url, depth)
            elif 'text/html' in response.headers.get('Content-Type', ''):
                logger.debug("BeautifulSoup not available, skipping HTML parsing")
                
        except Exception as e:
            logger.debug(f"爬取 {url} 失败：{e}")
    
    def _is_api_response(self, response: requests.Response) -> bool:
        """检测是否为API响应
        
        Args:
            response: HTTP响应
            
        Returns:
            bool: 是否为API响应
        """
        content_type = response.headers.get('Content-Type', '')
        return any(ct in content_type for ct in ['application/json', 'application/xml', 'text/json'])
    
    def _extract_api_endpoint(self, url: str, response: requests.Response):
        """提取API端点信息
        
        Args:
            url: API URL
            response: HTTP响应
        """
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        endpoint = APIEndpoint(
            url=url,
            method='GET',
            params=params,
            headers=dict(response.headers)
        )
        
        # 尝试解析响应体
        try:
            if response.text:
                endpoint.body = response.json()
        except json.JSONDecodeError:
            pass
        
        self.api_endpoints.append(endpoint)
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str, depth: int):
        """从HTML中提取链接
        
        Args:
            soup: BeautifulSoup对象
            base_url: 基础URL
            depth: 当前爬取深度
        """
        # 提取<a>标签
        for a_tag in soup.find_all('a', href=True):
            href = a_tag.get('href')
            absolute_url = urljoin(base_url, href)
            
            # 确保是同域链接
            if self._is_same_domain(absolute_url):
                self._crawl_recursive(absolute_url, depth + 1)
        
        # 提取<form>标签
        for form_tag in soup.find_all('form'):
            action = form_tag.get('action', '')
            method = form_tag.get('method', 'GET').upper()
            
            absolute_url = urljoin(base_url, action)
            if self._is_same_domain(absolute_url):
                # 提取表单参数
                form_params = {}
                for input_tag in form_tag.find_all('input'):
                    name = input_tag.get('name')
                    value = input_tag.get('value', '')
                    if name:
                        form_params[name] = [value]
                
                # 创建API端点
                endpoint = APIEndpoint(
                    url=absolute_url,
                    method=method,
                    params=form_params,
                    headers={}
                )
                self.api_endpoints.append(endpoint)
    
    def _is_same_domain(self, url: str) -> bool:
        """检测是否为同域链接
        
        Args:
            url: 要检测的URL
            
        Returns:
            bool: 是否为同域链接
        """
        base_domain = urlparse(self.base_url).netloc
        target_domain = urlparse(url).netloc
        return target_domain == base_domain or target_domain == ''
    
    def analyze_api_endpoints(self) -> List[APIEndpoint]:
        """分析API端点，评估风险等级
        
        Returns:
            List[APIEndpoint]: 分析后的API端点列表
        """
        for endpoint in self.api_endpoints:
            # 基于URL路径和参数评估风险
            path = urlparse(endpoint.url).path
            
            # 高风险路径
            high_risk_paths = ['/admin', '/api', '/login', '/auth', '/user', '/account']
            # 高风险参数
            high_risk_params = ['id', 'user', 'password', 'token', 'api_key', 'secret']
            
            # 评估风险等级
            if any(risk_path in path for risk_path in high_risk_paths):
                endpoint.risk_level = 'high'
            elif any(risk_param in endpoint.params for risk_param in high_risk_params):
                endpoint.risk_level = 'medium'
            
            # 生成描述
            endpoint.description = self._generate_description(endpoint)
        
        return self.api_endpoints
    
    def _generate_description(self, endpoint: APIEndpoint) -> str:
        """生成API端点描述
        
        Args:
            endpoint: API端点
            
        Returns:
            str: 描述
        """
        path = urlparse(endpoint.url).path
        method = endpoint.method
        
        descriptions = {
            '/login': '用户登录接口',
            '/auth': '认证接口',
            '/api': 'API接口',
            '/admin': '管理后台接口',
            '/user': '用户相关接口',
            '/account': '账户相关接口',
            '/data': '数据相关接口',
            '/upload': '文件上传接口',
            '/download': '文件下载接口'
        }
        
        for key, desc in descriptions.items():
            if key in path:
                return f"{method} {desc}"
        
        return f"{method} {path}"
    
    def export_api_documentation(self, output_file: str):
        """导出API文档
        
        Args:
            output_file: 输出文件路径
        """
        api_data = []
        for endpoint in self.api_endpoints:
            api_data.append({
                'url': endpoint.url,
                'method': endpoint.method,
                'params': endpoint.params,
                'headers': endpoint.headers,
                'body': endpoint.body,
                'description': endpoint.description,
                'risk_level': endpoint.risk_level
            })
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(api_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"API文档已导出到：{output_file}")

if __name__ == '__main__':
    # 测试API爬虫
    crawler = APICrawler('https://httpbin.org', max_depth=2)
    endpoints = crawler.crawl()
    analyzed_endpoints = crawler.analyze_api_endpoints()
    
    print(f"发现 {len(analyzed_endpoints)} 个API端点：")
    for i, endpoint in enumerate(analyzed_endpoints):
        print(f"\n{i+1}. {endpoint.method} {endpoint.url}")
        print(f"   描述: {endpoint.description}")
        print(f"   风险等级: {endpoint.risk_level}")
        print(f"   参数: {endpoint.params}")
    
    # 导出API文档
    crawler.export_api_documentation('api_documentation.json')
