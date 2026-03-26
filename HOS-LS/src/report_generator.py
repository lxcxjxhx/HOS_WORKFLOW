#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告生成模块
"""

import os
import json
from datetime import datetime
from jinja2 import Template
from docx import Document
from docx.shared import Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH

class ReportGenerator:
    """报告生成器类"""
    
    def __init__(self, results, target, output_dir):
        """初始化报告生成器
        
        Args:
            results: 扫描结果
            target: 扫描目标
            output_dir: 输出目录
        """
        self.results = results
        self.target = target
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def generate_html(self, filename='security_report.html', template_file=None):
        """生成HTML报告"""
        # 尝试从模板文件加载
        if template_file and os.path.exists(template_file):
            with open(template_file, 'r', encoding='utf-8') as f:
                template_content = f.read()
            template = Template(template_content)
        # 尝试从templates目录加载（检查多个可能的位置）
        elif os.path.exists('templates'):
            template_path = os.path.join('templates', 'html_template.html')
            if os.path.exists(template_path):
                with open(template_path, 'r', encoding='utf-8') as f:
                    template_content = f.read()
                template = Template(template_content)
            else:
                # 使用默认模板
                template = Template('''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HOS-LS 安全检测报告</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
        }
        h2 {
            color: #555;
            margin-top: 30px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }
        .summary {
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary-item {
            display: inline-block;
            margin-right: 20px;
        }
        .high-risk {
            color: #d32f2f;
            font-weight: bold;
        }
        .medium-risk {
            color: #f57c00;
            font-weight: bold;
        }
        .low-risk {
            color: #388e3c;
            font-weight: bold;
        }
        .risk-level {
            padding: 5px 10px;
            border-radius: 15px;
            font-weight: bold;
        }
        .risk-high {
            background-color: #ffebee;
            color: #c62828;
        }
        .risk-medium {
            background-color: #fff3e0;
            color: #ef6c00;
        }
        .risk-low {
            background-color: #e8f5e8;
            color: #2e7d32;
        }
        .project-info {
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .security-assessment {
            background-color: #f3e5f5;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .recommendations {
            background-color: #fff8e1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .recommendation-item {
            margin-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .footer {
            margin-top: 40px;
            text-align: center;
            color: #666;
            font-size: 14px;
        }
        /* 选项卡样式 */
        .tab-button {
            background-color: #f1f1f1;
            border: 1px solid #ddd;
            padding: 10px 15px;
            cursor: pointer;
            margin-right: 5px;
            border-radius: 4px 4px 0 0;
            transition: background-color 0.3s;
        }
        .tab-button:hover {
            background-color: #ddd;
        }
        .tab-button.active {
            background-color: #f0f0f0;
            font-weight: bold;
        }
        .tab-content {
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 4px 4px;
        }
        /* 复制按钮样式 */
        .copy-button {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 8px 15px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 14px;
            margin: 4px 2px;
            cursor: pointer;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .copy-button:hover {
            background-color: #45a049;
        }
        .copy-button:active {
            background-color: #3e8e41;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>HOS-LS 安全检测报告</h1>
        
        <div class="project-info">
            <h2>项目信息</h2>
            <div class="summary-item">检测目标: {{ target }}</div>
            <div class="summary-item">检测时间: {{ timestamp }}</div>
            <div class="summary-item">项目类型: {{ project_type }}</div>
            <div class="summary-item">使用规则集: {{ rule_set }}</div>
        </div>
        
        <div class="summary">
            <h2>检测摘要</h2>
            <div class="summary-item high-risk">高风险: {{ high_risk }}</div>
            <div class="summary-item medium-risk">中风险: {{ medium_risk }}</div>
            <div class="summary-item low-risk">低风险: {{ low_risk }}</div>
            <div class="summary-item">总体风险等级: <span class="risk-level risk-{{ overall_risk }}">{{ overall_risk_text }}</span></div>
        </div>
        
        <div class="security-assessment">
            <h2>安全评估</h2>
            <p>{{ security_assessment }}</p>
        </div>
        
        <div class="recommendations">
            <h2>安全建议</h2>
            {% for recommendation in recommendations %}
            <div class="recommendation-item">
                <strong>{{ recommendation.severity }}风险:</strong> {{ recommendation.text }}
            </div>
            {% endfor %}
        </div>
        
        {% if code_security %}
        <h2>代码安全</h2>
        <table>
            <tr>
                <th>文件</th>
                <th>问题</th>
                <th>严重程度</th>
                <th>详情</th>
            </tr>
            {% for item in code_security %}
            <tr>
                <td>{{ item.file }}</td>
                <td>{{ item.issue }}</td>
                <td class="{{ item.severity }}-risk">{{ item.severity }}</td>
                <td>{{ item.details }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if permission_security %}
        <h2>权限安全</h2>
        <table>
            <tr>
                <th>文件</th>
                <th>问题</th>
                <th>严重程度</th>
                <th>详情</th>
            </tr>
            {% for item in permission_security %}
            <tr>
                <td>{{ item.file }}</td>
                <td>{{ item.issue }}</td>
                <td class="{{ item.severity }}-risk">{{ item.severity }}</td>
                <td>{{ item.details }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if network_security %}
        <h2>网络安全</h2>
        <table>
            <tr>
                <th>文件</th>
                <th>问题</th>
                <th>严重程度</th>
                <th>详情</th>
            </tr>
            {% for item in network_security %}
            <tr>
                <td>{{ item.file }}</td>
                <td>{{ item.issue }}</td>
                <td class="{{ item.severity }}-risk">{{ item.severity }}</td>
                <td>{{ item.details }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if dependency_security %}
        <h2>依赖安全</h2>
        <table>
            <tr>
                <th>文件</th>
                <th>问题</th>
                <th>严重程度</th>
                <th>详情</th>
            </tr>
            {% for item in dependency_security %}
            <tr>
                <td>{{ item.file }}</td>
                <td>{{ item.issue }}</td>
                <td class="{{ item.severity }}-risk">{{ item.severity }}</td>
                <td>{{ item.details }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if config_security %}
        <h2>配置安全</h2>
        <table>
            <tr>
                <th>文件</th>
                <th>问题</th>
                <th>严重程度</th>
                <th>详情</th>
            </tr>
            {% for item in config_security %}
            <tr>
                <td>{{ item.file }}</td>
                <td>{{ item.issue }}</td>
                <td class="{{ item.severity }}-risk">{{ item.severity }}</td>
                <td>{{ item.details }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        <div class="recommendations">
            <h2>AI安全建议</h2>
            {% if ai_suggestions.risk_assessment %}
            <div class="recommendation-item">
                <strong>风险评估:</strong> {{ ai_suggestions.risk_assessment }}
            </div>
            {% endif %}
            
            {% if ai_suggestions.specific_suggestions %}
            <h3>针对性建议</h3>
            {% for suggestion in ai_suggestions.specific_suggestions %}
            <div class="recommendation-item">
                {{ suggestion }}
            </div>
            {% endfor %}
            {% endif %}
            
            {% if ai_suggestions.best_practices %}
            <h3>安全最佳实践</h3>
            {% for practice in ai_suggestions.best_practices %}
            <div class="recommendation-item">
                {{ practice }}
            </div>
            {% endfor %}
            {% endif %}
            
            <h3>AI工具提示词</h3>
            
            <!-- 选项卡 -->
            <div style="margin-bottom: 10px;">
                <button class="tab-button active" onclick="switchTab('cursor')">Cursor</button>
                <button class="tab-button" onclick="switchTab('trae')">Trae</button>
                <button class="tab-button" onclick="switchTab('kiro')">Kiro</button>
            </div>
            
            <!-- 提示词内容 -->
            <div id="cursor-tab" class="tab-content active" style="background-color: #f0f0f0; padding: 15px; border-radius: 5px; white-space: pre-wrap; font-family: monospace;">
                {{ ai_suggestions.cursor_prompt | default('# Cursor 安全提示词\nAI工具安全提示词\n\n## 针对 Cursor 的安全建议\n\n### 风险评估\n正在生成风险评估...\n\n### 针对性建议\n- 正在生成针对性建议...\n\n### 安全最佳实践\n- 正在生成安全最佳实践...\n\n### 通用安全规则\n- 避免硬编码敏感信息，使用环境变量存储\n- 谨慎使用exec()、eval()等函数，防止代码注入攻击\n- 确保网络访问代码有适当的错误处理和安全验证') }}
            </div>
            
            <div id="trae-tab" class="tab-content" style="display: none; background-color: #f0f0f0; padding: 15px; border-radius: 5px; white-space: pre-wrap; font-family: monospace;">
                {{ ai_suggestions.trae_prompt | default('# Trae 安全提示词\nAI工具安全提示词\n\n## 针对 Trae 的安全建议\n\n### 风险评估\n正在生成风险评估...\n\n### 针对性建议\n- [安全提示] 正在生成针对性建议...\n\n### 安全最佳实践\n- [安全提示] 正在生成安全最佳实践...\n\n### 通用安全规则\n[安全规则] 请遵循安全最佳实践，确保代码安全。') }}
            </div>
            
            <div id="kiro-tab" class="tab-content" style="display: none; background-color: #f0f0f0; padding: 15px; border-radius: 5px; white-space: pre-wrap; font-family: monospace;">
                {{ ai_suggestions.kiro_prompt | default('# Kiro 安全提示词\nAI工具安全提示词\n\n## 针对 Kiro 的安全建议\n\n### 风险评估\n正在生成风险评估...\n\n### 针对性建议\n- 安全提醒：正在生成针对性建议...\n\n### 安全最佳实践\n- 安全提醒：正在生成安全最佳实践...\n\n### 通用安全规则\n• 避免硬编码敏感信息，使用环境变量存储\n• 谨慎使用exec()、eval()等函数，防止代码注入攻击\n• 确保网络访问代码有适当的错误处理和安全验证') }}
            </div>
            
            <!-- 复制按钮 -->
            <div style="margin-top: 10px;">
                <button onclick="copyContent('cursor-tab')" class="copy-button">复制Cursor提示词</button>
                <button onclick="copyContent('trae-tab')" class="copy-button">复制Trae提示词</button>
                <button onclick="copyContent('kiro-tab')" class="copy-button">复制Kiro提示词</button>
            </div>
            <p style="margin-top: 10px; font-size: 12px; color: #666;">提示：点击上方按钮复制对应IDE的提示词</p>
        </div>
        
        <div class="footer">
            <p>报告生成时间: {{ timestamp }}</p>
            <p>HOS-LS 安全检测工具 v1.0.0</p>
        </div>
    </div>
    <script>
        // 选项卡切换功能
        function switchTab(tabName) {
            // 隐藏所有选项卡内容
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(content => {
                content.style.display = 'none';
            });
            
            // 移除所有选项卡按钮的活动状态
            const tabButtons = document.querySelectorAll('.tab-button');
            tabButtons.forEach(button => {
                button.classList.remove('active');
            });
            
            // 显示选中的选项卡内容
            document.getElementById(tabName + '-tab').style.display = 'block';
            
            // 激活选中的选项卡按钮
            event.currentTarget.classList.add('active');
        }
        
        // 复制内容到剪贴板
        function copyContent(tabId) {
            const content = document.getElementById(tabId).innerText;
            navigator.clipboard.writeText(content)
                .then(() => {
                    // 显示复制成功提示
                    const button = event.currentTarget;
                    const originalText = button.innerText;
                    button.innerText = '已复制!';
                    button.style.backgroundColor = '#4CAF50';
                    
                    // 2秒后恢复按钮状态
                    setTimeout(() => {
                        button.innerText = originalText;
                        button.style.backgroundColor = '';
                    }, 2000);
                })
                .catch(err => {
                    console.error('复制失败:', err);
                });
        }
    </script>
</body>
</html>
''')
        # 如果templates目录不存在，也使用默认模板
        else:
            # 使用默认模板
            template = Template('''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HOS-LS 安全检测报告</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
        }
        h2 {
            color: #555;
            margin-top: 30px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }
        .summary {
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary-item {
            display: inline-block;
            margin-right: 20px;
        }
        .high-risk {
            color: #d32f2f;
            font-weight: bold;
        }
        .medium-risk {
            color: #f57c00;
            font-weight: bold;
        }
        .low-risk {
            color: #388e3c;
            font-weight: bold;
        }
        .risk-level {
            padding: 5px 10px;
            border-radius: 15px;
            font-weight: bold;
        }
        .risk-high {
            background-color: #ffebee;
            color: #c62828;
        }
        .risk-medium {
            background-color: #fff3e0;
            color: #ef6c00;
        }
        .risk-low {
            background-color: #e8f5e8;
            color: #2e7d32;
        }
        .project-info {
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .security-assessment {
            background-color: #f3e5f5;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .recommendations {
            background-color: #fff8e1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .recommendation-item {
            margin-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .footer {
            margin-top: 40px;
            text-align: center;
            color: #666;
            font-size: 14px;
        }
        /* 选项卡样式 */
        .tab-button {
            background-color: #f1f1f1;
            border: 1px solid #ddd;
            padding: 10px 15px;
            cursor: pointer;
            margin-right: 5px;
            border-radius: 4px 4px 0 0;
            transition: background-color 0.3s;
        }
        .tab-button:hover {
            background-color: #ddd;
        }
        .tab-button.active {
            background-color: #f0f0f0;
            font-weight: bold;
        }
        .tab-content {
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 4px 4px;
        }
        /* 复制按钮样式 */
        .copy-button {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 8px 15px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 14px;
            margin: 4px 2px;
            cursor: pointer;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .copy-button:hover {
            background-color: #45a049;
        }
        .copy-button:active {
            background-color: #3e8e41;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>HOS-LS 安全检测报告</h1>
        
        <div class="project-info">
            <h2>项目信息</h2>
            <div class="summary-item">检测目标: {{ target }}</div>
            <div class="summary-item">检测时间: {{ timestamp }}</div>
            <div class="summary-item">项目类型: {{ project_type }}</div>
            <div class="summary-item">使用规则集: {{ rule_set }}</div>
        </div>
        
        <div class="summary">
            <h2>检测摘要</h2>
            <div class="summary-item high-risk">高风险: {{ high_risk }}</div>
            <div class="summary-item medium-risk">中风险: {{ medium_risk }}</div>
            <div class="summary-item low-risk">低风险: {{ low_risk }}</div>
            <div class="summary-item">总体风险等级: <span class="risk-level risk-{{ overall_risk }}">{{ overall_risk_text }}</span></div>
        </div>
        
        <div class="security-assessment">
            <h2>安全评估</h2>
            <p>{{ security_assessment }}</p>
        </div>
        
        <div class="recommendations">
            <h2>安全建议</h2>
            {% for recommendation in recommendations %}
            <div class="recommendation-item">
                <strong>{{ recommendation.severity }}风险:</strong> {{ recommendation.text }}
            </div>
            {% endfor %}
        </div>
        
        {% if code_security %}
        <h2>代码安全</h2>
        <table>
            <tr>
                <th>文件</th>
                <th>问题</th>
                <th>严重程度</th>
                <th>详情</th>
            </tr>
            {% for item in code_security %}
            <tr>
                <td>{{ item.file }}</td>
                <td>{{ item.issue }}</td>
                <td class="{{ item.severity }}-risk">{{ item.severity }}</td>
                <td>{{ item.details }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if permission_security %}
        <h2>权限安全</h2>
        <table>
            <tr>
                <th>文件</th>
                <th>问题</th>
                <th>严重程度</th>
                <th>详情</th>
            </tr>
            {% for item in permission_security %}
            <tr>
                <td>{{ item.file }}</td>
                <td>{{ item.issue }}</td>
                <td class="{{ item.severity }}-risk">{{ item.severity }}</td>
                <td>{{ item.details }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if network_security %}
        <h2>网络安全</h2>
        <table>
            <tr>
                <th>文件</th>
                <th>问题</th>
                <th>严重程度</th>
                <th>详情</th>
            </tr>
            {% for item in network_security %}
            <tr>
                <td>{{ item.file }}</td>
                <td>{{ item.issue }}</td>
                <td class="{{ item.severity }}-risk">{{ item.severity }}</td>
                <td>{{ item.details }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if dependency_security %}
        <h2>依赖安全</h2>
        <table>
            <tr>
                <th>文件</th>
                <th>问题</th>
                <th>严重程度</th>
                <th>详情</th>
            </tr>
            {% for item in dependency_security %}
            <tr>
                <td>{{ item.file }}</td>
                <td>{{ item.issue }}</td>
                <td class="{{ item.severity }}-risk">{{ item.severity }}</td>
                <td>{{ item.details }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if config_security %}
        <h2>配置安全</h2>
        <table>
            <tr>
                <th>文件</th>
                <th>问题</th>
                <th>严重程度</th>
                <th>详情</th>
            </tr>
            {% for item in config_security %}
            <tr>
                <td>{{ item.file }}</td>
                <td>{{ item.issue }}</td>
                <td class="{{ item.severity }}-risk">{{ item.severity }}</td>
                <td>{{ item.details }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        <div class="recommendations">
            <h2>AI安全建议</h2>
            {% if ai_suggestions.risk_assessment %}
            <div class="recommendation-item">
                <strong>风险评估:</strong> {{ ai_suggestions.risk_assessment }}
            </div>
            {% endif %}
            
            {% if ai_suggestions.specific_suggestions %}
            <h3>针对性建议</h3>
            {% for suggestion in ai_suggestions.specific_suggestions %}
            <div class="recommendation-item">
                {{ suggestion }}
            </div>
            {% endfor %}
            {% endif %}
            
            {% if ai_suggestions.best_practices %}
            <h3>安全最佳实践</h3>
            {% for practice in ai_suggestions.best_practices %}
            <div class="recommendation-item">
                {{ practice }}
            </div>
            {% endfor %}
            {% endif %}
            
            <h3>AI工具提示词</h3>
            
            <!-- 选项卡 -->
            <div style="margin-bottom: 10px;">
                <button class="tab-button active" onclick="switchTab('cursor')">Cursor</button>
                <button class="tab-button" onclick="switchTab('trae')">Trae</button>
                <button class="tab-button" onclick="switchTab('kiro')">Kiro</button>
            </div>
            
            <!-- 提示词内容 -->
            <div id="cursor-tab" class="tab-content active" style="background-color: #f0f0f0; padding: 15px; border-radius: 5px; white-space: pre-wrap; font-family: monospace;">
                {{ ai_suggestions.cursor_prompt | default('# Cursor 安全提示词\nAI工具安全提示词\n\n## 针对 Cursor 的安全建议\n\n### 风险评估\n正在生成风险评估...\n\n### 针对性建议\n- 正在生成针对性建议...\n\n### 安全最佳实践\n- 正在生成安全最佳实践...\n\n### 通用安全规则\n- 避免硬编码敏感信息，使用环境变量存储\n- 谨慎使用exec()、eval()等函数，防止代码注入攻击\n- 确保网络访问代码有适当的错误处理和安全验证') }}
            </div>
            
            <div id="trae-tab" class="tab-content" style="display: none; background-color: #f0f0f0; padding: 15px; border-radius: 5px; white-space: pre-wrap; font-family: monospace;">
                {{ ai_suggestions.trae_prompt | default('# Trae 安全提示词\nAI工具安全提示词\n\n## 针对 Trae 的安全建议\n\n### 风险评估\n正在生成风险评估...\n\n### 针对性建议\n- [安全提示] 正在生成针对性建议...\n\n### 安全最佳实践\n- [安全提示] 正在生成安全最佳实践...\n\n### 通用安全规则\n[安全规则] 请遵循安全最佳实践，确保代码安全。') }}
            </div>
            
            <div id="kiro-tab" class="tab-content" style="display: none; background-color: #f0f0f0; padding: 15px; border-radius: 5px; white-space: pre-wrap; font-family: monospace;">
                {{ ai_suggestions.kiro_prompt | default('# Kiro 安全提示词\nAI工具安全提示词\n\n## 针对 Kiro 的安全建议\n\n### 风险评估\n正在生成风险评估...\n\n### 针对性建议\n- 安全提醒：正在生成针对性建议...\n\n### 安全最佳实践\n- 安全提醒：正在生成安全最佳实践...\n\n### 通用安全规则\n• 避免硬编码敏感信息，使用环境变量存储\n• 谨慎使用exec()、eval()等函数，防止代码注入攻击\n• 确保网络访问代码有适当的错误处理和安全验证') }}
            </div>
            
            <!-- 复制按钮 -->
            <div style="margin-top: 10px;">
                <button onclick="copyContent('cursor-tab')" class="copy-button">复制Cursor提示词</button>
                <button onclick="copyContent('trae-tab')" class="copy-button">复制Trae提示词</button>
                <button onclick="copyContent('kiro-tab')" class="copy-button">复制Kiro提示词</button>
            </div>
            <p style="margin-top: 10px; font-size: 12px; color: #666;">提示：点击上方按钮复制对应IDE的提示词</p>
        </div>
        
        <div class="footer">
            <p>报告生成时间: {{ timestamp }}</p>
            <p>HOS-LS 安全检测工具 v1.0.0</p>
        </div>
    </div>
    <script>
        // 选项卡切换功能
        function switchTab(tabName) {
            // 隐藏所有选项卡内容
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(content => {
                content.style.display = 'none';
            });
            
            // 移除所有选项卡按钮的活动状态
            const tabButtons = document.querySelectorAll('.tab-button');
            tabButtons.forEach(button => {
                button.classList.remove('active');
            });
            
            // 显示选中的选项卡内容
            document.getElementById(tabName + '-tab').style.display = 'block';
            
            // 激活选中的选项卡按钮
            event.currentTarget.classList.add('active');
        }
        
        // 复制内容到剪贴板
        function copyContent(tabId) {
            const content = document.getElementById(tabId).innerText;
            navigator.clipboard.writeText(content)
                .then(() => {
                    // 显示复制成功提示
                    const button = event.currentTarget;
                    const originalText = button.innerText;
                    button.innerText = '已复制!';
                    button.style.backgroundColor = '#4CAF50';
                    
                    // 2秒后恢复按钮状态
                    setTimeout(() => {
                        button.innerText = originalText;
                        button.style.backgroundColor = '';
                    }, 2000);
                })
                .catch(err => {
                    console.error('复制失败:', err);
                });
        }
    </script>
</body>
</html>
''')
        
        # 计算风险数量
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        for category in self.results.values():
            if isinstance(category, list):
                for item in category:
                    if item.get('severity') == 'high':
                        high_risk += 1
                    elif item.get('severity') == 'medium':
                        medium_risk += 1
                    elif item.get('severity') == 'low':
                        low_risk += 1
        
        # 计算总体风险等级
        if high_risk > 0:
            overall_risk = 'high'
            overall_risk_text = '高风险'
        elif medium_risk > 3:
            overall_risk = 'medium'
            overall_risk_text = '中风险'
        else:
            overall_risk = 'low'
            overall_risk_text = '低风险'
        
        # 获取项目类型和规则集
        project_type = self.results.get('project_type', 'unknown')
        rule_set = self.results.get('rule_set', 'default')
        
        # 生成安全评估
        security_assessment = f"本次安全扫描共发现 {high_risk} 个高风险问题，{medium_risk} 个中风险问题，{low_risk} 个低风险问题。"
        if high_risk > 0:
            security_assessment += " 系统存在严重安全隐患，建议立即处理高风险问题。"
        elif medium_risk > 3:
            security_assessment += " 系统存在一定安全风险，建议尽快处理中风险问题。"
        else:
            security_assessment += " 系统安全状态良好，建议定期进行安全检查。"
        
        # 生成安全建议
        recommendations = []
        if high_risk > 0:
            recommendations.append({"severity": "高", "text": "立即处理所有高风险问题，特别是硬编码的敏感信息和后门代码。"})
        if medium_risk > 0:
            recommendations.append({"severity": "中", "text": "尽快处理中风险问题，如网络访问代码的安全验证和依赖库版本管理。"})
        if low_risk > 0:
            recommendations.append({"severity": "低", "text": "定期进行安全检查，保持系统和依赖库的更新。"})
        
        # 根据项目类型生成特定建议
        if project_type == "openclaw":
            recommendations.append({"severity": "中", "text": "确保OpenClaw端口仅本地监听，避免公网暴露。"})
            recommendations.append({"severity": "中", "text": "定期更新OpenClaw到最新版本，获取安全修复。"})
        elif project_type == "cursor":
            recommendations.append({"severity": "中", "text": "确保Cursor生成的代码不包含硬编码的API密钥。"})
            recommendations.append({"severity": "低", "text": "审查Cursor生成的提示模板，确保不包含敏感信息。"})
        
        # 通用安全建议
        recommendations.append({"severity": "低", "text": "使用环境变量存储敏感信息，避免硬编码。"})
        recommendations.append({"severity": "低", "text": "遵循最小权限原则，限制文件和目录权限。"})
        recommendations.append({"severity": "低", "text": "定期进行安全扫描，及时发现和处理安全问题。"})
        
        # 获取AI建议
        ai_suggestions = self.results.get('ai_suggestions', {})
        
        html = template.render(
            target=self.target,
            timestamp=self.timestamp,
            high_risk=high_risk,
            medium_risk=medium_risk,
            low_risk=low_risk,
            overall_risk=overall_risk,
            overall_risk_text=overall_risk_text,
            security_assessment=security_assessment,
            recommendations=recommendations,
            project_type=project_type,
            rule_set=rule_set,
            code_security=self.results.get('code_security', []),
            permission_security=self.results.get('permission_security', []),
            network_security=self.results.get('network_security', []),
            dependency_security=self.results.get('dependency_security', []),
            config_security=self.results.get('config_security', []),
            ai_suggestions=ai_suggestions
        )
        
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_path
    
    def generate_docx(self, filename='security_report.docx'):
        """生成DOCX报告"""
        doc = Document()
        
        # 添加标题
        doc.add_heading('HOS-LS 安全检测报告', 0)
        
        # 添加检测摘要
        doc.add_heading('检测摘要', level=1)
        
        # 计算风险数量
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        for category in self.results.values():
            if isinstance(category, list):
                for item in category:
                    if item['severity'] == 'high':
                        high_risk += 1
                    elif item['severity'] == 'medium':
                        medium_risk += 1
                    elif item['severity'] == 'low':
                        low_risk += 1
        
        # 添加摘要内容
        summary_table = doc.add_table(rows=1, cols=5)
        hdr_cells = summary_table.rows[0].cells
        hdr_cells[0].text = '检测目标'
        hdr_cells[1].text = '检测时间'
        hdr_cells[2].text = '高风险'
        hdr_cells[3].text = '中风险'
        hdr_cells[4].text = '低风险'
        
        row_cells = summary_table.add_row().cells
        row_cells[0].text = self.target
        row_cells[1].text = self.timestamp
        row_cells[2].text = str(high_risk)
        row_cells[3].text = str(medium_risk)
        row_cells[4].text = str(low_risk)
        
        # 添加详细内容
        categories = [
            ('代码安全', 'code_security'),
            ('权限安全', 'permission_security'),
            ('网络安全', 'network_security'),
            ('依赖安全', 'dependency_security'),
            ('配置安全', 'config_security')
        ]
        
        for category_name, category_key in categories:
            items = self.results.get(category_key, [])
            if items:
                doc.add_heading(category_name, level=1)
                table = doc.add_table(rows=1, cols=4)
                hdr_cells = table.rows[0].cells
                hdr_cells[0].text = '文件'
                hdr_cells[1].text = '问题'
                hdr_cells[2].text = '严重程度'
                hdr_cells[3].text = '详情'
                
                for item in items:
                    row_cells = table.add_row().cells
                    row_cells[0].text = item['file']
                    row_cells[1].text = item['issue']
                    row_cells[2].text = item['severity']
                    row_cells[3].text = item['details']
        
        # 添加页脚
        section = doc.sections[0]
        footer = section.footer
        footer_paragraph = footer.add_paragraph()
        footer_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        footer_paragraph.add_run(f'报告生成时间: {self.timestamp}')
        footer_paragraph.add_run('\nHOS-LS 安全检测工具 v1.0.0')
        
        output_path = os.path.join(self.output_dir, filename)
        doc.save(output_path)
        
        return output_path
    
    def generate_md(self, filename='security_report.md', template_file=None):
        """生成MD报告"""
        # 计算风险数量
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        for category in self.results.values():
            if isinstance(category, list):
                for item in category:
                    if item['severity'] == 'high':
                        high_risk += 1
                    elif item['severity'] == 'medium':
                        medium_risk += 1
                    elif item['severity'] == 'low':
                        low_risk += 1
        
        # 尝试从模板文件加载
        if template_file and os.path.exists(template_file):
            with open(template_file, 'r', encoding='utf-8') as f:
                template_content = f.read()
            template = Template(template_content)
            md = template.render(
                target=self.target,
                timestamp=self.timestamp,
                high_risk=high_risk,
                medium_risk=medium_risk,
                low_risk=low_risk,
                code_security=self.results.get('code_security', []),
                permission_security=self.results.get('permission_security', []),
                network_security=self.results.get('network_security', []),
                dependency_security=self.results.get('dependency_security', []),
                config_security=self.results.get('config_security', [])
            )
        # 尝试从templates目录加载
        elif os.path.exists('templates'):
            template_path = os.path.join('templates', 'md_template.md')
            if os.path.exists(template_path):
                with open(template_path, 'r', encoding='utf-8') as f:
                    template_content = f.read()
                template = Template(template_content)
                md = template.render(
                    target=self.target,
                    timestamp=self.timestamp,
                    high_risk=high_risk,
                    medium_risk=medium_risk,
                    low_risk=low_risk,
                    code_security=self.results.get('code_security', []),
                    permission_security=self.results.get('permission_security', []),
                    network_security=self.results.get('network_security', []),
                    dependency_security=self.results.get('dependency_security', []),
                    config_security=self.results.get('config_security', [])
                )
            else:
                # 使用默认模板
                md = f'''
# HOS-LS 安全检测报告

## 检测摘要

| 检测目标 | 检测时间 | 高风险 | 中风险 | 低风险 |
|---------|---------|-------|-------|-------|
| {self.target} | {self.timestamp} | {high_risk} | {medium_risk} | {low_risk} |
'''
                
                # 添加详细内容
                categories = [
                    ('代码安全', 'code_security'),
                    ('权限安全', 'permission_security'),
                    ('网络安全', 'network_security'),
                    ('依赖安全', 'dependency_security'),
                    ('配置安全', 'config_security')
                ]
                
                for category_name, category_key in categories:
                    items = self.results.get(category_key, [])
                    if items:
                        md += f'''
## {category_name}

| 文件 | 问题 | 严重程度 | 详情 |
|------|------|---------|------|
'''
                        for item in items:
                            md += f'| {item["file"]} | {item["issue"]} | {item["severity"]} | {item["details"]} |\n'
                
                md += f'''
---

报告生成时间: {self.timestamp}
HOS-LS 安全检测工具 v1.0.0
'''
        else:
            # 使用默认模板
            md = f'''
# HOS-LS 安全检测报告

## 检测摘要

| 检测目标 | 检测时间 | 高风险 | 中风险 | 低风险 |
|---------|---------|-------|-------|-------|
| {self.target} | {self.timestamp} | {high_risk} | {medium_risk} | {low_risk} |
'''
            
            # 添加详细内容
            categories = [
                ('代码安全', 'code_security'),
                ('权限安全', 'permission_security'),
                ('网络安全', 'network_security'),
                ('依赖安全', 'dependency_security'),
                ('配置安全', 'config_security')
            ]
            
            for category_name, category_key in categories:
                items = self.results.get(category_key, [])
                if items:
                    md += f'''
## {category_name}

| 文件 | 问题 | 严重程度 | 详情 |
|------|------|---------|------|
'''
                    for item in items:
                        md += f'| {item["file"]} | {item["issue"]} | {item["severity"]} | {item["details"]} |\n'
            
            md += f'''
---

报告生成时间: {self.timestamp}
HOS-LS 安全检测工具 v1.0.0
'''
        
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)
        
        return output_path
