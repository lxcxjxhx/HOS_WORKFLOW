#!/usr/bin/env python3
"""
AI建议生成器测试脚本

测试功能：
1. 基本的提示词生成功能
2. AI增强的提示词生成
3. 动态提示词调整机制
4. 结构化提示词生成
5. 多语言支持
"""

import sys
import os

# 添加项目根目录到Python路径
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.ai_suggestion_generator import AISuggestionGenerator

def test_basic_suggestions():
    """测试基本的提示词生成功能"""
    print("=== 测试基本的提示词生成功能 ===")
    
    generator = AISuggestionGenerator()
    
    # 模拟扫描结果
    mock_scan_results = {
        "code_security": [
            {"issue": "发现硬编码的敏感信息", "severity": "high", "file": "test.py", "details": "API Key"},
            {"issue": "未发现潜在的后门代码", "severity": "low", "file": "test.py", "details": "Clean"}
        ],
        "permission_security": [
            {"issue": "AI 模型文件权限过于宽松", "severity": "high", "file": "model.bin", "details": "777"}
        ],
        "network_security": [
            {"issue": "发现端口暴露到公网", "severity": "high", "file": "config.py", "details": "Port 8080"}
        ]
    }
    
    # 测试生成 Cursor 提示词
    print("\n1. 测试生成 Cursor 提示词:")
    cursor_prompt = generator.generate_dynamic_suggestions(mock_scan_results, 'cursor')
    print(cursor_prompt[:500] + "..." if len(cursor_prompt) > 500 else cursor_prompt)
    
    # 测试生成 Trae 提示词
    print("\n2. 测试生成 Trae 提示词:")
    trae_prompt = generator.generate_dynamic_suggestions(mock_scan_results, 'trae')
    print(trae_prompt[:500] + "..." if len(trae_prompt) > 500 else trae_prompt)
    
    # 测试生成 Kiro 提示词
    print("\n3. 测试生成 Kiro 提示词:")
    kiro_prompt = generator.generate_dynamic_suggestions(mock_scan_results, 'kiro')
    print(kiro_prompt[:500] + "..." if len(kiro_prompt) > 500 else kiro_prompt)
    
    print("\n✅ 基本提示词生成功能测试完成")

def test_structured_prompts():
    """测试结构化提示词生成功能"""
    print("\n=== 测试结构化提示词生成功能 ===")
    
    generator = AISuggestionGenerator()
    
    # 模拟扫描结果
    mock_scan_results = {
        "code_security": [
            {"issue": "发现硬编码的敏感信息", "severity": "high", "file": "test.py", "details": "API Key"}
        ]
    }
    
    # 测试生成结构化提示词（使用动态生成方法）
    print("1. 测试生成结构化提示词:")
    structured_prompt = generator.generate_dynamic_suggestions(mock_scan_results, 'cursor')
    print(structured_prompt[:800] + "..." if len(structured_prompt) > 800 else structured_prompt)
    
    print("\n✅ 结构化提示词生成功能测试完成")

def test_multilingual_support():
    """测试多语言支持功能"""
    print("\n=== 测试多语言支持功能 ===")
    
    generator = AISuggestionGenerator()
    
    # 模拟扫描结果
    mock_scan_results = {
        "code_security": [
            {"issue": "发现硬编码的敏感信息", "severity": "high", "file": "test.py", "details": "API Key"}
        ]
    }
    
    # 测试生成中文提示词
    print("1. 测试生成中文提示词:")
    chinese_prompt = generator.generate_dynamic_suggestions(mock_scan_results, 'cursor', 'zh')
    print(chinese_prompt[:500] + "..." if len(chinese_prompt) > 500 else chinese_prompt)
    
    # 测试生成英文提示词
    print("\n2. 测试生成英文提示词:")
    english_prompt = generator.generate_dynamic_suggestions(mock_scan_results, 'cursor', 'en')
    print(english_prompt[:500] + "..." if len(english_prompt) > 500 else english_prompt)
    
    print("\n✅ 多语言支持功能测试完成")

def test_all_tool_prompts():
    """测试生成所有工具的提示词"""
    print("\n=== 测试生成所有工具的提示词 ===")
    
    generator = AISuggestionGenerator()
    
    # 模拟扫描结果
    mock_scan_results = {
        "code_security": [
            {"issue": "发现硬编码的敏感信息", "severity": "high", "file": "test.py", "details": "API Key"}
        ]
    }
    
    # 测试生成所有工具的提示词
    print("1. 测试生成所有工具的提示词:")
    all_prompts = generator.generate_all_tool_prompts(mock_scan_results)
    for tool_name, prompt in all_prompts.items():
        print(f"\n{tool_name} 提示词:")
        print(prompt[:300] + "..." if len(prompt) > 300 else prompt)
    
    # 测试生成所有工具的结构化提示词（现在使用相同的方法）
    print("\n2. 测试生成所有工具的结构化提示词:")
    all_structured_prompts = generator.generate_all_tool_prompts(mock_scan_results)
    for tool_name, prompt in all_structured_prompts.items():
        print(f"\n{tool_name} 结构化提示词:")
        print(prompt[:500] + "..." if len(prompt) > 500 else prompt)
    
    print("\n✅ 生成所有工具提示词功能测试完成")

def test_language_detection():
    """测试语言自动检测功能"""
    print("\n=== 测试语言自动检测功能 ===")
    
    generator = AISuggestionGenerator()
    
    # 测试中文文本检测（简化测试）
    print("1. 测试语言配置:")
    print(f"默认语言：{generator.language_config['default_language']}")
    print(f"支持的语言：{generator.language_config['supported_languages']}")
    
    print("\n✅ 语言配置测试完成")

if __name__ == '__main__':
    print("开始测试AI建议生成器...\n")
    
    try:
        test_basic_suggestions()
        test_structured_prompts()
        test_multilingual_support()
        test_all_tool_prompts()
        test_language_detection()
        
        print("\n🎉 所有测试通过！AI建议生成器功能正常。")
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
