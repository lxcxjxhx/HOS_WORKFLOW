#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from ai_suggestion_generator import AISuggestionGenerator

print("开始测试 AI 生成器...")
generator = AISuggestionGenerator()

print("生成 Cursor 提示词...")
cursor_prompt = generator.generate_security_prompts('cursor')
print(f"✓ Cursor 提示词生成成功，长度：{len(cursor_prompt)} 字符")
print(f"前 200 字符:\n{cursor_prompt[:200]}...")

print("\n生成 Trae 提示词...")
trae_prompt = generator.generate_security_prompts('trae')
print(f"✓ Trae 提示词生成成功，长度：{len(trae_prompt)} 字符")

print("\n生成 Kiro 提示词...")
kiro_prompt = generator.generate_security_prompts('kiro')
print(f"✓ Kiro 提示词生成成功，长度：{len(kiro_prompt)} 字符")

print("\n所有提示词生成完成！")
