#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HOS-LS 安全检测工具
"""

import os
import sys
import argparse
import logging
import json
from colorama import init, Fore, Style

# 初始化colorama
init(autoreset=True)

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='HOS-LS 安全检测工具',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '-o', '--output',
        choices=['html', 'docx', 'md'],
        default='html',
        help='报告输出格式 (默认: html)'
    )
    
    parser.add_argument(
        '-d', '--output-dir',
        default='reports',
        help='报告输出目录 (默认: reports)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='显示详细输出'
    )
    
    parser.add_argument(
        '-s', '--silent',
        action='store_true',
        help='静默模式，不输出控制台信息'
    )
    
    parser.add_argument(
        '--version',
        action='store_true',
        help='显示版本信息'
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='要检测的AI工具目录或文件路径'
    )
    
    parser.add_argument(
        '--scan-result',
        help='扫描结果文件路径'
    )
    
    parser.add_argument(
        '--parallel',
        action='store_true',
        default=True,
        help='启用并行扫描 (默认开启)'
    )
    
    parser.add_argument(
        '--no-parallel',
        action='store_false',
        dest='parallel',
        help='禁用并行扫描'
    )
    
    parser.add_argument(
        '--workers',
        type=int,
        default=4,
        help='并行扫描工作进程数 (默认：4)'
    )
    
    args = parser.parse_args()
    
    if args.version:
        if not args.silent:
            print('HOS-LS 安全检测工具 v1.0.0')
        return
    
    if not args.target:
        if not args.silent:
            parser.print_help()
        return
    
    # 检查目标路径是否存在
    if not os.path.exists(args.target):
        if not args.silent:
            print(f'{Fore.RED}错误: 目标路径不存在: {args.target}{Style.RESET_ALL}')
        sys.exit(1)
    
    # 确保输出目录存在
    os.makedirs(args.output_dir, exist_ok=True)
    
    if not args.silent:
        print(f'{Fore.BLUE}开始检测：{args.target}{Style.RESET_ALL}')
        print(f'{Fore.BLUE}输出格式：{args.output}{Style.RESET_ALL}')
        print(f'{Fore.BLUE}输出目录：{args.output_dir}{Style.RESET_ALL}')
        print(f'{Fore.BLUE}扫描模式：{"并行" if args.parallel else "串行"}{Style.RESET_ALL}')
        if args.parallel:
            print(f'{Fore.BLUE}工作进程数：{args.workers}{Style.RESET_ALL}')
    
    # 导入安全扫描模块
    from enhanced_scanner import EnhancedSecurityScanner
    from report_generator import ReportGenerator
    
    # 从文件读取扫描结果或执行安全扫描
    if args.scan_result and os.path.exists(args.scan_result):
        with open(args.scan_result, 'r', encoding='utf-8') as f:
            results = json.load(f)
        if not args.silent:
            print(f'{Fore.GREEN}从文件读取扫描结果：{args.scan_result}{Style.RESET_ALL}')
    else:
        # 执行安全扫描 (使用增强扫描器，支持并行)
        scanner = EnhancedSecurityScanner(
            args.target, 
            silent=args.silent,
            use_parallel=args.parallel,
            max_workers=args.workers
        )
        results = scanner.scan()

    # 生成AI辅助安全建议
    ai_suggestions = {}
    try:
        from ai_suggestion_generator import AISuggestionGenerator
        
        ai_generator = AISuggestionGenerator()
        if not args.silent:
            print(f'\n{Fore.BLUE}生成AI辅助安全建议...{Style.RESET_ALL}')
        
        # 为每个工具生成安全提示词（调用 AI 生成，不使用固定模板）
        if not args.silent:
            print(f'{Fore.BLUE}正在为各工具生成安全提示词（AI 生成）...{Style.RESET_ALL}')
        
        prompts = {}
        for tool_name in ['cursor', 'trae', 'kiro']:
            if not args.silent:
                print(f'{Fore.CYAN}  生成 {tool_name} 提示词...{Style.RESET_ALL}')
            try:
                # 调用 AI 生成安全提示词
                prompt = ai_generator.generate_security_prompts(tool_name)
                prompts[tool_name] = prompt
                if not args.silent:
                    print(f'{Fore.GREEN}  [OK] {tool_name} 提示词已生成（{len(prompt)} 字符）{Style.RESET_ALL}')
            except Exception as e:
                if not args.silent:
                    print(f'{Fore.RED}  [ERROR] 生成{tool_name}提示词时出错：{e}{Style.RESET_ALL}')
                import traceback
                traceback.print_exc()
                prompts[tool_name] = f"# {tool_name} 安全提示词（生成失败）"
        
        if not args.silent:
            print(f'{Fore.GREEN}[OK] 所有工具提示词生成完成{Style.RESET_ALL}')
            print(f'{Fore.GREEN}  - prompts 字典键：{list(prompts.keys())}{Style.RESET_ALL}')
        
        # 保存提示词到文件
        prompts_dir = os.path.join(args.output_dir, 'prompts')
        os.makedirs(prompts_dir, exist_ok=True)
        
        # 将 AI 生成的提示词保存到文件
        for tool_name, prompt in prompts.items():
            try:
                prompt_file = os.path.join(prompts_dir, f'{tool_name}_security_prompt.txt')
                with open(prompt_file, 'w', encoding='utf-8') as f:
                    f.write(prompt)
                if not args.silent:
                    print(f'{Fore.GREEN}  [OK] 已保存：{prompt_file}{Style.RESET_ALL}')
            except Exception as e:
                if not args.silent:
                    print(f'{Fore.RED}  [ERROR] 保存{tool_name}提示词时出错：{e}{Style.RESET_ALL}')
        
        # 分析扫描结果获取实际的风险数量
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        for category in results.values():
            if isinstance(category, list):
                for item in category:
                    if item.get('severity') == 'high':
                        high_risk += 1
                    elif item.get('severity') == 'medium':
                        medium_risk += 1
                    elif item.get('severity') == 'low':
                        low_risk += 1
        
        # 生成风险评估
        if high_risk > 0:
            risk_assessment = f"本次扫描发现{high_risk}个高风险问题，{medium_risk}个中风险问题，{low_risk}个低风险问题。系统存在严重安全隐患，建议立即处理高风险问题。"
        elif medium_risk > 0:
            risk_assessment = f"本次扫描发现{high_risk}个高风险问题，{medium_risk}个中风险问题，{low_risk}个低风险问题。系统存在一定安全风险，建议尽快处理中风险问题。"
        else:
            risk_assessment = f"本次扫描发现{high_risk}个高风险问题，{medium_risk}个中风险问题，{low_risk}个低风险问题。系统安全状态良好，建议定期进行安全检查。"
        
        # 构建 AI 建议数据（完全使用 AI 生成的内容）
        ai_suggestions = {
            'risk_assessment': risk_assessment,
            'specific_suggestions': ["请查看各工具的安全提示词文件获取详细建议"],
            'best_practices': ["请参考生成的安全提示词文件"],
            'tool_prompts': "\n\n".join([f"# {tool_name} 安全提示词\n{prompt}" for tool_name, prompt in prompts.items()]),
            'cursor_prompt': prompts.get('cursor', '# Cursor 安全提示词（AI 生成失败）'),
            'trae_prompt': prompts.get('trae', '# Trae 安全提示词（AI 生成失败）'),
            'kiro_prompt': prompts.get('kiro', '# Kiro 安全提示词（AI 生成失败）')
        }
        
        # 将 AI 建议添加到扫描结果中
        results['ai_suggestions'] = ai_suggestions
        if not args.silent:
            print(f'{Fore.GREEN}  [OK] AI 建议已生成并添加到结果中{Style.RESET_ALL}')
            print(f'{Fore.GREEN}    - Cursor 提示词长度：{len(ai_suggestions.get("cursor_prompt", ""))} 字符{Style.RESET_ALL}')
            print(f'{Fore.GREEN}    - Trae 提示词长度：{len(ai_suggestions.get("trae_prompt", ""))} 字符{Style.RESET_ALL}')
            print(f'{Fore.GREEN}    - Kiro 提示词长度：{len(ai_suggestions.get("kiro_prompt", ""))} 字符{Style.RESET_ALL}')
    except Exception as e:
        if not args.silent:
            print(f'{Fore.YELLOW}生成 AI 建议时出错：{e}{Style.RESET_ALL}')
        import traceback
        traceback.print_exc()

    # 生成报告
    try:
        if not args.silent:
            print(f'\n{Fore.BLUE}开始生成报告...{Style.RESET_ALL}')
            print(f'{Fore.BLUE}  - 输出目录：{args.output_dir}{Style.RESET_ALL}')
            print(f'{Fore.BLUE}  - 输出格式：{args.output}{Style.RESET_ALL}')
            print(f'{Fore.BLUE}  - AI 建议是否存在：{"ai_suggestions" in results}{Style.RESET_ALL}')
            print(f'{Fore.BLUE}  - results 字典的键：{list(results.keys())}{Style.RESET_ALL}')
            if 'ai_suggestions' in results:
                print(f'{Fore.BLUE}  - ai_suggestions 的键：{list(results["ai_suggestions"].keys())}{Style.RESET_ALL}')
        
        # 检查输出目录是否存在
        if not os.path.exists(args.output_dir):
            if not args.silent:
                print(f'{Fore.YELLOW}输出目录不存在，创建目录：{args.output_dir}{Style.RESET_ALL}')
            os.makedirs(args.output_dir, exist_ok=True)
        
        # 检查扫描结果
        if not args.silent:
            print(f'{Fore.CYAN}创建 ReportGenerator 实例...{Style.RESET_ALL}')
        generator = ReportGenerator(results, args.target, args.output_dir)
        
        if not args.silent:
            print(f'{Fore.CYAN}调用 generate_html() 方法...{Style.RESET_ALL}')
        report_path = generator.generate_html()
        
        if not args.silent:
            print(f'{Fore.GREEN}[OK] HTML 报告已生成：{report_path}{Style.RESET_ALL}')
            if report_path and os.path.exists(report_path):
                file_size = os.path.getsize(report_path)
                print(f'{Fore.GREEN}  - 文件大小：{file_size} 字节{Style.RESET_ALL}')
            else:
                print(f'{Fore.YELLOW}  [WARN] 报告文件不存在或路径为空{Style.RESET_ALL}')
    except Exception as e:
        if not args.silent:
            print(f'{Fore.RED}生成报告时出错：{e}{Style.RESET_ALL}')
        import traceback
        traceback.print_exc()
        if not results:
            if not args.silent:
                print(f'{Fore.YELLOW}扫描结果为空，无法生成报告{Style.RESET_ALL}')
            return
        
        # 检查AI建议
        if 'ai_suggestions' not in results:
            if not args.silent:
                print(f'{Fore.YELLOW}AI建议不存在，添加默认建议{Style.RESET_ALL}')
            results['ai_suggestions'] = {
                'risk_assessment': '正在生成风险评估...',
                'specific_suggestions': ['正在生成针对性建议...'],
                'best_practices': ['正在生成安全最佳实践...'],
                'tool_prompts': '',
                'cursor_prompt': '# Cursor 安全提示词\n正在生成...',
                'trae_prompt': '# Trae 安全提示词\n正在生成...',
                'kiro_prompt': '# Kiro 安全提示词\n正在生成...'
            }
        
        generator = ReportGenerator(results, args.target, args.output_dir)
        
        if args.output == 'html':
            if not args.silent:
                print(f'{Fore.BLUE}生成HTML报告...{Style.RESET_ALL}')
            report_path = generator.generate_html()
        elif args.output == 'docx':
            if not args.silent:
                print(f'{Fore.BLUE}生成DOCX报告...{Style.RESET_ALL}')
            report_path = generator.generate_docx()
        elif args.output == 'md':
            if not args.silent:
                print(f'{Fore.BLUE}生成MD报告...{Style.RESET_ALL}')
            report_path = generator.generate_md()
        
        if not args.silent:
            print(f'{Fore.GREEN}检测完成!{Style.RESET_ALL}')
            print(f'{Fore.GREEN}报告已生成：{report_path}{Style.RESET_ALL}')
            
            # 检查报告文件是否存在
            if os.path.exists(report_path):
                print(f'{Fore.GREEN}报告文件存在，大小：{os.path.getsize(report_path)} 字节{Style.RESET_ALL}')
            else:
                print(f'{Fore.RED}报告文件不存在，生成失败{Style.RESET_ALL}')
    except Exception as e:
        if not args.silent:
            print(f'{Fore.RED}生成报告时出错: {e}{Style.RESET_ALL}')
            import traceback
            traceback.print_exc()
    
if __name__ == '__main__':
    main()
