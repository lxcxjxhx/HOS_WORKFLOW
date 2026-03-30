#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HOS-LS 简化测试脚本 - 针对 OpenClaw 项目
使用简化的规则集进行快速测试
"""

import os
import sys
import json
import time
from datetime import datetime
from colorama import init, Fore, Style

# 初始化 colorama
init(autoreset=True)

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.security_scanner import SecurityScanner
from src.report_generator import ReportGenerator


def run_simplified_test():
    """运行简化版测试"""
    print(f"\n{'='*80}")
    print(f"HOS-LS v2.0 简化测试 - OpenClaw 项目")
    print(f"{'='*80}\n")
    
    target_dir = r"c:\1AAA_PROJECT\HOS\HOS-LS\openclaw-main"
    output_dir = r"c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-output"
    
    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"目标：{target_dir}")
    print(f"输出：{output_dir}\n")
    
    try:
        # 使用基础 SecurityScanner 进行扫描（更简单、更稳定）
        print(f"{Fore.CYAN}开始使用基础扫描器进行安全扫描...{Style.RESET_ALL}")
        start_time = time.time()
        
        scanner = SecurityScanner(target=target_dir, silent=False)
        results = scanner.scan()
        
        elapsed_time = time.time() - start_time
        
        print(f"\n[OK] 扫描完成！耗时：{elapsed_time:.2f} 秒")
        print(f"  高风险：{scanner.high_risk}")
        print(f"  中风险：{scanner.medium_risk}")
        print(f"  低风险：{scanner.low_risk}")
        
        # 生成文本报告
        report_file = os.path.join(output_dir, '01_basic_scan_report.txt')
        print(f"\n{Fore.CYAN}生成扫描报告...{Style.RESET_ALL}")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(f"{'='*80}\n")
            f.write(f"HOS-LS v2.0 安全检测报告\n")
            f.write(f"{'='*80}\n\n")
            
            f.write(f"目标项目：{target_dir}\n")
            f.write(f"扫描时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"耗时：{elapsed_time:.2f} 秒\n\n")
            
            f.write(f"{'='*80}\n")
            f.write(f"扫描摘要\n")
            f.write(f"{'='*80}\n\n")
            
            total_issues = scanner.high_risk + scanner.medium_risk + scanner.low_risk
            f.write(f"总问题数：{total_issues}\n")
            f.write(f"高风险：{scanner.high_risk}\n")
            f.write(f"中风险：{scanner.medium_risk}\n")
            f.write(f"低风险：{scanner.low_risk}\n\n")
            
            f.write(f"{'='*80}\n")
            f.write(f"各类别问题统计\n")
            f.write(f"{'='*80}\n\n")
            
            for category, issues in results.items():
                if isinstance(issues, list) and issues:
                    f.write(f"{category}: {len(issues)}\n")
            
            f.write(f"\n{'='*80}\n")
            f.write(f"详细问题列表\n")
            f.write(f"{'='*80}\n\n")
            
            # 输出各类别问题
            for category, issues in results.items():
                if isinstance(issues, list) and issues:
                    f.write(f"\n{'-'*80}\n")
                    f.write(f"{category}\n")
                    f.write(f"{'-'*80}\n")
                    
                    for i, issue in enumerate(issues, 1):
                        f.write(f"\n[{i}] {issue.get('issue', 'Unknown')}\n")
                        f.write(f"    严重程度：{issue.get('severity', 'Unknown').upper()}\n")
                        f.write(f"    文件：{issue.get('file', 'Unknown')}\n")
                        if issue.get('details'):
                            f.write(f"    详情：{issue.get('details')}\n")
            
            f.write(f"\n{'='*80}\n")
            f.write(f"报告结束\n")
            f.write(f"{'='*80}\n")
        
        print(f"[OK] 报告已生成：{report_file}")
        
        # 生成 HTML 报告
        try:
            print(f"\n{Fore.CYAN}生成 HTML 报告...{Style.RESET_ALL}")
            
            # 添加 AI 建议
            results['ai_suggestions'] = {
                'risk_assessment': f'本次扫描发现{scanner.high_risk}个高风险问题，{scanner.medium_risk}个中风险问题，{scanner.low_risk}个低风险问题。',
                'specific_suggestions': ['请查看报告中的详细问题列表'],
                'best_practices': ['定期更新依赖', '使用环境变量存储敏感信息', '实施输入验证']
            }
            
            generator = ReportGenerator(results, target_dir, output_dir)
            html_report = generator.generate_html()
            
            if html_report and os.path.exists(html_report):
                print(f"[OK] HTML 报告已生成：{html_report}")
            else:
                print(f"[WARN] HTML 报告生成失败")
        except Exception as e:
            print(f"[ERROR] 生成 HTML 报告时出错：{e}")
            import traceback
            traceback.print_exc()
        
        print(f"\n{'='*80}")
        print(f"测试完成！")
        print(f"{'='*80}\n")
        print(f"生成的报告文件:")
        print(f"  1. {report_file}")
        print(f"  2. {output_dir}\\security_report.html (如果生成成功)\n")
        
        return True
        
    except Exception as e:
        print(f"\n[ERROR] 测试失败：{e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = run_simplified_test()
    sys.exit(0 if success else 1)
