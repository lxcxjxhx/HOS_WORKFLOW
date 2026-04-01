# AI工具安全检测报告

## 检测摘要

| 检测目标 | 检测时间 | 高风险 | 中风险 | 低风险 |
|---------|---------|-------|-------|-------|
| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main | 2026-04-01 22:24:39 | 5 | 11 | 45 |


## 代码安全

| 文件 | 行号 | 问题 | 严重程度 | 详情 |
|------|------|------|---------|------|

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\cli\src\plugin\prompts.ts | 13 | AI 输入验证 | medium | 检测 AI 输入处理代码，可能缺少输入验证 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\cli\src\plugin\prompts.ts | 77 | AI 输入验证 | medium | 检测 AI 输入处理代码，可能缺少输入验证 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\test\ast\visitors.test.ts | 84 | 后门代码 | high | 检测潜在的后门代码（危险函数使用） |








## 依赖安全

| 文件 | 行号 | 问题 | 严重程度 | 详情 |
|------|------|------|---------|------|

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\package.json | 16 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\package.json | 17 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\package.json | 19 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\package.json | 20 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\package.json | 21 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\docs\package.json | 11 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\examples\package.json | 8 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\examples\package.json | 9 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\examples\package.json | 10 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\cli\package.json | 35 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\cli\package.json | 36 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\cli\package.json | 37 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\cli\package.json | 38 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\cli\package.json | 41 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 30 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 31 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 32 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 33 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 34 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 35 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 36 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 37 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 38 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 39 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 40 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 41 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 42 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 43 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 44 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 45 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 46 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 47 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 48 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 49 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 50 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 51 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 52 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 53 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 54 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\core\package.json | 57 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\create-agentflow\package.json | 31 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\create-agentflow\package.json | 32 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\create-agentflow\package.json | 33 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\create-agentflow\package.json | 36 | 依赖版本未固定 | low | 检测依赖库版本未固定 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\packages\create-agentflow\package.json | 37 | 依赖版本未固定 | low | 检测依赖库版本未固定 |




## 配置安全

| 文件 | 行号 | 问题 | 严重程度 | 详情 |
|------|------|------|---------|------|

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\docs\guide\configuration.md | 77 | AI 配置 | medium | 检测 AI 特定配置 |

| c:\1AAA_PROJECT\HOS\HOS-LS\real-project\agentflow-main\docs\guide\configuration.md | 78 | AI 配置 | medium | 检测 AI 特定配置 |



---

报告生成时间: 2026-04-01 22:24:39
AI工具安全检测工具 v1.0.0