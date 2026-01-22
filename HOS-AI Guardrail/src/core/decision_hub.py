from loguru import logger

class DecisionHub:
    def pass_decision(self) -> dict:
        """生成通过裁决"""
        return {
            "suggestion": "pass",
            "categories": [],
            "answer": ""
        }
    
    def generate_decision(self, violations: list, actions: dict) -> dict:
        """根据违规情况生成裁决结果"""
        # 确定最终动作（优先级：block > rewrite > pass）
        final_action = "pass"
        final_answer = ""
        
        # 遍历所有违规动作，确定优先级最高的动作
        for violation, action_config in actions.items():
            action = action_config.get("action", "pass")
            answer = action_config.get("answer", "")
            
            # 动作优先级：block > rewrite > pass
            if action == "block":
                final_action = "block"
                final_answer = answer
                break  # block优先级最高，直接返回
            elif action == "rewrite" and final_action != "block":
                final_action = "rewrite"
                final_answer = answer
            elif action == "pass" and final_action not in ["block", "rewrite"]:
                final_action = "pass"
        
        logger.info(f"生成裁决结果: 建议={final_action}, 违规类型={violations}, 代答内容={final_answer}")
        
        return {
            "suggestion": final_action,
            "categories": violations,
            "answer": final_answer
        }
    
    def error_decision(self, error_msg: str) -> dict:
        """生成错误裁决"""
        return {
            "suggestion": "error",
            "categories": ["system_error"],
            "answer": f"系统错误: {error_msg}"
        }
