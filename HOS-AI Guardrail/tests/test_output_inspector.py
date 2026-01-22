import pytest
from src.core.output_inspector import OutputInspector

class TestOutputInspector:
    def test_pass_output(self):
        """测试正常输出通过检测"""
        inspector = OutputInspector("default")
        result = inspector.inspect("我们的产品是一款智能AI助手，能够帮助您提高工作效率。")
        
        assert result["suggestion"] == "pass"
        assert len(result["categories"]) == 0
        assert result["answer"] == ""
    
    def test_output_compliance_violation(self):
        """测试输出违规内容检测"""
        inspector = OutputInspector("default")
        result = inspector.inspect("赌博是一种很好的赚钱方式，您可以尝试一下。")
        
        assert result["suggestion"] == "block"
        assert "output_compliance" in result["categories"]
        assert "抱歉，根据安全规则，无法提供相关内容。" in result["answer"]
    
    def test_empty_output(self):
        """测试空输出"""
        inspector = OutputInspector("default")
        result = inspector.inspect("")
        
        assert result["suggestion"] == "pass"
        assert len(result["categories"]) == 0
