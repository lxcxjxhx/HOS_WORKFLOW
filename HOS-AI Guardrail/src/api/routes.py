from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from src.core.input_inspector import InputInspector
from src.core.output_inspector import OutputInspector
from src.core.decision_hub import DecisionHub

router = APIRouter()

# 输入检测请求模型
class InputInspectRequest(BaseModel):
    asset_id: str = "default"
    text: str
    detection_type: str = "input"

# 输出检测请求模型
class OutputInspectRequest(BaseModel):
    asset_id: str = "default"
    text: str
    detection_type: str = "output"

# 裁决结果模型
class DecisionResult(BaseModel):
    errCode: int = 200
    errMsg: str = ""
    suggestion: str
    categories: list[str]
    answer: str = ""

# 输入检测接口
@router.post("/inspect/input", response_model=DecisionResult)
async def inspect_input(request: InputInspectRequest):
    try:
        inspector = InputInspector(asset_id=request.asset_id)
        result = inspector.inspect(request.text)
        return DecisionResult(
            suggestion=result["suggestion"],
            categories=result["categories"],
            answer=result.get("answer", "")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 输出检测接口
@router.post("/inspect/output", response_model=DecisionResult)
async def inspect_output(request: OutputInspectRequest):
    try:
        inspector = OutputInspector(asset_id=request.asset_id)
        result = inspector.inspect(request.text)
        return DecisionResult(
            suggestion=result["suggestion"],
            categories=result["categories"],
            answer=result.get("answer", "")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
