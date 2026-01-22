from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from src.core.input_inspector import InputInspector
from src.core.output_inspector import OutputInspector
from src.core.decision_hub import DecisionHub
from src.core.model_engine import ModelEngine

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

# 模型配置请求模型
class ModelConfigRequest(BaseModel):
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    api_key: str = ""
    temperature: float = 0.1
    max_tokens: int = 500
    timeout: int = 30

# 输入检测接口
@router.post("/inspect/input", response_model=DecisionResult)
async def inspect_input(request: InputInspectRequest):
    try:
        inspector = InputInspector(asset_id=request.asset_id)
        result = await inspector.inspect(request.text)
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
        result = await inspector.inspect(request.text)
        return DecisionResult(
            suggestion=result["suggestion"],
            categories=result["categories"],
            answer=result.get("answer", "")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 获取当前模型配置
@router.get("/model/config")
async def get_model_config():
    try:
        model_engine = ModelEngine()
        return model_engine.get_current_model()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 设置模型配置
@router.post("/model/config")
async def set_model_config(config: ModelConfigRequest):
    try:
        model_engine = ModelEngine()
        model_engine.set_current_model(config.model_dump())
        return {"message": "模型配置已更新", "config": config.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 重新加载模型配置
@router.post("/model/reload")
async def reload_model_config():
    try:
        model_engine = ModelEngine()
        model_engine.reload_config()
        return {"message": "模型配置已重新加载"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
