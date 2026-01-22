from fastapi import FastAPI
from loguru import logger
import uvicorn

# 导入API路由
from src.api import routes

# 创建FastAPI应用
app = FastAPI(
    title="HOS-AI 围栏工作流插件",
    description="AI安全检测插件，支持文本、文件、图片的输入输出检测",
    version="0.1.0"
)

# 注册路由
app.include_router(routes.router, prefix="/api")

# 启动事件
@app.on_event("startup")
async def startup_event():
    logger.info("HOS-AI 围栏工作流插件已启动")

# 根路径
@app.get("/")
async def root():
    return {"message": "HOS-AI 围栏工作流插件 API", "version": "0.1.0"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
