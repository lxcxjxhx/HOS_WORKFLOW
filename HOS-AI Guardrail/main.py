from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
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

# 挂载静态文件
app.mount("/static", StaticFiles(directory="static"), name="static")

# 根路径重定向到静态文件
@app.get("/")
async def root():
    return FileResponse("static/index.html")

# 启动事件
@app.on_event("startup")
async def startup_event():
    logger.info("HOS-AI 围栏工作流插件已启动")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
