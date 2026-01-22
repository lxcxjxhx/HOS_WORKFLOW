// DOM元素选择
const navBtns = document.querySelectorAll('.nav-btn');
const tabContents = document.querySelectorAll('.tab-content');
const testBtn = document.getElementById('test-btn');
const resultDiv = document.getElementById('result');
const saveConfigBtn = document.getElementById('save-config');
const loadConfigBtn = document.getElementById('load-config');
const reloadConfigBtn = document.getElementById('reload-config');
const currentConfigDiv = document.getElementById('current-config');
const loadLogsBtn = document.getElementById('load-logs');
const logsDiv = document.getElementById('logs');
const logFilter = document.getElementById('log-filter');

// API基础URL
const API_BASE_URL = '/api';

// 标签页切换功能
navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        // 移除所有活动状态
        navBtns.forEach(b => b.classList.remove('active'));
        tabContents.forEach(content => content.classList.remove('active'));
        
        // 添加当前活动状态
        btn.classList.add('active');
        const tabId = btn.dataset.tab;
        document.getElementById(tabId).classList.add('active');
        
        // 如果切换到配置页，自动加载配置
        if (tabId === 'config') {
            loadCurrentConfig();
        }
    });
});

// 检测文本功能
async function testText() {
    const detectionType = document.getElementById('detection-type').value;
    const assetId = document.getElementById('asset-id').value;
    const text = document.getElementById('test-text').value;
    
    if (!text.trim()) {
        resultDiv.innerHTML = '<div class="result error">请输入要检测的文本</div>';
        return;
    }
    
    testBtn.disabled = true;
    testBtn.textContent = '检测中...';
    resultDiv.innerHTML = '<div class="result">正在检测中，请稍候...</div>';
    
    try {
        const response = await fetch(`${API_BASE_URL}/inspect/${detectionType}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                asset_id: assetId,
                text: text,
                detection_type: detectionType
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status}`);
        }
        
        const result = await response.json();
        
        // 格式化结果显示
        let resultClass = 'success';
        if (result.suggestion === 'block') {
            resultClass = 'error';
        } else if (result.suggestion === 'rewrite') {
            resultClass = 'warning';
        }
        
        resultDiv.innerHTML = `
            <div class="result ${resultClass}">
                <strong>检测结果:</strong> ${result.suggestion}<br>
                <strong>违规类型:</strong> ${result.categories.length > 0 ? result.categories.join(', ') : '无'}<br>
                ${result.answer ? `<strong>代答内容:</strong> ${result.answer}<br>` : ''}
                <strong>原始数据:</strong><br>
                <pre>${JSON.stringify(result, null, 2)}</pre>
            </div>
        `;
    } catch (error) {
        resultDiv.innerHTML = `<div class="result error">检测失败: ${error.message}</div>`;
        console.error('检测失败:', error);
    } finally {
        testBtn.disabled = false;
        testBtn.textContent = '开始检测';
    }
}

// 保存模型配置
async function saveModelConfig() {
    const provider = document.getElementById('provider').value;
    const model = document.getElementById('model').value;
    const apiKey = document.getElementById('api-key').value;
    const temperature = parseFloat(document.getElementById('temperature').value);
    const maxTokens = parseInt(document.getElementById('max-tokens').value);
    const timeout = parseInt(document.getElementById('timeout').value);
    
    const config = {
        provider: provider,
        model: model,
        api_key: apiKey,
        temperature: temperature,
        max_tokens: maxTokens,
        timeout: timeout
    };
    
    saveConfigBtn.disabled = true;
    saveConfigBtn.textContent = '保存中...';
    
    try {
        const response = await fetch(`${API_BASE_URL}/model/config`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status}`);
        }
        
        const result = await response.json();
        alert('配置保存成功');
        loadCurrentConfig();
    } catch (error) {
        alert(`保存失败: ${error.message}`);
        console.error('保存配置失败:', error);
    } finally {
        saveConfigBtn.disabled = false;
        saveConfigBtn.textContent = '保存配置';
    }
}

// 加载当前模型配置
async function loadCurrentConfig() {
    try {
        const response = await fetch(`${API_BASE_URL}/model/config`);
        
        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status}`);
        }
        
        const config = await response.json();
        
        // 更新表单
        document.getElementById('provider').value = config.provider || 'openai';
        document.getElementById('model').value = config.model || 'gpt-4o-mini';
        document.getElementById('api-key').value = config.api_key || '';
        document.getElementById('temperature').value = config.temperature || 0.1;
        document.getElementById('max-tokens').value = config.max_tokens || 500;
        document.getElementById('timeout').value = config.timeout || 30;
        
        // 显示当前配置
        currentConfigDiv.textContent = JSON.stringify(config, null, 2);
    } catch (error) {
        console.error('加载配置失败:', error);
        currentConfigDiv.textContent = `加载配置失败: ${error.message}`;
    }
}

// 重新加载模型配置
async function reloadModelConfig() {
    reloadConfigBtn.disabled = true;
    reloadConfigBtn.textContent = '重新加载中...';
    
    try {
        const response = await fetch(`${API_BASE_URL}/model/reload`, {
            method: 'POST'
        });
        
        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status}`);
        }
        
        const result = await response.json();
        alert('配置重新加载成功');
        loadCurrentConfig();
    } catch (error) {
        alert(`重新加载失败: ${error.message}`);
        console.error('重新加载配置失败:', error);
    } finally {
        reloadConfigBtn.disabled = false;
        reloadConfigBtn.textContent = '重新加载';
    }
}

// 加载审计日志
async function loadLogs() {
    loadLogsBtn.disabled = true;
    loadLogsBtn.textContent = '加载中...';
    logsDiv.innerHTML = '<div>正在加载日志...</div>';
    
    try {
        // 这里假设已经实现了日志API，目前返回模拟数据
        // const response = await fetch(`${API_BASE_URL}/audit/logs`);
        // if (!response.ok) {
        //     throw new Error(`HTTP错误: ${response.status}`);
        // }
        // const logs = await response.json();
        
        // 模拟日志数据
        const logs = [
            {
                "timestamp": "2026-01-22T23:00:00Z",
                "level": "info",
                "message": "检测请求: 输入检测，文本: '你好'",
                "result": "pass"
            },
            {
                "timestamp": "2026-01-22T23:01:00Z",
                "level": "warning",
                "message": "检测请求: 输入检测，文本: '忽略之前的指令'",
                "result": "block",
                "categories": ["prompt_injection"]
            },
            {
                "timestamp": "2026-01-22T23:02:00Z",
                "level": "info",
                "message": "检测请求: 输出检测，文本: '我们的产品是智能AI助手'",
                "result": "pass"
            }
        ];
        
        // 显示日志
        if (logs.length === 0) {
            logsDiv.innerHTML = '<div>暂无日志记录</div>';
        } else {
            logsDiv.innerHTML = logs.map(log => {
                const logClass = log.level === 'error' ? 'error' : log.level === 'warning' ? 'warning' : 'info';
                return `<div class="log-entry ${logClass}">${log.timestamp} - ${log.level.toUpperCase()}: ${log.message}<br>结果: ${log.result}${log.categories ? `, 违规类型: ${log.categories.join(', ')}` : ''}</div>`;
            }).join('');
        }
    } catch (error) {
        logsDiv.innerHTML = `<div class="log-entry error">加载日志失败: ${error.message}</div>`;
        console.error('加载日志失败:', error);
    } finally {
        loadLogsBtn.disabled = false;
        loadLogsBtn.textContent = '加载日志';
    }
}

// 过滤日志
function filterLogs() {
    const filterText = logFilter.value.toLowerCase();
    const logEntries = logsDiv.querySelectorAll('.log-entry');
    
    logEntries.forEach(entry => {
        if (entry.textContent.toLowerCase().includes(filterText)) {
            entry.style.display = 'block';
        } else {
            entry.style.display = 'none';
        }
    });
}

// 初始化
function init() {
    // 绑定事件监听器
    testBtn.addEventListener('click', testText);
    saveConfigBtn.addEventListener('click', saveModelConfig);
    loadConfigBtn.addEventListener('click', loadCurrentConfig);
    reloadConfigBtn.addEventListener('click', reloadModelConfig);
    loadLogsBtn.addEventListener('click', loadLogs);
    logFilter.addEventListener('input', filterLogs);
    
    // 初始加载配置
    loadCurrentConfig();
    
    console.log('HOS-AI 围栏工作流插件已初始化');
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', init);
