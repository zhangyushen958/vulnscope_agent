/* Independent model settings bootstrap. Remains usable if app.js fails. */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const indicator = byId('modelIndicator');
  const panel = byId('modelSettings');
  const trigger = byId('showModels');
  const info = byId('modelInfo');
  if (!indicator || !panel || !trigger || !info) {
    console.error('VulnScope: model settings elements are missing');
    return;
  }
  const mark = (message, kind = 'muted') => {
    indicator.className = `pill pill-${kind}`;
    indicator.textContent = message;
  };
  const inform = message => { info.textContent = message; };
  const fetchJSON = async (path, options = undefined) => {
    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 12000);
    try {
      const response = await fetch(path, { ...options, signal: ctrl.signal, cache: 'no-store' });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
      return payload;
    } catch (err) {
      if (err.name === 'AbortError') throw new Error(`请求 ${path} 超时（12 秒），请查看服务端日志`);
      throw err;
    } finally { clearTimeout(timeout); }
  };
  const loadModels = async () => {
    inform('正在读取模型设置…');
    try {
      const data = await fetchJSON('/api/models');
      if (!data.active) throw new Error('模型设置接口未返回 active 字段，请确认前后端均为同一版本');
      byId('modelSelect').value = data.active.model;
      byId('thinkingSelect').value = data.active.thinking;
      byId('stepsSelect').value = data.active.max_agent_steps;
      inform(data.configured ? '服务端已配置阿里云百炼 API Key；密钥不会显示在网页上。' : '尚未配置阿里云百炼 API Key，请编辑项目根目录 .env。');
    } catch (err) { inform(`读取模型配置失败：${err.message}`); }
  };
  const refreshIndicator = async () => {
    try {
      const h = await fetchJSON('/api/health');
      mark(h.model_configured ? `模型就绪 · ${h.model_name}` : '模型尚未配置', h.model_configured ? 'good' : 'bad');
    } catch (err) {
      mark('配置加载失败 · 点击查看', 'bad');
      inform(`读取服务状态失败：${err.message}`);
    }
  };
  const toggle = async () => {
    const opening = panel.classList.contains('hidden');
    panel.classList.toggle('hidden', !opening);
    trigger.setAttribute('aria-expanded', String(opening));
    if (opening) await loadModels();
  };
  trigger.setAttribute('aria-controls', 'modelSettings');
  trigger.setAttribute('aria-expanded', 'false');
  trigger.addEventListener('click', toggle);
  indicator.style.cursor = 'pointer';
  indicator.title = '点击打开模型设置';
  indicator.addEventListener('click', () => { if (panel.classList.contains('hidden')) toggle(); });
  byId('saveModels').addEventListener('click', async () => {
    const body = {
      model: byId('modelSelect').value,
      thinking: byId('thinkingSelect').value,
      max_agent_steps: Number(byId('stepsSelect').value),
    };
    inform('正在保存模型设置…');
    try {
      const data = await fetchJSON('/api/models/select', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
      });
      inform(`已保存 ${data.active.model}，新任务将使用该配置。`);
      await refreshIndicator();
    } catch (err) { inform(`保存失败：${err.message}`); }
  });
  byId('testModels').addEventListener('click', async () => {
    inform('正在验证模型工具调用（可能产生少量 API 费用）…');
    try {
      const data = await fetchJSON('/api/models/test', {method: 'POST'});
      inform(data.tool_call_supported ? `连接成功，Function Calling 可用（${(data.tool_names || []).join(', ')}）。` : `API 已连接，但未返回工具调用（finish_reason=${data.finish_reason || '未知'}）。${data.message || '请检查模型工具调用配置。'}`);
    } catch (err) { inform(`连接测试失败：${err.message}`); }
  });
  window.addEventListener('error', event => {
    if (event.target && event.target.tagName === 'SCRIPT') {
      mark('前端脚本加载失败', 'bad');
      inform('JavaScript 文件加载失败。请确认启动了新版服务，并按 Ctrl+Shift+R 强制刷新。');
    }
  }, true);
  refreshIndicator();
})();
