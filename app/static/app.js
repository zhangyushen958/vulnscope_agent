/* VulnScope dashboard. No CDN/scripts/third-party assets; all dynamic text is escaped via textContent. */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const state = { jobId: null, stream: null, events: 0, reports: [], kind: 'single', toastTimer: null };
  const finalStatuses = new Set(['completed', 'partial', 'failed']);

  function toast(message) {
    $('toast').textContent = message;
    $('toast').classList.add('show');
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => $('toast').classList.remove('show'), 4000);
  }
  function setBusy(isBusy) {
    $('runSingle').disabled = isBusy;
    $('runBatch').disabled = isBusy;
    $('runKnowledge').disabled = isBusy;
  }
  function badge(el, text, kind='muted') {
    el.className = `pill pill-${kind}`;
    el.textContent = text;
  }
  function switchTab(name) {
    document.querySelectorAll('.nav-button').forEach(button => button.classList.toggle('active', button.dataset.tab === name));
    document.querySelectorAll('.workspace-tab').forEach(tab => tab.classList.toggle('hidden', tab.id !== `tab-${name}`));
  }
  async function request(url, options) {
    const response = await fetch(url, options);
    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = json.detail;
      throw new Error(typeof error === 'string' ? error : JSON.stringify(error || `HTTP ${response.status}`));
    }
    return json;
  }
  async function refreshHealth() {
    try {
      const h = await request('/api/health');
      $('caseCount').textContent = h.knowledge.case_count.toLocaleString('zh-CN');
      $('cweCount').textContent = h.knowledge.cwe_types.toLocaleString('zh-CN');
      $('runtimeText').textContent = h.langgraph_installed ? 'LangGraph' : 'Local graph';
      $('runtimeNote').textContent = h.langgraph_installed ? '条件路由 · 自主工具决策' : '离线兼容运行 · 部署请安装 LangGraph';
      $('localKnowledgeHint').textContent = h.dataset_files?.['knowledge.jsonl'] ? '✓ 已发现 dataset/knowledge.jsonl，可直接构建。' : '未找到 dataset/knowledge.jsonl，请将课程文件复制到项目 dataset/ 目录。';
      $('localTestHint').textContent = h.dataset_files?.['test.jsonl'] ? '✓ 已发现 dataset/test.jsonl，点击即可启动批量检测。' : '未找到 dataset/test.jsonl，请先放入项目 dataset/ 目录。';
      badge($('modelIndicator'), h.model_configured ? `模型就绪 · ${h.model_name}` : '模型尚未配置', h.model_configured ? 'good' : 'bad');
    } catch (e) { badge($('modelIndicator'), '服务连接异常', 'bad'); toast(e.message); }
  }
  function newNode(tag, css, text) {
    const node = document.createElement(tag);
    if (css) node.className = css;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function resetResults() {
    $('eventFeed').replaceChildren();
    $('reportArea').replaceChildren();
    $('reportArea').appendChild(emptyMessage('正在等待检测报告…', 'Agent 的结构化结论将在这里显示。'));
    $('reportActions').classList.add('hidden');
    state.events = 0;
    state.reports = [];
    $('eventCount').textContent = '0 EVENTS';
    badge($('jobStatus'), '正在分析…', 'muted');
  }
  function emptyMessage(title, body) {
    const box = newNode('div', 'empty-state');
    box.append(newNode('div', 'empty-icon', '▤'), newNode('strong', '', title), newNode('p', '', body));
    return box;
  }
  function traceSummary(event) {
    const d = event.data || {};
    const item = newNode('div', 'timeline-entry');
    const kind = event.kind === 'trace' ? d.kind : event.kind;
    item.dataset.kind = kind;
    item.append(newNode('span', 'event-mark', ({knowledge:'◇', reason:'↻', decision:'↗', repository:'⌘', warning:'!', verdict:'✓', sample_error:'!', sample_done:'✓', snapshot:'▦'}[kind] || '·')));
    const box = newNode('div', 'event-card');
    const title = d.title || d.message || ({sample_start:'开始分析样本',sample_done:'样本检测完成',sample_error:'样本检测失败',job_done:'全部任务结束',snapshot:'加载仓库快照'}[event.kind] || '任务状态更新');
    box.append(newNode('div', 'event-title', title));
    const time = new Date(event.created * 1000).toLocaleTimeString('zh-CN', {hour12:false});
    box.append(newNode('div', 'event-subline', `${time} · ${d.idx === undefined ? '' : `IDX ${d.idx} · `}${kind.toUpperCase()}`));
    const detail = d.detail || (event.kind === 'sample_done' ? {prediction:d.prediction, confidence:d.confidence} : null);
    if (detail && Object.keys(detail).length) {
      const details = document.createElement('details');
      const summary = newNode('summary', 'event-subline', '查看工具参数 / 证据记录');
      summary.style.cursor = 'pointer';
      const content = newNode('pre', 'event-detail', JSON.stringify(detail, null, 2));
      details.append(summary,content);
      box.append(details);
    }
    item.append(box);
    return item;
  }
  function renderEvent(event) {
    const feed = $('eventFeed');
    if (state.events === 0) feed.replaceChildren();
    feed.append(traceSummary(event));
    state.events += 1;
    $('eventCount').textContent = `${state.events} EVENTS`;
    feed.scrollTop = feed.scrollHeight;
    if (event.kind === 'sample_done') badge($('jobStatus'), '检测完成 · 汇总中', 'good');
    if (event.kind === 'sample_error') badge($('jobStatus'), '部分样本失败', 'bad');
  }
  async function watchJob(jobId, kind) {
    state.kind = kind;
    state.jobId = jobId;
    resetResults();
    setBusy(true);
    if (state.stream) state.stream.close();
    const stream = new EventSource(`/api/jobs/${jobId}/events`);
    state.stream = stream;
    stream.addEventListener('trace', (ev) => {
      try { renderEvent(JSON.parse(ev.data)); } catch (err) { console.error(err); }
    });
    stream.addEventListener('finished', async () => {
      stream.close();
      state.stream = null;
      await displayJob();
    });
    stream.onerror = async () => {
      stream.close();
      state.stream = null;
      try {
        const job = await request(`/api/jobs/${jobId}`);
        if (finalStatuses.has(job.status)) { await displayJob(); }
        else { badge($('jobStatus'), '实时连接中断，请刷新任务', 'bad'); setBusy(false); }
      } catch (e) { toast(e.message); setBusy(false); }
    };
    document.getElementById('resultsSection').scrollIntoView({behavior:'smooth',block:'start'});
  }
  async function displayJob() {
    try {
      const job = await request(`/api/jobs/${state.jobId}`);
      state.reports = job.rows;
      const success = job.success || 0;
      badge($('jobStatus'), `${success}/${job.total} 条完成 · ${job.failures} 条失败`, job.failures ? 'bad' : 'good');
      $('reportActions').classList.remove('hidden');
      $('downloadResult').disabled = job.status !== 'completed';
      renderReportPanel(job.rows);
      if (state.kind === 'batch') { await refreshScoreJobs(state.jobId); }
      if (job.failures) toast(`检测完成但有 ${job.failures} 条失败，请下载完整报告排查；禁止生成不完整的 result.jsonl`);
    } catch (e) { toast(e.message); }
    finally { setBusy(false); }
  }
  function renderReportPanel(rows) {
    const area = $('reportArea');
    area.replaceChildren();
    if (!rows.length) { area.append(emptyMessage('没有可展示的样本', '请查看实时分析记录。')); return; }
    let selected = rows[0];
    if (rows.length > 1) {
      const select = newNode('select', 'report-picker');
      rows.forEach((r,i) => { const opt = newNode('option', '', `${r.idx} · ${r.status === 'completed' ? '检测完成' : '检测失败'}`); opt.value = i; select.append(opt); });
      select.addEventListener('change', () => renderOne(rows[Number(select.value)], view));
      area.append(select);
    }
    const view = newNode('div','report-data');
    area.append(view);
    renderOne(selected, view);
  }
  function renderOne(row, area) {
    area.replaceChildren();
    if (row.status === 'failed' || !row.report) {
      const box = newNode('div', 'prediction-chip vulnerable');
      box.append(newNode('span','prediction-icon','!'), newNode('strong','',`样本 ${row.idx} 检测失败`));
      area.append(box,newNode('p','reason-text',row.error || '服务端未返回检测报告'));
      return;
    }
    const r = row.report;
    const chip = newNode('div', `prediction-chip ${r.prediction === 1 ? 'vulnerable' : ''}`);
    chip.append(newNode('span','prediction-icon',r.prediction === 1 ? '!' : '✓'));
    const wrap = newNode('div');
    wrap.append(newNode('strong','',r.prediction === 1 ? '存在潜在漏洞' : '未检测到漏洞'),newNode('small','',`模型置信度 ${(r.confidence*100).toFixed(0)}% · 非准确率承诺`));
    chip.append(wrap);
    const meta = newNode('div','result-meta');
    meta.append(newNode('span','',`IDX  ${r.idx}`),newNode('span','',`仓库状态 ${r.repository_status === 'available' ? '已读取单版本' : '不可用'}`));
    area.append(chip,meta,newNode('div','reason-title','判定理由 / REASONING'),newNode('p','reason-text',r.reason));
    if (r.evidence && r.evidence.length) {
      area.append(newNode('div','evidence-title','关键证据 / EVIDENCE'));
      const list = newNode('ul','evidence-list');
      r.evidence.forEach(e => list.append(newNode('li','',e)));
      area.append(list);
    }
    area.append(newNode('div','evidence-title',`${r.trace.length} 条可追溯分析事件（见左侧记录）`));
  }
  function setupFileDrop(zoneId,inputId) {
    const zone = $(zoneId);
    const input = $(inputId);
    ['dragenter','dragover'].forEach(n => zone.addEventListener(n,e => {e.preventDefault();zone.classList.add('dragover');}));
    ['dragleave','drop'].forEach(n => zone.addEventListener(n,e => {e.preventDefault();zone.classList.remove('dragover');}));
    zone.addEventListener('drop', e => { if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; input.dispatchEvent(new Event('change')); } });
    input.addEventListener('change', () => {
      const label = zone.querySelector('strong');
      label.textContent = input.files.length ? input.files[0].name : '选择 .jsonl 或 .zip 文件';
    });
  }
  $('singleForm').addEventListener('submit', async e => {
    e.preventDefault();
    const code = $('func').value;
    if (code.trim().length < 10) return toast('函数代码至少 10 个字符');
    const commitUrl = $('commitUrl').value.trim();
    const label = $('target').value;
    if (commitUrl && !['0','1'].includes(label)) return toast('提供 commit_url 时，必须选定 0 或 1 以严格隔离仓库版本');
    const body = {idx:$('idx').value.trim(),func:code,commit_url:commitUrl||null,target:commitUrl?Number(label):null};
    try { const result = await request('/api/jobs/single', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); await watchJob(result.job_id,'single'); }
    catch(err){toast(err.message)}
  });
  $('batchForm').addEventListener('submit', async e => {
    e.preventDefault();
    if (!$('batchFile').files.length) return toast('请先上传文件，或点击“使用 dataset/test.jsonl 检测”');
    const data = new FormData(); data.append('file',$('batchFile').files[0]);
    try { const result = await request('/api/jobs/batch',{method:'POST',body:data});toast(`已提交 ${result.total} 条样本，每条独立检测`);await watchJob(result.job_id,'batch'); }
    catch(err){toast(err.message)}
  });
  $('knowledgeForm').addEventListener('submit', async e => {
    e.preventDefault();
    if (!$('knowledgeFile').files.length) return toast('请先上传文件，或点击“读取 dataset/knowledge.jsonl 构建”');
    const data = new FormData(); data.append('file',$('knowledgeFile').files[0]);
    setBusy(true);
    try { const result = await request('/api/knowledge/import',{method:'POST',body:data});toast(`已构建 ${result.imported_pairs} 对案例；排除异常 ${result.knowledge?.import_audit?.rejected_pairs ?? 0} 对，重复 ${result.knowledge?.import_audit?.duplicate_pairs ?? 0} 对`);await refreshHealth(); }
    catch(err){toast(err.message)}finally{setBusy(false)}
  });
  $('runLocalKnowledge').addEventListener('click', async () => {
    setBusy(true);
    $('runLocalKnowledge').disabled = true;
    try {
      const data = await request('/api/knowledge/import-local', {method:'POST'});
      toast(`本地知识库构建成功：${data.imported_pairs} 个历史配对`);
      await refreshHealth();
    } catch(e) { toast(e.message); }
    finally { setBusy(false); $('runLocalKnowledge').disabled = false; }
  });
  $('runLocalBatch').addEventListener('click', async () => {
    setBusy(true);
    $('runLocalBatch').disabled = true;
    try {
      const data = await request('/api/jobs/batch-local', {method:'POST'});
      toast(`已提交本地 ${data.total} 条样本`);
      await watchJob(data.job_id, 'batch');
    } catch(e) { toast(e.message); }
    finally { $('runLocalBatch').disabled = false; if (!state.stream) setBusy(false); }
  });
  async function refreshScoreJobs(selectedId) {
    try {
      const data = await request('/api/results');
      const box = $('scoreJob');
      const original = selectedId || box.value;
      box.replaceChildren(newNode('option','', '请选择已结束的批量任务'));
      for (const job of data.jobs.filter(j => j.mode === 'batch' && finalStatuses.has(j.status))) {
        const option = newNode('option','', `${job.id.slice(0,10)} · ${job.status} · ${job.success}/${job.total}`);
        option.value = job.id;
        box.append(option);
      }
      if ([...box.options].some(o=>o.value === original)) box.value = original;
    } catch(e) { $('scoreHint').textContent = e.message; }
  }
  function showScore(score) {
    const root = $('scoreView'); root.replaceChildren();
    const title = newNode('div','score-banner');
    title.append(newNode('div','score-grade',score.grade),newNode('div','',score.complete ? `正式统计 · ${score.evaluated_pairs}/${score.pairs} 对已评分` : `暂定等级 · ${score.evaluated_pairs}/${score.pairs} 对已评分，仍有缺失预测`));
    root.append(title);
    const grid = newNode('div','score-metrics');
    [['P-C','正确区分两版'],['P-V','两版均判有漏洞'],['P-B','两版均判无漏洞'],['P-R','两版完全反转']].forEach(([key,caption])=>{
      const tile=newNode('div','score-metric');
      tile.append(newNode('strong','',String(score[key])),newNode('span','',key),newNode('small','',caption));
      grid.append(tile);
    });
    root.append(grid);
    const total = Math.max(1,score.evaluated_pairs);
    const bars = newNode('div','score-bars');
    [['P-C','#25b88b'],['P-V','#e0a44a'],['P-B','#6c89c3'],['P-R','#e96a76']].forEach(([name,color])=>{
      const bar=newNode('div','score-bar');
      bar.append(newNode('span','',name));
      const track=newNode('div','score-track');const fill=newNode('div','score-fill');fill.style.width=`${100*score[name]/total}%`;fill.style.background=color;track.append(fill);
      bar.append(track,newNode('span','',`${(100*score[name]/total).toFixed(1)}%`));bars.append(bar);
    });
    root.append(bars);
    root.append(newNode('p','form-hint',`成对正确率：${(score.pair_accuracy*100).toFixed(2)}% · 惩罚：${score.penalty?'触发降级':'未触发'} · 已有预测 ${score.predictions} 条 · 保存目录 ${score.output_directory}`));
    if (!score.complete) root.append(newNode('p','score-warning','⚠ 预测尚未覆盖全部测试样本；此等级仅作参考，不是最终课程评分。'));
  }
  // Destructive operations require user confirmation and server-side checks.
  async function clearResults(jobId) {
    const scope = jobId ? `任务 ${jobId.slice(0, 12)}` : '所有已结束任务';
    if (!window.confirm(`确定删除${scope}的报告、评分和事件日志吗？\n此操作不可撤销，但不会删除知识库、原始数据集或模型配置。`)) return;
    try {
      const payload = {confirm: 'CLEAR_RESULTS'};
      if (jobId) payload.job_id = jobId;
      const data = await request('/api/results/clear', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
      if (state.stream) { state.stream.close(); state.stream = null; }
      state.jobId = null;
      state.reports = [];
      state.events = 0;
      $('eventFeed').replaceChildren(emptyMessage('暂无历史记录', '可以直接重新提交检测任务。'));
      $('reportArea').replaceChildren(emptyMessage('暂无检测报告', '新任务完成后显示报告。'));
      $('eventCount').textContent = '0 EVENTS';
      $('reportActions').classList.add('hidden');
      $('scoreView').replaceChildren(emptyMessage('尚无评分', '运行新批量任务后可重新评分。'));
      badge($('jobStatus'), '尚未运行', 'muted');
      setBusy(false);
      await refreshScoreJobs();
      toast(`已删除 ${data.deleted_jobs} 项任务，可直接重新运行`);
    } catch(e) { toast(`清空失败：${e.message}`); }
  }
  $('clearAllResults').addEventListener('click', () => clearResults(null));
  $('deleteScoreJob').addEventListener('click', () => {
    const id = $('scoreJob').value;
    if (!id) return toast('请先选择历史任务');
    return clearResults(id);
  });
  $('clearKnowledge').addEventListener('click', async () => {
    if (!window.confirm('确定清空当前 RAG 知识库索引吗？\n原始 dataset/knowledge.jsonl 将保留；清空后需重新构建索引。')) return;
    try {
      const r = await request('/api/knowledge/clear', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:'CLEAR_KNOWLEDGE'})});
      await refreshHealth();
      toast(`已清空 ${r.deleted_cases} 条历史案例；可直接重新构建`);
    } catch(e) { toast(`清空知识库失败：${e.message}`); }
  });
  $('refreshJobs').addEventListener('click',()=>refreshScoreJobs());
  $('runScore').addEventListener('click',async()=>{
    const id=$('scoreJob').value;
    if (!id) return toast('请先选择已经结束的批量任务');
    try {const data=await request(`/api/jobs/${id}/score`);showScore(data);toast('评分已写入 result/ 对应任务目录');}
    catch(e){toast(e.message);$('scoreHint').textContent=e.message;}
  });
  document.querySelector('[data-tab="scoring"]').addEventListener('click',()=>refreshScoreJobs(state.jobId));
  $('downloadResult').addEventListener('click',()=> {if(state.jobId)window.location.href=`/api/jobs/${state.jobId}/download?format=result`;});
  $('downloadReports').addEventListener('click',()=> {if(state.jobId)window.location.href=`/api/jobs/${state.jobId}/download?format=reports`;});
  $('fillExample').addEventListener('click',()=> {
    $('func').value = 'int sum_nonnegative(const int *values, size_t count) {\n    int total = 0;\n    if (values == NULL) return -1;\n    for (size_t i = 0; i < count; ++i) {\n        if (values[i] >= 0) total += values[i];\n    }\n    return total;\n}';
    $('func').dispatchEvent(new Event('input'));
    toast('已填入教学演示函数，仅用于展示交互，不代表真实数据集样本');
  });
  $('func').addEventListener('input',()=> $('charCount').textContent=`${$('func').value.length.toLocaleString()} chars`);
  document.querySelectorAll('.nav-button').forEach(n => n.addEventListener('click',()=>switchTab(n.dataset.tab)));
  setupFileDrop('batchDrop','batchFile');
  setupFileDrop('knowledgeDrop','knowledgeFile');
  // Model settings are initialized independently in model-settings.js.
  // Other workspace features must not prevent users from opening model settings.
  refreshHealth();
})();
