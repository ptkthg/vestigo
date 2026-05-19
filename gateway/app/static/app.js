'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
let currentResult = null;
let currentPerfil = 'n1';
let currentAnalysisId = null;
let selectedVerdict = null;

// ── File upload ───────────────────────────────────────────────────────────────
function loadFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    document.getElementById('logInput').value = e.target.result;
    document.getElementById('fileName').textContent = file.name;
  };
  reader.readAsText(file, 'utf-8');
}

function setupDragDrop() {
  const zone = document.getElementById('dropZone');
  const overlay = document.getElementById('dropOverlay');
  if (!zone) return;

  zone.addEventListener('dragover', e => {
    e.preventDefault();
    overlay.classList.remove('hidden');
  });
  zone.addEventListener('dragleave', () => overlay.classList.add('hidden'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    overlay.classList.add('hidden');
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      document.getElementById('logInput').value = ev.target.result;
      document.getElementById('fileName').textContent = file.name;
    };
    reader.readAsText(file, 'utf-8');
  });
}

// ── Export ────────────────────────────────────────────────────────────────────
function exportJSON() {
  if (!currentResult) return;
  const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vestigo-${currentPerfil}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportPDF() {
  if (!currentResult) return;
  window.print();
}

// ── Progress stages ───────────────────────────────────────────────────────────
function setStage(stage) {
  const ids = { parser: 'stageParser', enricher: 'stageEnricher', ai: 'stageAI' };
  Object.entries(ids).forEach(([key, id]) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = 'stage';
    if (key === stage) el.classList.add('active');
    else if (stageOrder(key) < stageOrder(stage)) el.classList.add('done');
  });
}

function stageOrder(s) {
  return { parser: 0, enricher: 1, ai: 2 }[s] ?? -1;
}

// ── Main analyze (SSE streaming) ──────────────────────────────────────────────
async function analyze() {
  const logInput = document.getElementById('logInput').value.trim();
  currentPerfil = document.getElementById('profileSelect').value;

  if (!logInput) {
    showError('Cole um log de segurança antes de analisar.');
    return;
  }

  setLoading(true);
  hideError();
  hideResults();
  showProgress();

  try {
    const resp = await fetch('/api/analyze/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ log_raw: logInput, perfil: currentPerfil }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || `Erro ${resp.status}`);
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const raw = line.slice(6).trim();
        if (!raw || raw === '[DONE]') continue;

        try {
          const msg = JSON.parse(raw);
          if (msg.event === 'progress') {
            setStage(msg.stage);
          } else if (msg.event === 'context') {
            renderContext(msg.similar || []);
          } else if (msg.event === 'result') {
            currentResult = msg.data;
            currentAnalysisId = msg.analysis_id || null;
            renderResults(currentResult, currentPerfil);
            resetDiagnosis();
          } else if (msg.event === 'error') {
            throw new Error(msg.detail || 'Erro no processamento');
          }
        } catch (parseErr) {
          if (parseErr.message !== 'Erro no processamento') continue;
          throw parseErr;
        }
      }
    }
  } catch (e) {
    showError(e.message || 'Falha ao conectar ao servidor.');
  } finally {
    setLoading(false);
    hideProgress();
  }
}

// ── Render ────────────────────────────────────────────────────────────────────
function renderResults(data, perfil) {
  const res = data.resultado || {};
  const severidade = (data.severidade || res.severidade_confirmada || 'medium').toLowerCase();

  const banner = document.getElementById('severityBanner');
  banner.className = `severity-banner sev-${severidade}`;
  document.getElementById('severityText').textContent = severidade.toUpperCase();

  document.getElementById('resumoText').textContent =
    res.resumo || res.resumo_executivo || 'Sem resumo disponível.';

  const mitreDiv = document.getElementById('mitreText');
  if (data.mitre_id || res.mitre_analise?.id) {
    const id = data.mitre_id || res.mitre_analise?.id || '';
    const tecnica = data.mitre_tecnica || res.mitre_analise?.tecnica_principal || '';
    const tatica = res.mitre_analise?.tatica || '';
    mitreDiv.innerHTML = `
      <span class="mitre-id">${escHtml(id)}</span>
      <span class="mitre-tecnica">${escHtml(tecnica)}</span>
      ${tatica ? `<span class="mitre-tactic">${escHtml(tatica)}</span>` : ''}
      ${res.mitre_analise?.justificativa
        ? `<p style="margin-top:10px;font-size:12px;color:var(--text-2);font-family:var(--sans);line-height:1.6">${escHtml(res.mitre_analise.justificativa)}</p>`
        : ''}
    `;
  } else {
    mitreDiv.innerHTML = '<span style="color:var(--text-3)">Técnica MITRE não identificada</span>';
  }

  const acoesList = document.getElementById('acoesList');
  acoesList.innerHTML = '';
  const acoes = perfil === 'n1' ? res.acoes_imediatas || [] : res.recomendacoes_tecnicas || [];
  if (acoes.length) {
    acoes.forEach(a => {
      const li = document.createElement('li');
      li.textContent = a;
      acoesList.appendChild(li);
    });
  } else {
    acoesList.innerHTML = '<li style="list-style:none;color:var(--text-muted)">Nenhuma ação específica identificada.</li>';
  }

  renderIocs(data.iocs || {});

  const queries = res.queries || {};
  document.getElementById('kqlQuery').textContent = queries.kql || queries.kql_detection || '-- Nenhuma query KQL gerada';
  document.getElementById('splQuery').textContent = queries.spl || queries.spl_detection || '-- Nenhuma query SPL gerada';
  switchTab('kql');

  const n2Card = document.getElementById('cardN2Extra');
  if (perfil === 'n2n3' && res.cadeia_ataque) {
    n2Card.classList.remove('hidden');
    renderN2Extra(res);
  } else {
    n2Card.classList.add('hidden');
  }

  document.getElementById('results').classList.remove('hidden');
  document.getElementById('cardDiagnosis').classList.remove('hidden');
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderIocs(iocs) {
  const container = document.getElementById('iocsContent');
  container.innerHTML = '';

  const groups = [
    { key: 'ips', label: 'IPs' },
    { key: 'hashes', label: 'Hashes' },
    { key: 'dominios', label: 'Domínios' },
    { key: 'urls', label: 'URLs' },
    { key: 'emails', label: 'Emails' },
  ];

  let hasAny = false;
  groups.forEach(({ key, label }) => {
    const items = iocs[key] || [];
    if (!items.length) return;
    hasAny = true;

    const group = document.createElement('div');
    group.className = 'ioc-group';
    group.innerHTML = `<div class="ioc-group-label">${label} (${items.length})</div>`;

    items.slice(0, 8).forEach(val => {
      const tag = document.createElement('span');
      tag.className = 'ioc-tag';
      tag.textContent = val;
      group.appendChild(tag);
    });

    container.appendChild(group);
  });

  if (!hasAny) {
    container.innerHTML = '<span class="no-iocs">Nenhum IoC extraído.</span>';
  }
}

function renderN2Extra(res) {
  const container = document.getElementById('n2ExtraContent');
  container.innerHTML = '';

  const sections = [
    { key: 'cadeia_ataque', label: 'Cadeia de Ataque', type: 'text' },
    { key: 'hipoteses', label: 'Hipóteses', type: 'list' },
    { key: 'pivos', label: 'Pivôs de Investigação', type: 'list' },
    { key: 'containment', label: 'Contenção Imediata', type: 'text' },
    { key: 'false_positive_reasoning', label: 'Análise de Falso Positivo', type: 'text' },
  ];

  sections.forEach(({ key, label, type }) => {
    const val = res[key];
    if (!val || (Array.isArray(val) && !val.length)) return;

    const div = document.createElement('div');
    div.className = 'n2-section';

    if (type === 'text') {
      div.innerHTML = `<div class="n2-section-title">${escHtml(label)}</div>
        <p style="font-size:13px;color:var(--text);line-height:1.7">${escHtml(val)}</p>`;
    } else {
      const items = Array.isArray(val) ? val : [val];
      div.innerHTML = `<div class="n2-section-title">${escHtml(label)}</div>
        <ul class="n2-list">${items.map(i => `<li>${escHtml(i)}</li>`).join('')}</ul>`;
    }
    container.appendChild(div);
  });

  const queries = res.queries || {};
  if (queries.kql_hunting) {
    const div = document.createElement('div');
    div.className = 'n2-section';
    div.innerHTML = `
      <div class="n2-section-title">KQL — Threat Hunting</div>
      <div style="position:relative">
        <pre class="query-code" id="kqlHuntingQuery">${escHtml(queries.kql_hunting)}</pre>
        <button class="btn-copy" onclick="copyQuery('kqlHuntingQuery')">Copiar</button>
      </div>`;
    container.appendChild(div);
  }
}

// ── Tabs ───────────────────────────────────────────────────────────────────────
function switchTab(tab) {
  document.getElementById('queryKQL').classList.toggle('hidden', tab !== 'kql');
  document.getElementById('querySPL').classList.toggle('hidden', tab !== 'spl');
  document.getElementById('results').querySelectorAll('.queries-tabs .tab-btn').forEach((btn, i) => {
    btn.classList.toggle('active', (i === 0 && tab === 'kql') || (i === 1 && tab === 'spl'));
  });
}

function switchCorrTab(tab) {
  document.getElementById('corrQueryKQL').classList.toggle('hidden', tab !== 'kql');
  document.getElementById('corrQuerySPL').classList.toggle('hidden', tab !== 'spl');
  document.getElementById('resultsCorrelate').querySelectorAll('.queries-tabs .tab-btn').forEach((btn, i) => {
    btn.classList.toggle('active', (i === 0 && tab === 'kql') || (i === 1 && tab === 'spl'));
  });
}

// ── Utils ──────────────────────────────────────────────────────────────────────
function copyQuery(elemId) {
  const text = document.getElementById(elemId)?.textContent || '';
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector(`[onclick="copyQuery('${elemId}')"]`);
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = 'Copiado!';
      setTimeout(() => btn.textContent = orig, 1500);
    }
  });
}

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setLoading(on) {
  const btn = document.getElementById('analyzeBtn');
  const text = document.getElementById('btnText');
  const spinner = document.getElementById('btnSpinner');
  btn.disabled = on;
  text.textContent = on ? 'Analisando...' : 'Analisar';
  spinner.classList.toggle('hidden', !on);
}

function showProgress() {
  document.getElementById('progressBar').classList.remove('hidden');
  setStage('parser');
}
function hideProgress() {
  document.getElementById('progressBar').classList.add('hidden');
}
function showError(msg) {
  const el = document.getElementById('errorBanner');
  const span = document.getElementById('errorMsg');
  if (span) span.textContent = msg;
  else el.textContent = msg;
  el.classList.remove('hidden');
}
function hideError() {
  document.getElementById('errorBanner').classList.add('hidden');
}
function hideResults() {
  document.getElementById('results').classList.add('hidden');
  document.getElementById('cardContext')?.classList.add('hidden');
}

// ── Diagnosis ─────────────────────────────────────────────────────────────────
function selectVerdict(v) {
  selectedVerdict = v;
  document.querySelectorAll('.verdict-btn').forEach(btn => btn.classList.remove('selected'));
  const map = { verdadeiro_positivo: 'vp', falso_positivo: 'fp', inconclusivo: 'inc' };
  document.querySelector(`.verdict-btn.${map[v]}`)?.classList.add('selected');
  document.getElementById('diagnosisSubmit').disabled = false;
}

function resetDiagnosis() {
  selectedVerdict = null;
  document.querySelectorAll('.verdict-btn').forEach(b => b.classList.remove('selected'));
  const note = document.getElementById('diagnosisNote');
  if (note) note.value = '';
  document.getElementById('diagnosisSubmit').disabled = true;
  document.getElementById('diagnosisSaved').classList.add('hidden');
  document.getElementById('cardDiagnosis').classList.remove('hidden');
}

async function submitDiagnosis() {
  if (!selectedVerdict || !currentAnalysisId) return;
  const note = document.getElementById('diagnosisNote')?.value || '';
  const btn = document.getElementById('diagnosisSubmit');
  btn.disabled = true;
  btn.textContent = 'Salvando...';

  try {
    const resp = await fetch(`/api/analyses/${currentAnalysisId}/diagnosis`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verdict: selectedVerdict, note }),
    });
    if (!resp.ok) throw new Error();
    document.getElementById('diagnosisSaved').classList.remove('hidden');
    btn.textContent = 'Salvo';
  } catch {
    btn.disabled = false;
    btn.textContent = 'Salvar diagnóstico';
    showError('Falha ao salvar diagnóstico.');
  }
}

// ── Context (similar analyses) ────────────────────────────────────────────────
function renderContext(similar) {
  const card = document.getElementById('cardContext');
  if (!similar || !similar.length) { card.classList.add('hidden'); return; }

  const withDiagnosis = similar.filter(s => s.diagnosis);
  const total = similar.length;

  const counts = {};
  withDiagnosis.forEach(s => { counts[s.diagnosis] = (counts[s.diagnosis] || 0) + 1; });

  const labels = {
    verdadeiro_positivo: 'VP',
    falso_positivo: 'FP',
    inconclusivo: '?',
  };
  const colors = {
    verdadeiro_positivo: 'var(--red)',
    falso_positivo: 'var(--green)',
    inconclusivo: 'var(--yellow)',
  };

  const summaryParts = Object.entries(counts).map(([k, v]) =>
    `<span class="ctx-pill" style="color:${colors[k]}">${labels[k]} ${v}</span>`
  ).join('');

  document.getElementById('contextSummary').innerHTML = `
    <span class="ctx-total">${total} ocorrência${total > 1 ? 's' : ''} deste padrão</span>
    ${summaryParts}
  `;

  const recent = withDiagnosis.slice(0, 3);
  document.getElementById('contextList').innerHTML = recent.map(s => {
    const d = new Date(s.created_at);
    const dateStr = d.toLocaleDateString('pt-BR') + ' ' + d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
    const diagLabel = { verdadeiro_positivo: 'VP', falso_positivo: 'FP', inconclusivo: '?' }[s.diagnosis] || '';
    const diagColor = colors[s.diagnosis] || 'var(--text-3)';
    return `
      <div class="ctx-item">
        <span class="ctx-date">${dateStr}</span>
        <span class="ctx-verdict" style="color:${diagColor}">${diagLabel}</span>
        ${s.diagnosis_note
          ? `<span class="ctx-note">${escHtml(s.diagnosis_note)}</span>`
          : '<span class="ctx-note ctx-no-note">Sem nota</span>'}
      </div>
    `;
  }).join('');

  card.classList.remove('hidden');
}

// ── Mode switching ─────────────────────────────────────────────────────────────
let currentMode = 'individual';

function switchMode(mode) {
  currentMode = mode;
  const isCorr = mode === 'correlate';
  document.getElementById('sectionIndividual').classList.toggle('hidden', isCorr);
  document.getElementById('sectionCorrelate').classList.toggle('hidden', !isCorr);
  document.getElementById('results').classList.add('hidden');
  document.getElementById('resultsCorrelate').classList.add('hidden');
  document.getElementById('modeTabIndividual').classList.toggle('active', !isCorr);
  document.getElementById('modeTabCorrelate').classList.toggle('active', isCorr);
  hideError();
}

// ── Correlation log list ───────────────────────────────────────────────────────
let corrLogs = ['', ''];

function initCorrLogs() {
  renderCorrLogList();
}

function addCorrLog() {
  if (corrLogs.length >= 10) return;
  // sync current values before adding
  syncCorrLogs();
  corrLogs.push('');
  renderCorrLogList();
}

function removeCorrLog(index) {
  if (corrLogs.length <= 2) return;
  syncCorrLogs();
  corrLogs.splice(index, 1);
  renderCorrLogList();
}

function syncCorrLogs() {
  document.querySelectorAll('.corr-log-textarea').forEach((ta, i) => {
    if (i < corrLogs.length) corrLogs[i] = ta.value;
  });
}

function renderCorrLogList() {
  const container = document.getElementById('corrLogList');
  container.innerHTML = corrLogs.map((val, i) => `
    <div class="corr-log-entry">
      <div class="corr-log-header">
        <span class="corr-log-num">Evento ${i + 1}</span>
        ${corrLogs.length > 2
          ? `<button class="btn-remove-log" onclick="removeCorrLog(${i})">
               <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                 <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
               </svg>
               Remover
             </button>`
          : ''}
      </div>
      <textarea
        class="log-textarea corr-log-textarea"
        placeholder="Cole o log do evento ${i + 1} aqui..."
        spellcheck="false"
      >${escHtml(val)}</textarea>
    </div>
  `).join('');
}

// ── Correlate ─────────────────────────────────────────────────────────────────
let currentCorrResult = null;

async function correlate() {
  syncCorrLogs();
  const logs = corrLogs.map(l => l.trim()).filter(Boolean);
  if (logs.length < 2) {
    showError('Preencha pelo menos 2 logs para correlacionar.');
    return;
  }

  const perfil = document.getElementById('corrProfileSelect').value;
  const btn = document.getElementById('corrBtn');
  const btnText = document.getElementById('corrBtnText');
  const spinner = document.getElementById('corrSpinner');

  btn.disabled = true;
  btnText.textContent = 'Correlacionando...';
  spinner.classList.remove('hidden');
  hideError();
  document.getElementById('resultsCorrelate').classList.add('hidden');

  try {
    const resp = await fetch('/api/analyze/correlate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ logs, perfil }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || `Erro ${resp.status}`);
    }
    currentCorrResult = await resp.json();
    renderCorrelation(currentCorrResult);
  } catch (e) {
    showError(e.message || 'Falha ao correlacionar.');
  } finally {
    btn.disabled = false;
    btnText.textContent = 'Correlacionar';
    spinner.classList.add('hidden');
  }
}

function renderCorrelation(data) {
  const res = data.resultado || {};
  const sev = (data.severidade_geral || res.severidade_geral || 'medium').toLowerCase();
  const isCoord = data.e_ataque_coordenado || res.e_ataque_coordenado || false;

  document.getElementById('corrSeverityBanner').className = `severity-banner sev-${sev}`;
  document.getElementById('corrSeverityText').textContent = sev.toUpperCase();
  document.getElementById('corrCoordText').textContent = isCoord
    ? `Ataque coordenado identificado · ${data.total_eventos || 0} eventos correlacionados`
    : `Padrão não coordenado · ${data.total_eventos || 0} eventos analisados`;

  document.getElementById('corrResumo').textContent = res.resumo_geral || 'Sem resumo disponível.';

  // MITRE
  const ma = res.mitre_analise || {};
  document.getElementById('corrMitre').innerHTML = ma.id ? `
    <span class="mitre-id">${escHtml(ma.id)}</span>
    <span class="mitre-tecnica">${escHtml(ma.tecnica_principal || '')}</span>
    ${ma.tatica ? `<span class="mitre-tactic">${escHtml(ma.tatica)}</span>` : ''}
    ${(ma.tecnicas_secundarias || []).length
      ? `<p style="margin-top:8px;font-size:12px;color:var(--text-2);font-family:var(--sans)">Técnicas secundárias: ${ma.tecnicas_secundarias.map(escHtml).join(', ')}</p>`
      : ''}
    ${ma.justificativa
      ? `<p style="margin-top:8px;font-size:12px;color:var(--text-2);font-family:var(--sans);line-height:1.6">${escHtml(ma.justificativa)}</p>`
      : ''}
  ` : '<span style="color:var(--text-3)">Técnica MITRE não identificada</span>';

  // Timeline
  const events = res.linha_do_tempo || [];
  document.getElementById('corrTimeline').innerHTML = events.length
    ? events.map(ev => `
        <div class="timeline-entry">
          <div class="timeline-num">${ev.ordem || '?'}</div>
          <div class="timeline-body">
            <div class="timeline-event">${escHtml(ev.evento || '')}</div>
            <div class="timeline-role">${escHtml(ev.papel_no_ataque || '')}</div>
            ${ev.timestamp ? `<div class="timeline-ts">${escHtml(ev.timestamp)}</div>` : ''}
          </div>
        </div>
      `).join('')
    : '<span style="color:var(--text-3)">Linha do tempo não disponível.</span>';

  // Correlações
  const corrs = res.correlacoes || [];
  document.getElementById('corrLinks').innerHTML = corrs.length
    ? corrs.map(c => `
        <div class="corr-link-item">
          <div class="corr-link-type">${escHtml(c.tipo || '')}</div>
          <div class="corr-link-value">${escHtml(c.valor || '')}</div>
          <div class="corr-link-events">Eventos ${(c.eventos_envolvidos || []).join(' e ')}</div>
          <div class="corr-link-sig">${escHtml(c.significancia || '')}</div>
        </div>
      `).join('')
    : '<span style="color:var(--text-3)">Nenhuma correlação direta identificada.</span>';

  // IoCs combinados
  const iocsComb = res.iocs_combinados || {};
  const corrIoCs = document.getElementById('corrIoCs');
  corrIoCs.innerHTML = '';
  const iocGroups = [
    { key: 'ips', label: 'IPs' },
    { key: 'dominios', label: 'Domínios' },
    { key: 'hashes', label: 'Hashes' },
    { key: 'usuarios', label: 'Usuários' },
  ];
  let hasAny = false;
  iocGroups.forEach(({ key, label }) => {
    const items = iocsComb[key] || [];
    if (!items.length) return;
    hasAny = true;
    const group = document.createElement('div');
    group.className = 'ioc-group';
    group.innerHTML = `<div class="ioc-group-label">${label} (${items.length})</div>`;
    items.slice(0, 8).forEach(v => {
      const tag = document.createElement('span');
      tag.className = 'ioc-tag';
      tag.textContent = v;
      group.appendChild(tag);
    });
    corrIoCs.appendChild(group);
  });
  if (!hasAny) corrIoCs.innerHTML = '<span class="no-iocs">Nenhum IoC combinado identificado.</span>';

  // Recomendações
  const recs = res.recomendacoes || [];
  document.getElementById('corrRecomendacoes').innerHTML = recs.length
    ? recs.map(r => `<li>${escHtml(r)}</li>`).join('')
    : '<li style="list-style:none;color:var(--text-3)">Nenhuma recomendação disponível.</li>';

  // Queries
  const queries = res.queries || {};
  document.getElementById('corrKql').textContent = queries.kql_correlacao || '-- Nenhuma query KQL gerada';
  document.getElementById('corrSpl').textContent = queries.spl_correlacao || '-- Nenhuma query SPL gerada';
  switchCorrTab('kql');

  document.getElementById('resultsCorrelate').classList.remove('hidden');
  document.getElementById('resultsCorrelate').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function exportCorrJSON() {
  if (!currentCorrResult) return;
  const blob = new Blob([JSON.stringify(currentCorrResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vestigo-correlacao-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Init ───────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setupDragDrop();
  initCorrLogs();
  document.getElementById('logInput').addEventListener('keydown', e => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) analyze();
  });
});
