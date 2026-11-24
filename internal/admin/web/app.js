'use strict';

const pages = {overview:'运行总览', regions:'地区出口', access:'接入管理', connections:'连接与会话', events:'事件与任务', settings:'系统设置', tutorial:'使用教程'};
const countries = new Intl.DisplayNames(['zh-CN'], {type:'region'});
const roleOrder = ['主用','候选','备用'];
const labels = {rotate:'自动轮换', region:'固定地区', sticky:'固定会话', read:'只读', write:'管理', feedback:'会话和限流反馈'};
const $ = s => document.querySelector(s);
const escape = x => String(x ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const regionName = code => code ? countries.of(code) : '全部地区';
const badge = (text,tone='') => `<span class="badge ${tone}">${escape(text)}</span>`;
const button = (text,action,id='',kind='') => `<button type="button" class="${kind}" data-action="${action}" data-id="${escape(id)}">${escape(text)}</button>`;
const navButton = (text,page,kind='quiet') => `<button type="button" class="${kind}" data-nav="${page}">${escape(text)}</button>`;
const heading = (title,sub,actions='') => `<div class="page-heading"><div><h1>${title}</h1><p>${sub}</p></div><div class="line">${actions}</div></div>`;
const panel = (title,body,actions='') => `<section class="panel"><div class="panel-head"><h2>${title}</h2><div class="line">${actions}</div></div>${body}</section>`;
const populated = value => value && !value.startsWith('0001-');
const time = value => populated(value) ? new Date(value).toLocaleString('zh-CN',{hour12:false}) : '—';
const idCell = value => `<span class="mono">${escape(value || '—')}</span>`;
const errorBox = '<p class="field-error" role="alert"></p>';
const keyResult = (title,secret) => {
  openDialog(title,`<div class="secret-once"><p>凭据只显示这一次。请保存到你的密码管理器。</p><code id="copy-value">${escape(secret)}</code></div>${button('复制凭据','copy')}`);
};

let auth = {};
let data;
let view = new URLSearchParams(location.search).get('view') || 'overview';
if (!pages[view]) view = 'overview';
let region = new URLSearchParams(location.search).get('region') || '';
let accessTab = 'accounts';
let connTab = 'flows';
let eventTab = 'events';
let settingsTab = 'policy';
let regionTab = 'exits';
let tutorial = '';
let sessionStream;
let stale = false;
let busyRefresh = false;
let loginNeedsCode = false;
let retainedLogin;
let settingsDirty = false;
let filter = '';
let filterRegion = '';
let lastStatus = '';

async function api(path, payload) {
  const options = {headers:{'X-Ferry-Request':'1'}, cache:'no-store'};
  if (payload !== undefined) {
    options.method = 'POST';
    options.headers['Content-Type'] = 'application/json';
    options.headers['X-Ferry-CSRF'] = auth.CSRF || '';
    options.body = JSON.stringify(payload);
  }
  let response;
  try {
    response = await fetch('/api/v1/' + path, options);
  } catch {
    throw new Error('暂时无法连接渡口，请检查服务状态。');
  }
  const body = await response.json();
  if (!response.ok) {
    if (response.status === 401 && auth.Authenticated && !path.startsWith('security/')) {
      auth.Authenticated = false;
      stopStream();
      renderAuth('管理会话已过期，请重新登录。');
    }
    throw new Error(body.Error || '操作未完成，请重试。');
  }
  return body;
}

function stopStream() {
  sessionStream?.close();
  sessionStream = undefined;
}

function startStream() {
  stopStream();
  sessionStream = new EventSource('/api/v1/stream');
  // The server pushes the full status only when it changes, plus a heartbeat.
  sessionStream.addEventListener('status', event => {
    let next;
    try { next = JSON.parse(event.data); } catch { refresh(); return; }
    applyStatus(next);
  });
  sessionStream.onerror = () => {
    if (!stale) {
      stale = true;
      showStale();
    }
    refresh();
  };
}

async function refresh(force=false) {
  if (busyRefresh || !auth.Authenticated) return;
  busyRefresh = true;
  try {
    applyStatus(await api('status'), force);
  } catch (error) {
    if (!auth.Authenticated) return;
    if (!data) {
      $('#app').innerHTML = `<main class="content"><p class="notice">${escape(error.message)}</p>${button('重试','reload')}</main>`;
    }
    stale = true;
    showStale();
  } finally {
    busyRefresh = false;
  }
}

// applyStatus re-renders only when something changed and the user is not
// reading the tutorial, using a dialog, editing settings or typing a filter.
function applyStatus(next, force=false) {
  if (!auth.Authenticated) return;
  data = next;
  emptyCollections();
  stale = false;
  showStale();
  const status = JSON.stringify({...data, Time:null, Devices:data.Devices.map(({ID,Agent,Current})=>({ID,Agent,Current}))});
  if (force || (status !== lastStatus && view !== 'tutorial' && !document.querySelector('dialog[open]') && !settingsDirty && !$('#filter-form')?.contains(document.activeElement))) {
    lastStatus = status;
    render();
  } else {
    const updated = $('#last-update');
    if (updated) updated.textContent = '更新于 ' + time(data.Time);
  }
}

function emptyCollections() {
  for (const key of ['Regions','Exits','Nodes','Accounts','Keys','Flows','Bindings','Cooldowns','Operations','Events','Devices']) {
    data[key] ||= [];
  }
}

function showStale() {
  const notice = $('#stale');
  if (notice) notice.hidden = !stale;
}

function navigate(next) {
  if (!pages[next]) return;
  if (settingsDirty && next !== view) {
    openDialog('离开未保存的设置？','<p>未保存的修改将被丢弃。</p>',() => {
      settingsDirty = false;
      closeDialog();
      navigate(next);
    },'丢弃并离开');
    return;
  }
  view = next;
  filter = '';
  filterRegion = '';
  history.pushState({},'', '?view='+next+(next==='regions'&&region?'&region='+region:''));
  render();
  scrollTo(0,0);
}

function render() {
  if (!auth.Authenticated || !data) return;
  const enabled = data.Regions.filter(r => r.Enabled);
  const ready = enabled.filter(r => r.Healthy > 0).length;
  $('#app').innerHTML = `<header class="app-header"><div class="topbar">
    <a class="brand" href="?view=overview" data-nav="overview"><span class="mark">渡</span>渡口 <span class="muted small">Ferry Console</span></a>
    <div class="line end"><span id="last-update" class="live-label small">更新于 ${time(data.Time)}</span>${badge(ready===0?'无可用出口':ready===enabled.length?'运行中':'部分可用', ready!==enabled.length||!ready?'warn':'')}
    ${button('退出','logout','','quiet')}</div></div>
    <nav class="topnav" aria-label="主导航">${Object.entries(pages).map(([v,n])=>`<a href="?view=${v}" data-nav="${v}" aria-current="${v===view?'page':'false'}" class="nav-link ${v===view?'active':''}">${n}</a>`).join('')}</nav></header>
    <main class="content"><div id="stale" class="notice" ${stale?'':'hidden'}>状态更新中断。恢复前显示最后一次快照。</div>
    ${({overview,regions,access,connections,events,settings,tutorial:tutorialView}[view])()}</main>`;
  if (view === 'tutorial') {
    for (const code of document.querySelectorAll('.lesson pre')) {
      const tools = document.createElement('div');
      tools.className = 'snippet-tools';
      tools.innerHTML = button('复制代码','copy-example','','quiet');
      code.before(tools);
    }
  }
}

function formField(label,name,value='',type='text',attributes='') {
  return `<div class="field"><label for="f-${name}">${label}</label><input id="f-${name}" name="${name}" type="${type}" value="${escape(value)}" ${attributes}></div>`;
}
function selectField(label,name,items,value='') {
  return `<div class="field"><label for="f-${name}">${label}</label><select id="f-${name}" name="${name}">${items.map(([v,t])=>`<option value="${escape(v)}" ${v===value?'selected':''}>${escape(t)}</option>`).join('')}</select></div>`;
}
function tabs(group,items,current) {
  return `<div class="subtabs" aria-label="视图">${items.map(([t,label])=>`<button type="button" data-tab="${group}" data-value="${t}" class="${t===current?'active':''}" aria-pressed="${t===current}">${label}</button>`).join('')}</div>`;
}
function table(headers,rows,empty='暂无记录') {
  if (!rows.length) return `<div class="blank-state"><p>${escape(empty)}</p></div>`;
  return `<div class="table-scroll"><table class="table"><thead><tr>${headers.map(h=>`<th scope="col">${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}
function row(...cells) {return '<tr>'+cells.map(c=>'<td>'+c+'</td>').join('')+'</tr>';}
function detail(items) {return `<dl class="kv">${items.map(([k,v])=>`<div><dt>${k}</dt><dd>${escape(v)}</dd></div>`).join('')}</dl>`;}
function regionState(r) {
  if (!r.Enabled) return badge('已停用');
  if (!r.Healthy && r.Connecting) return badge('正在建立','warn');
  if (!r.Healthy) return badge('暂无出口','bad');
  return r.Healthy < r.Target ? badge('备用不足','warn') : badge('可用','good');
}

function overview() {
  const enabled = data.Regions.filter(r=>r.Enabled);
  const ready = enabled.filter(r=>r.Healthy);
  const attention = enabled.filter(r=>r.Healthy < r.Target);
  const healthy = enabled.reduce((n,r)=>n+r.Healthy,0);
  return heading('运行总览','查看地区容量、实际出口和待处理的任务。',button('刷新节点','refresh')+navButton('接入代理','access','primary'))+
    (attention.length?`<div class="notice"><strong>${attention.length} 个地区需要关注</strong><span>${attention.map(r=>escape(regionName(r.Code))+' '+r.Healthy+'/'+r.Target).join('，')}</span>${navButton('查看地区','regions')}</div>`:'')+
    (!data.Tunnels?`<div class="notice">当前仅运行管理服务。启用容器隧道后可发现 VPNGate 节点。</div>`:'')+
    (data.CatalogError?`<div class="notice">最近一次节点列表刷新失败。${navButton('查看任务','events')}</div>`:'')+
    `<div class="summary-bar"><span><b>${healthy} / ${enabled.length*3}</b>健康出口</span><span><b>${ready.length} / ${enabled.length}</b>可用地区</span><span><b>${data.Flows.length}</b>当前连接</span><span><b>${data.DialStats.Total?Math.round(data.DialStats.Successful/data.DialStats.Total*100)+'%':'—'}</b>TCP 建连成功率</span><span class="small muted">近 5 分钟 · ${data.DialStats.Total} 次拨号</span></div>
    <div class="grid-overview">${panel('地区出口池',table(['地区','健康 / 目标','主用 IP','状态',''],data.Regions.map(r=>row(escape(regionName(r.Code))+' '+idCell(r.Code),r.Healthy+' / '+r.Target,idCell(r.Primary),regionState(r),button('详情','region',r.Code,'quiet')))))}
    ${panel('开始接入',`<div class="pad"><p>自动轮换用于新建爬虫连接，固定地区用于 hy2 或 REALITY 的落地。</p><dl class="kv"><div><dt>代理地址</dt><dd class="mono">${escape(proxyAddress())}</dd></div><div><dt>当前账号</dt><dd>${data.Accounts.filter(a=>a.Enabled).length} 个启用</dd></div></dl>${navButton('查看使用教程','tutorial','primary')}</div>`)}</div>
    <div class="overview-lower">${panel('最近事件',eventRows(data.Events.slice(0,4)),navButton('查看全部','events'))}
    ${panel('节点来源',`<div class="pad">${detail([['来源','VPNGate'],['出口地区核验','Country.is'],['上次刷新',time(data.CatalogAt)],['已发现节点',data.Nodes.length]])}</div>`)}</div>`;
}

function regions() {
  const r = data.Regions.find(r=>r.Code===region)||data.Regions[0];
  const title=heading('地区出口','每个地区独立维护主用、候选、备用三个角色。',button('刷新列表','refresh')+button('添加地区','add-region','','primary'));
  if (!r) return title+panel('尚未配置地区','<div class="pad">添加一个国家或地区后，系统会自动寻找节点。</div>');
  region=r.Code;
  const x = data.Exits.filter(x=>x.Region===region);
  const roleCards = roleOrder.map(role=>{
    const exit=x.find(x=>x.Role===role && !populated(x.DrainUntil));
    if (!exit) return `<section class="panel exit-card empty-slot"><h3>${role}缺额</h3><p>${r.Connecting?'正在建立或核验新隧道。':r.Nodes?'等待候选节点通过验证。':'列表中暂未发现该地区节点。'}</p></section>`;
    return `<section class="panel exit-card"><div class="exit-top"><h3>${escape(role)}</h3>${badge(exit.State,exit.State==='健康'?'good':'warn')}</div><div class="exit-ip">${escape(exit.IP)}</div><p>${escape(regionName(exit.Region))} / 已核验</p>
      <dl class="kv"><div><dt>接受新连接</dt><dd>${exit.Accept?'允许':'停止'}</dd></div><div><dt>当前连接</dt><dd>${exit.Connections}</dd></div><div><dt>最近探测用时</dt><dd>${exit.LatencyMS>0?exit.LatencyMS+' ms':'暂无样本'}</dd></div><div><dt>最近验证</dt><dd>${time(exit.LastOK)}</dd></div></dl>
      <footer>${button('详情','exit',exit.ID,'quiet')}${button('探测','probe',exit.ID,'quiet')}${button('维护','exit-menu',exit.ID,'quiet')}</footer></section>`;
  }).join('');
  const pending=data.Nodes.filter(n=>n.Region===region&&!n.Connected);
  const other=x.filter(x=>!roleOrder.includes(x.Role));
  return title+`<div class="region-selector" aria-label="选择地区">${data.Regions.map(o=>button(regionName(o.Code)+' '+o.Code+'  '+o.Healthy+'/'+o.Target,'region',o.Code,o.Code===region?'active':'')).join('')}</div>`+
    panel(escape(regionName(r.Code))+'出口池',`<div class="pad"><div class="line wrap">${regionState(r)}<span>健康 ${r.Healthy} / 目标 ${r.Target}，待连接 ${pending.length} 个</span></div><p class="scope-note">指定此地区的连接只会使用本地区。无可用出口时返回失败。</p></div>`,button(r.Enabled?'停用地区':'启用地区','toggle-region',r.Code))+
    tabs('region',[['exits','已连接出口'],['nodes','待连接节点'],['history','地区事件']],regionTab)+
    (regionTab==='exits'?`<div class="health-slots">${roleCards}</div>`+(other.length?`<div class="subheading"><h2>等待恢复或排空</h2></div>`+panel('暂不分配的新旧出口',table(['公网 IP','状态','剩余连接','结束时间',''],other.map(x=>row(idCell(x.IP),badge(x.State,'warn'),x.Connections,time(x.DrainUntil),button('维护','exit-menu',x.ID,'quiet'))))):''):
    regionTab==='nodes'?panel('尚未分配的候选节点',table(['远端','协议','冷却至',''],pending.map(n=>row(idCell(n.ID),escape(n.Protocol),time(n.Cooldown),button('连接并验证','node',n.ID,'quiet'))),'暂未发现本地区可测试的节点')):
    panel('地区事件',eventRows(data.Events.filter(e=>e.Region===region))));
}

function access(){
  const controls = tabs('access',[['accounts','代理账号'],['keys','管理 API 凭据']],accessTab);
  const keys=data.Keys.map(k=>row(escape(k.Name),escape(labels[k.Scope]),time(k.Created),button('撤销','delete-key',k.ID,'quiet danger')));
  const accounts=data.Accounts.map(a=>row(escape(a.Name),escape(labels[a.Mode]),escape(a.Regions.map(regionName).join('、')),a.Limit,populated(a.Expires)?time(a.Expires):'长期',badge(a.Enabled?'已启用':'已禁用',a.Enabled?'good':''),button('管理','edit-account',a.Name,'quiet')));
  return heading('接入管理','为爬虫和地区落地分别创建账号，按用途限制地区、并发与有效期。',navButton('查看接入教程','tutorial')+button(accessTab==='keys'?'创建 API 凭据':'创建代理账号',accessTab==='keys'?'new-key':'new-account','','primary'))+
    controls+(accessTab==='accounts'?panel('代理账号',table(['账号','分配策略','允许地区','并发','有效期','状态',''],accounts,'还没有账号。创建一个账号后，才能通过 SOCKS5 或 HTTP 使用渡口。')):
    panel('管理 API 凭据',table(['名称','权限','创建时间',''],keys,'尚未创建 API 凭据。')));
}
function filterForm() {
  return `<form class="toolbar" id="filter-form"><input name="filter" type="search" value="${escape(filter)}" placeholder="搜索 ID、账号、地区或地址" aria-label="搜索记录"><select name="region" aria-label="地区筛选"><option value="">全部地区</option>${data.Regions.map(r=>`<option value="${r.Code}" ${r.Code===filterRegion?'selected':''}>${escape(regionName(r.Code))}</option>`).join('')}</select><button type="submit">筛选</button>${button('清除','clear-filter','','quiet')}</form>`;
}
function filtered(items) {
  return items.filter(x=>(!filterRegion || x.Region===filterRegion)&&(!filter||JSON.stringify(x).toLowerCase().includes(filter.toLowerCase())));
}
// A lost exit never comes back: connections using the session fail until it expires.
function bindingState(b) {
  if (b.ExitState==='lost') return badge('出口已失效，请新建会话','bad');
  if (b.ExitState==='unavailable') return badge('出口暂不可用','warn');
  return badge('可用','good');
}
function connections() {
  const cooldowns=data.Cooldowns.map(c=>({...c,Region:data.Exits.find(x=>x.ID===c.Exit)?.Region||''}));
  const cells = {
    flows:table(['连接 ID','账号','地区','出口','目标','建立时间',''],filtered(data.Flows).map(f=>row(idCell(f.ID),escape(f.Account),escape(regionName(f.Region)),idCell(f.IP),idCell(f.Target),time(f.Since),button('结束','close-connection',f.ID,'quiet danger')))),
    bindings:table(['会话 ID','账号','地区','绑定出口','出口状态','到期时间',''],filtered(data.Bindings).map(b=>row(idCell(b.ID),escape(b.Account),escape(regionName(b.Region)),idCell(data.Exits.find(x=>x.ID===b.Exit)?.IP),bindingState(b),time(b.Expires),button('释放','release-session',b.ID,'quiet')))),
    cooldowns:table(['目标域名','出口 ID','地区','恢复时间',''],filtered(cooldowns).map(c=>row(idCell(c.Target),idCell(c.Exit),escape(regionName(c.Region)),time(c.Expires),button('解除','release-cooldown',c.Exit+'|'+c.Target,'quiet'))))
  };
  return heading('连接与会话','检查实际出口，或为一组请求固定同一个已验证的连接出口。',button('创建固定会话','new-session','','primary'))+
    tabs('connection',[['flows','当前连接'],['bindings','固定会话'],['cooldowns','目标冷却']],connTab)+
    filterForm()+panel({flows:'连接记录',bindings:'会话绑定',cooldowns:'目标与出口维度的冷却'}[connTab],cells[connTab],connTab==='cooldowns'?button('报告限流反馈','feedback'):'');
}
function eventRows(items) {
  return items.length?`<div class="event-list">${items.map(e=>`<div class="event-entry"><time>${populated(e.Time)?new Date(e.Time).toLocaleTimeString('zh-CN',{hour12:false}):'—'}</time><div><strong>${escape(e.Message)}</strong><p>${escape(regionName(e.Region))}</p></div></div>`).join('')}</div>`:'<div class="blank-state"><p>暂无记录。</p></div>';
}
function events() {
  const items=filtered(data.Events).filter(e=>eventTab==='audit'?e.Kind==='audit':e.Kind!=='audit');
  const tasks=filtered(data.Operations).map(o=>row(idCell(o.ID),escape(o.Kind),escape(regionName(o.Region)),badge(({running:'进行中',done:'已完成',failed:'失败'})[o.State],({running:'warn',done:'good',failed:'bad'})[o.State]),escape(o.Detail||'正在执行'),time(o.Time)));
  return heading('事件与任务','查看建立隧道、探测、切换和管理操作的记录。')+
    tabs('event',[['events','系统事件'],['tasks','后台任务'],['audit','管理审计']],eventTab)+
    filterForm()+panel(eventTab==='tasks'?'任务状态':eventTab==='audit'?'审计记录':'地区运行事件',eventTab==='tasks'?table(['任务 ID','操作','地区','状态','结果','提交时间'],tasks):eventRows(items));
}
function settings() {
  const c=data.Config;
  const controls=tabs('settings',[['policy','出口与日志'],['security','账号与安全']],settingsTab);
  return heading('系统设置','设置隧道上限、探测和排空时间，管理管理员身份。')+controls+
    (settingsTab==='security'?`<div class="grid-2">${panel('管理员身份',`<div class="pad"><p>${escape(data.Admin)}</p><div class="toggle-row"><div><strong>管理员密码</strong><p>修改后撤销其他登录会话。</p></div>${button('修改密码','password')}</div><div class="toggle-row"><div><strong>动态验证码</strong><p>${data.TOTP?'已启用':'未启用'}</p></div>${button(data.TOTP?'关闭':'启用','totp')}</div></div>`)}
    ${panel('登录设备',table(['浏览器','最近活动',''],data.Devices.map(d=>row(escape(d.Agent||'浏览器'),time(d.Used),d.Current?badge('当前设备'):button('撤销','device',d.ID,'quiet danger')))),button('撤销其他会话','devices'))}</div>`:
    panel('运行参数',`<form id="settings-form" class="pad"><div class="form-pair">
    ${formField('最大隧道数','MaxTunnels',c.MaxTunnels,'number','min="3" max="24" required')}
    ${formField('探测间隔（秒）','ProbeSeconds',c.ProbeSeconds,'number','min="10" max="600" required')}
    ${formField('旧出口排空上限（秒）','DrainSeconds',c.DrainSeconds,'number','min="0" max="600" required')}
    ${formField('事件保留天数','RetentionDays',c.RetentionDays,'number','min="1" max="90" required')}</div>
    <label class="check-line"><input type="checkbox" name="LogTargets" ${c.LogTargets?'checked':''}>在当前连接列表显示目标域名与端口</label>
    <p class="scope-note">每地区目标为 3 条隧道。验证后替换需要额外一个位置。保留记录仅包含操作和状态，不包含代理凭据。</p>${errorBox}
    <div class="settings-footer"><button type="submit" class="primary">保存设置</button></div></form>`));
}
const proxyAddress = () => data?.ProxyAddress || '127.0.0.1:7928';
// The tutorial uses {{PROXY}}, {{PROXY_HOST}} and {{PROXY_PORT}} for the address clients should use.
function tutorialHTML() {
  const address = proxyAddress();
  const cut = address.lastIndexOf(':');
  const host = address.slice(0, cut).replace(/^\[|\]$/g, ''), port = address.slice(cut + 1);
  const values = {PROXY: address, PROXY_HOST: host, PROXY_PORT: port};
  return tutorial.replace(/\{\{(PROXY|PROXY_HOST|PROXY_PORT)\}\}/g, (_, key) => escape(values[key]));
}
function tutorialView() {
  if (!tutorial) loadTutorial();
  return heading('使用教程','从第一次连接，到给现有代理选择地区落地。',navButton('创建代理账号','access'))+
    (tutorial?tutorialHTML():'<div id="tutorial-load" class="panel pad">正在加载教程…</div>');
}
async function loadTutorial() {
  try {
    const response=await fetch('/tutorial.html');
    if (!response.ok) throw new Error('教程加载失败');
    tutorial=await response.text();
    if (view==='tutorial') render();
  } catch {
    if ($('#tutorial-load')) $('#tutorial-load').textContent='教程加载失败，请刷新页面。';
  }
}

function renderAuth(message='') {
  const initialized=auth.Initialized;
  const title=initialized?(loginNeedsCode?'二次验证':'管理员登录'):'初始化渡口';
  const fields=initialized?
    (loginNeedsCode?formField('动态验证码或恢复码','Code','','text','required autocomplete="one-time-code"'):
    formField('用户名','Username','','text','required autocomplete="username" maxlength="40"')+formField('密码','Password','','password','required autocomplete="current-password" maxlength="256"')):
    (auth.SetupAvailable?formField('一次性初始化凭据','SetupToken','','password','required autocomplete="off"')+
    formField('管理员用户名','Username','admin','text','required pattern="[A-Za-z0-9_-]{2,40}" autocomplete="username"')+
    formField('新密码（至少 12 个字符）','Password','','password','required minlength="12" maxlength="256" autocomplete="new-password"')+
    formField('确认密码','Confirm','','password','required autocomplete="new-password"'):'');
  $('#app').innerHTML=`<div class="login"><div class="login-story"><div class="brand"><span class="mark">渡</span>渡口 <span class="muted small">Ferry</span></div>
    <div class="story-copy"><h1>地区出口与<br>接入权限</h1><p>管理 VPNGate 出口池、代理账号和连接分配。</p></div><p class="story-foot small muted">管理登录与代理账号独立认证。</p></div>
    <div class="login-side"><form id="auth-form" class="login-form"><h1>${title}</h1>
    <p class="muted">${initialized?'使用管理员凭据进入控制台。':'输入部署时生成的一次性凭据，创建管理员。'}</p>
    ${fields}<p class="field-error" role="alert">${escape(message)}</p>
    ${fields?`<button class="primary" type="submit">${initialized?'进入控制台':'创建管理员'}</button>`:'<div class="auth-info">请在 VPS 上运行 init-token 生成初始化凭据，再启动渡口。</div>'}
    <div class="auth-links">${loginNeedsCode?button('返回登录','back-login','','quiet'):initialized?button('无法登录？','recover','','quiet'):''}</div></form></div></div>`;
}
async function submitAuth(fd) {
  const q=Object.fromEntries(fd);
  if (!auth.Initialized && q.Password!==q.Confirm) throw new Error('两次输入的密码不一致。');
  delete q.Confirm;
  if (loginNeedsCode) Object.assign(q,retainedLogin);
  const next=await api(auth.Initialized?'login':'setup',q);
  if (next.NeedCode) {
    loginNeedsCode=true;
    retainedLogin={Username:q.Username,Password:q.Password};
    renderAuth();
    return;
  }
  auth={...auth,...next,Initialized:true};
  loginNeedsCode=false;
  retainedLogin=undefined;
  await refresh(true);
  startStream();
}

let dialogWork;
function closeDialog() {
  $('dialog')?.close();
}
function openDialog(title,html,work,label='确认') {
  $('dialog')?.remove();
  const dialog=document.createElement('dialog');
  dialog.setAttribute('aria-labelledby','dialog-title');
  dialog.innerHTML=`<h2 id="dialog-title">${escape(title)}</h2><form id="dialog-form">${html}${errorBox}<div class="actions">
    ${button(work?'取消':'关闭','close-dialog')}${work?`<button type="submit" class="primary">${escape(label)}</button>`:''}</div></form>`;
  dialogWork=work;
  dialog.addEventListener('close',()=>dialog.remove(),{once:true});
  document.body.append(dialog);
  dialog.showModal();
}
function confirm(title,description,work,label='确认') {
  openDialog(title,`<p>${escape(description)}</p>`,work,label);
}
async function mutate(path,q={}) {
  const result=await api(path,q);
  closeDialog();
  await refresh(true);
  if (result?.ID && (path.startsWith('exits/')||path==='nodes/connect')) {
    eventTab='tasks';
    navigate('events');
  }
  return result;
}
function hasAccount(name){return data.Accounts.find(a=>a.Name===name);}
function regionOptions(){return data.Regions.map(r=>[r.Code,regionName(r.Code)+' '+r.Code]);}

function accountDialog(name) {
  const old=hasAccount(name);
  if (!data.Regions.length) throw new Error('请先添加一个地区。');
  openDialog(old?'管理 '+name:'创建代理账号',
    formField('账号名称','Name',name,'text',old?'readonly':'required pattern="[A-Za-z0-9_-]{2,40}"')+
    selectField('分配模式','Mode',Object.entries(labels).slice(0,3),old?.Mode||'rotate')+
    `<div class="field"><label>允许地区</label><div class="checks">${regionOptions().map(([code,text])=>`<label><input name="Regions" type="checkbox" value="${code}" ${(old?old.Regions.includes(code):code===data.Regions[0].Code)?'checked':''}>${escape(text)}</label>`).join('')}</div></div>`+
    formField('最大并发','Limit',old?.Limit||10,'number','min="1" max="512" required')+
    (old?formField(`重新设置有效期（天）。当前：${populated(old.Expires)?escape(time(old.Expires))+' 到期':'长期'}。留空保持不变，0 改为长期`,'Days','','number','min="0" max="365"'):
      formField('有效期（天，0 表示长期）','Days',0,'number','min="0" max="365" required'))+
    `<label class="check-line"><input name="Enabled" type="checkbox" ${old?.Enabled===false?'':'checked'}>允许接入</label>`+
    (old?`<div class="line wrap">${button('重置密码','rotate-key',name)}${button('删除账号','delete-account',name,'danger')}</div>`:''),
    async fd=>{
      const days=String(fd.get('Days')??'').trim();
      const result=await mutate('accounts/save',{Name:fd.get('Name'),ID:old?.Name||'',Mode:fd.get('Mode'),Regions:fd.getAll('Regions'),Limit:Number(fd.get('Limit')),Days:Number(days||0),ClearExpiry:!!old&&days==='0',Enabled:fd.has('Enabled')});
      if (result.Secret) keyResult('保存 '+fd.get('Name')+' 的密码',result.Secret);
    },old?'保存配置':'创建并显示密码');
}

function exitDialog(id,menu) {
  const x=data.Exits.find(x=>x.ID===id);
  if (!x) throw new Error('出口已离开池，请刷新。');
  const facts=detail([['出口 ID',x.ID],['公网 IP',x.IP],['已核验地区',regionName(x.Region)],['角色',x.Role||'未分配'],['健康状态',x.State],['新连接',x.Accept?'接受':'停止'],['远端节点',x.Node],['建立时间',time(x.Since)],['最近成功探测',time(x.LastOK)],['TCP 建连 P50 / P95',x.DialStats.Successful?x.DialStats.P50+' / '+x.DialStats.P95+' ms':'暂无样本'],['近 5 分钟建连样本',x.DialStats.Successful+' 成功 / '+x.DialStats.Total+' 次'],['排空截止',time(x.DrainUntil)]]);
  const actions=`<div class="line wrap" style="margin-top:20px">
    ${x.Accept && x.Role!=='主用'?button('提升为主用','promote',id):''}
    ${populated(x.DrainUntil)?'':button('验证后替换','replace',id)+button('停止分配并排空','drain',id)}
    ${button('强制关闭','force-close',id,'danger')}</div>`;
  openDialog(menu?'维护出口':'出口详情',facts+(menu?actions:''));
}
function requirePasswordFields() {
  return formField('当前管理员密码','Password','','password','required autocomplete="current-password"')+
    (data.TOTP?formField('动态验证码或恢复码','Code','','text','required autocomplete="one-time-code"'):'');
}

async function action(key,id,el) {
  switch(key) {
    case 'reload': await boot(); break;
    case 'back-login': loginNeedsCode=false;retainedLogin=undefined;renderAuth();break;
    case 'recover':
      openDialog('恢复管理员访问','<p>启用了动态验证码时可使用先前保存的恢复码。忘记管理员密码时，在 VPS 上按部署说明运行 reset-admin。</p>');break;
    case 'logout':
      await api('security/logout',{});auth.Authenticated=false;data=undefined;stopStream();renderAuth();break;
    case 'close-dialog': closeDialog();break;
    case 'copy-example': {
      // Use the clicked button: Safari and Firefox on macOS do not focus buttons on click.
      const code=el?.closest('.snippet-tools')?.nextElementSibling;
      if (!code) break;
      try {
        await navigator.clipboard.writeText(code.textContent);
        const control=el;
        control.textContent='已复制';
        setTimeout(()=>{if(control.isConnected)control.textContent='复制代码';},1800);
      } catch {
        const selection=getSelection(),range=document.createRange();
        range.selectNodeContents(code);
        selection.removeAllRanges();
        selection.addRange(range);
      }
      break;
    }
    case 'copy': {
      const field=$('#copy-value');
      if (!field) break;
      try { await navigator.clipboard.writeText(field.textContent); $('#dialog-form .field-error').textContent='已复制。'; }
      catch { const sel=getSelection(),range=document.createRange();range.selectNodeContents(field);sel.removeAllRanges();sel.addRange(range); }
      break;
    }
    case 'refresh':
      await mutate('nodes/refresh');eventTab='tasks';navigate('events');break;
    case 'add-region':
      openDialog('添加地区',formField('两位国家代码，例如 JP 或 SG','Region','','text','required pattern="[A-Za-z]{2}" maxlength="2"')+'<p class="muted">列表中有节点且出口核验通过后，该地区才可使用。</p>',async fd=>{
        region=fd.get('Region').toUpperCase();
        await mutate('regions/save',{Region:region,Enabled:true});navigate('regions');
      },'添加地区');break;
    case 'region': region=id;regionTab='exits';navigate('regions');break;
    case 'toggle-region': {
      const r=data.Regions.find(r=>r.Code===id);
      confirm(r.Enabled?'停用地区？':'启用地区？',r.Enabled?'这个地区将停止接收新连接。已有连接会按排空设置退出。':'系统会寻找并核验这个地区的节点。',()=>mutate('regions/save',{Region:id,Enabled:!r.Enabled}));
      break;
    }
    case 'node': await mutate('nodes/connect',{Region:region,ID:id});break;
    case 'exit': exitDialog(id,false);break;
    case 'exit-menu': exitDialog(id,true);break;
    case 'probe': await mutate('exits/probe',{ID:id});break;
    case 'promote':confirm('提升为主用？','本地区新建的固定地区连接会优先选择此出口。',()=>mutate('exits/promote',{ID:id}));break;
    case 'replace':confirm('验证后替换？','找到并验证同地区的替代出口后，才会让原出口进入排空。',()=>mutate('exits/replace',{ID:id}));break;
    case 'drain':confirm('停止新分配？','现有连接保留到自然结束或排空期限。',()=>mutate('exits/drain',{ID:id}));break;
    case 'force-close':confirm('强制关闭出口？','使用这个出口的现有连接会立即断开。',()=>mutate('exits/close',{ID:id}),'强制关闭');break;
    case 'new-account':accountDialog('');break;
    case 'edit-account':accountDialog(id);break;
    case 'rotate-key':confirm('重置代理密码？','旧密码立即失效，此账号的现有连接将断开。',async()=>{const r=await mutate('accounts/rotate',{Name:id});keyResult('保存新密码',r.Secret);});break;
    case 'delete-account':confirm('删除代理账号？','使用此账号的现有连接将中断。',()=>mutate('accounts/delete',{Name:id}),'删除账号');break;
    case 'new-key':
      openDialog('创建 API 凭据',formField('用途名称','Name','','text','required pattern="[A-Za-z0-9_-]{2,40}"')+
        selectField('权限','Scope',[['read','只读查询'],['feedback','创建固定会话和提交限流反馈'],['write','管理操作']],'read'),
        async fd=>{const r=await mutate('keys/create',Object.fromEntries(fd));keyResult('保存 API 凭据',r.Secret);},'创建并显示');break;
    case 'delete-key':confirm('撤销 API 凭据？','持有此凭据的工具将无法继续调用管理接口。',()=>mutate('keys/delete',{ID:id}));break;
    case 'close-connection':confirm('中断连接？','客户端应用可能需要重新连接。',()=>mutate('connections/close',{ID:id}));break;
    case 'new-session':{
      const eligible=data.Accounts.filter(a=>a.Enabled);
      if (!eligible.length) throw new Error('先创建一个可用的代理账号。');
      openDialog('创建固定会话',selectField('代理账号','Account',eligible.map(a=>[a.Name,a.Name]))+
        selectField('地区','Region',[['','账号允许的地区'],...regionOptions()])+
        formField('有效期（分钟）','Minutes',15,'number','required min="1" max="1440"'),
        async fd=>{
          const r=await mutate('sessions',{Account:fd.get('Account'),Region:fd.get('Region'),Minutes:Number(fd.get('Minutes'))});
          connTab='bindings';navigate('connections');
          openDialog('固定会话已创建',`<p>代理用户名填下面的值，密码使用原代理账号密码。</p><div class="secret-once"><code id="copy-value">${escape(r.Account+'.'+r.Region+'.'+r.ID)}</code></div>${button('复制用户名','copy')}`);
        },'创建固定会话');break;
    }
    case 'release-session':confirm('释放固定会话？','后续使用该会话的新连接将失败，旧连接继续使用原出口。',()=>mutate('sessions/delete',{ID:id}));break;
    case 'feedback':
      openDialog('登记目标限流',formField('会话 ID','ID','','text','required')+formField('网站域名','Target','','text','required placeholder="example.com"')+
        formField('冷却分钟数','Minutes',5,'number','min="1" max="60" required'),fd=>mutate('feedback',{ID:fd.get('ID'),Target:fd.get('Target'),Minutes:Number(fd.get('Minutes'))}),'登记冷却');break;
    case 'release-cooldown':{
      const [exit,target]=id.split('|');
      confirm('解除目标冷却？','将允许这个出口再次分配给该域名。',()=>mutate('cooldowns/delete',{ID:exit,Target:target}));break;
    }
    case 'password':
      openDialog('修改管理员密码',requirePasswordFields()+formField('新密码','Next','','password','required minlength="12" maxlength="256" autocomplete="new-password"')+formField('确认密码','Confirm','','password','required autocomplete="new-password"'),async fd=>{
        if (fd.get('Next')!==fd.get('Confirm')) throw new Error('两次输入的新密码不一致。');
        await mutate('security/password',{Password:fd.get('Password'),Code:fd.get('Code')||'',Next:fd.get('Next')});
      },'保存新密码');break;
    case 'totp':
      if (data.TOTP) {
        openDialog('关闭动态验证码',requirePasswordFields(),fd=>mutate('security/totp-disable',Object.fromEntries(fd)),'关闭动态验证码');
      } else {
        openDialog('启用动态验证码',requirePasswordFields(),async fd=>{
          const password=fd.get('Password');
          const result=await api('security/totp-secret',{Password:password});
          openDialog('添加验证器',`<p>在验证器应用选「输入设置密钥」，类型选基于时间。填入下面的密钥，再输入验证器显示的 6 位数字。</p><div class="secret-once"><code id="copy-value">${escape(result.Secret)}</code></div>${button('复制设置密钥','copy')}`+
            formField('6 位验证码','Code','','text','required pattern="[0-9]{6}" inputmode="numeric"'),async verify=>{
            const r=await mutate('security/totp-enable',{Password:password,Code:verify.get('Code')});
            openDialog('保存一次性恢复码',`<p>请离线保存。每个恢复码只能使用一次。</p><pre id="copy-value">${r.Recovery.map(escape).join('\n')}</pre>${button('复制恢复码','copy')}`);
          },'验证并启用');
        },'获取设置密钥');
      }
      break;
    case 'device':
    case 'devices':confirm('撤销管理会话？','相关浏览器需要重新登录。',()=>mutate('security/revoke',{Device:id}));break;
    case 'clear-filter':filter='';filterRegion='';render();break;
  }
}

function showError(message) {
  const inline=document.querySelector('dialog[open] .field-error') || $('#auth-form .field-error') || $('#settings-form .field-error');
  if (inline) inline.textContent=message;
  else openDialog('操作未完成',`<p role="alert">${escape(message)}</p>`);
}
document.addEventListener('click',async event=>{
  const el=event.target.closest('button,a');
  if (!el) return;
  const {nav,action:key,id,tab,value}=el.dataset;
  if (!nav&&!key&&!tab) return;
  event.preventDefault();
  try {
    if (nav) navigate(nav);
    if (tab) {
      const set=()=>{
        if (tab==='region') regionTab=value;
        if (tab==='access') accessTab=value;
        if (tab==='connection') connTab=value;
        if (tab==='event') eventTab=value;
        if (tab==='settings') settingsTab=value;
        filter='';filterRegion='';render();
      };
      if (settingsDirty) confirm('丢弃未保存的设置？','切换页签会丢弃本次修改。',()=>{settingsDirty=false;closeDialog();set();});
      else set();
    }
    if (key) await action(key,id,el);
  } catch(error) { showError(error.message); }
});
document.addEventListener('submit',async event=>{
  event.preventDefault();
  const form=event.target, id=form.getAttribute('id'), fd=new FormData(form);
  const submitter=event.submitter;
  if (submitter?.disabled) return;
  if (submitter) submitter.disabled=true;
  try {
    if (id==='auth-form') await submitAuth(fd);
    if (id==='dialog-form'&&dialogWork) await dialogWork(fd);
    if (id==='filter-form') {filter=fd.get('filter').trim();filterRegion=fd.get('region');render();}
    if (id==='settings-form') {
      const Config=Object.fromEntries(['MaxTunnels','ProbeSeconds','DrainSeconds','RetentionDays'].map(k=>[k,Number(fd.get(k))]));
      Config.LogTargets=fd.has('LogTargets');
      await api('config',{Config});
      settingsDirty=false;
      await refresh(true);
    }
  } catch(error) {showError(error.message);}
  finally {if (submitter)submitter.disabled=false;}
});
document.addEventListener('input',event=>{if(event.target.closest('#settings-form'))settingsDirty=true;});
window.addEventListener('popstate',()=>{
  const next=new URLSearchParams(location.search).get('view');
  if (pages[next]) {view=next;render();}
});
async function boot(){
  try {
    auth=await api('auth');
    if (!auth.Authenticated) {renderAuth();return;}
    await refresh(true);
    startStream();
  } catch(error) {
    $('#app').innerHTML=`<main class="content"><p class="notice">${escape(error.message)}</p>${button('重试','reload')}</main>`;
  }
}
boot();
