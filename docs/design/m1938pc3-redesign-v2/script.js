const categories = [
  ['视频一区','日韩精选','国产原创','精品影片','欧美影片','动漫专区','独立短片','经典影片'],
  ['视频二区','热播精选','最新上线','系列合集','原创作品','人气推荐','专题收录','高清修复'],
  ['视频三区','中文字幕','经典系列','都市故事','家庭生活','明星作品','悬疑剧情','影视解说'],
  ['视频四区','热门资讯','旅行见闻','直播回顾','日常记录','人物访谈','生活方式','文化纪实'],
  ['视频五区','户外旅行','运动专题','亲情故事','女性视角','校园生活','每日推荐','短片精选'],
  ['小说专区','都市小说','校园故事','生活随笔','国风故事','情感故事','玄幻仙侠','连载小说'],
  ['图片专区','唯美写真','网友摄影','自然风光','街拍纪实','服饰搭配','卡通漫画','欧美风情']
];
const sampleTitles = ['长安三万里','宇宙探索编辑部','漫长的季节 第01集','人生大事','山海情 第01集','我在故宫修文物','流浪地球2','平原上的摩西 第01集','隐入尘烟','雄狮少年','爱情神话','中国奇谭 第01集','河西走廊 第01集','无名','装腔启示录 第01集','风味人间 第01集','城市与建筑 · 摄影集','旅途手记 · 连载一'];
const data = sampleTitles.map((name, i) => ({id:112582-i, name, type:categories[i%7][1+(i%7)], parent:categories[i%7][0], short:name.replace(/ 第.*| ·.*/g,'').slice(0,4), date:i<10?'09-09':'09-08', time:String(11-Math.floor(i/2)).padStart(2,'0')+':'+(i%2?'12':'38'), quality:i%3===0?'1080P':'高清', order:i}));
const endpoints = {
  JSON:['https://json.xingba222.com/api.php/provide/vod/','https://json.xgbbk8.com/api.php/provide/vod/'],
  XML:['https://xingba222.com/api.php/provide/vod/at/xml','https://api.xgbbk8.com/api.php/provide/vod/at/xml']
};
let selectedCategory='', searchTerm='', currentPage=1, format='JSON', toastTimer;
const pageSize=10;
const $=id=>document.getElementById(id);
function drawCategories(){
  categories.forEach((row,rowIndex)=>{
    const div=document.createElement('div');div.className='category-row';div.id='category-panel-'+rowIndex;div.dataset.parent=String(rowIndex);div.dataset.name=row[0];
    row.forEach((text,i)=>{const button=document.createElement('button');button.textContent=text;button.dataset.category=text;button.setAttribute('aria-pressed','false');if(!i)button.className='category-parent';div.append(button)});
    $('category-rows').append(div);
  });
  for(let i=1;i<=9;i++){const button=document.createElement('button');button.textContent=`sex8zy${i}.com`;button.dataset.copy=button.textContent;button.setAttribute('aria-label','复制镜像地址 '+button.textContent);$('mirrors').append(button)}
}
function drawEndpoints(){
  $('main-endpoint').textContent=endpoints[format][0];$('backup-endpoint').textContent=endpoints[format][1];
  $('main-endpoint').title=endpoints[format][0];$('backup-endpoint').title=endpoints[format][1];
  document.querySelectorAll('[data-format]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.format===format)));
}
function render(){
  let list=data.filter(x=>(!selectedCategory||x.type===selectedCategory||x.parent===selectedCategory)&&(!searchTerm||(x.name+' '+x.id).toLowerCase().includes(searchTerm.toLowerCase())));
  const sorting=$('sort').value;list.sort((a,b)=>sorting==='old'?b.order-a.order:sorting==='name'?a.name.localeCompare(b.name,'zh'):a.order-b.order);
  const pages=Math.max(1,Math.ceil(list.length/pageSize));currentPage=Math.min(currentPage,pages);
  const rows=$('resource-rows');rows.replaceChildren();
  list.slice((currentPage-1)*pageSize,currentPage*pageSize).forEach(item=>{
    const row=document.createElement('tr');
    row.innerHTML=`<td><div class="cover tone-${item.order%5}" aria-hidden="true"><span>${item.short}</span><small>${item.quality}</small></div></td><td><div class="title-line"><button class="resource-title" data-resource="${item.id}">${item.name}</button>${item.order<3?'<span class="new-label">NEW</span>':''}</div><div class="resource-subtitle"><span>编号 ${item.id}</span><span>${item.parent}</span><span>${item.quality}</span></div></td><td class="type-text">${item.type}</td><td class="updated"><time datetime="2026-${item.date}">${item.date}</time><small>${item.time}</small></td>`;
    rows.append(row);
  });
  $('empty').hidden=!!list.length;$('previous').disabled=currentPage===1;$('next').disabled=currentPage===pages;$('page-number').textContent=currentPage;
  $('result-count').textContent=`共 ${list.length} 条展示资源 · 第 ${currentPage} / ${pages} 页`;
  $('resource-title').textContent=searchTerm?'搜索结果':'最近更新';$('filter-label').textContent=selectedCategory||'全部资源';$('clear-filter').hidden=!selectedCategory&&!searchTerm;
  document.querySelectorAll('[data-category]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.category===selectedCategory)));
}
function reset(){selectedCategory='';searchTerm='';currentPage=1;$('keyword').value='';render()}
function toast(text){clearTimeout(toastTimer);$('toast').textContent=text;$('toast').hidden=false;toastTimer=setTimeout(()=>$('toast').hidden=true,2000)}
async function copy(text){
  try{if(!navigator.clipboard)throw new Error('No clipboard');await navigator.clipboard.writeText(text);toast('地址已复制')}
  catch(e){$('manual-copy').value=text;if(!$('copy-dialog').open)$('copy-dialog').showModal();$('manual-copy').select()}
}
function show(title,html){$('dialog-title').textContent=title;$('dialog-content').innerHTML=html;$('detail-dialog').showModal()}
function help(title){
  const bodies={
    '采集教程':'<p>原站的采集教程入口保留在主导航中。选择相应格式，复制首页接口地址，再在 MACCMS 后台完成采集来源和分类绑定。</p><ul><li>选择 JSON 或 XML 格式</li><li>填写采集地址与播放器标识</li><li>绑定分类并测试少量资源</li></ul>',
    '采集帮助':'<p>采集地址和播放器标识均保留在首页。主接口不可用时，可按原站说明检查备用接口；切换地址前先检查网络和格式配置。</p>',
    'TG交流群':'<p>保留原站交流群入口。</p><p><a href="https://t.me/xbxbxbzy" target="_blank" rel="noopener noreferrer">前往原站 TG 交流群 ↗</a></p>',
    'TG频道':'<p>保留原站频道入口，上线时沿用已有链接配置。</p>',
    '播放加载失败':'<p>请先检查网络和播放器配置。生产接入后，此入口应连接原有故障教程与报错流程。</p>',
    '播放器下载':'<p>播放器标识：<strong>s8m3u8</strong></p><p><a href="https://xingba111.com/template/help/bfq/mac_sex8zy.zip" target="_blank" rel="noopener noreferrer">打开原站播放器下载链接 ↗</a></p><p>该链接沿用原站公开配置，本次未验证下载包。</p>',
    '站点公告':'<p>这里保留原站的站点说明、采集提醒和服务承诺入口。首页展示与使用直接相关的信息，较长说明点击后查看。</p><p>图片采集后建议保存到本地。永久域名、九个镜像地址与主备用接口仍可从首页找到。</p>',
    '域名替换教程':'<p>原站更新时间：2026-08-26。</p><p><a href="https://sex8zy1.com/1.html" target="_blank" rel="noopener noreferrer">查看原站播放域名 / 图片域名替换教程 ↗</a></p>',
    '联系我们':'<p>上线时沿用 MACCMS 后台已有的联系信息配置，不新增或编造联系方式。</p>'
  };
  show(title,bodies[title]||'<p>此入口将沿用原站配置。</p>');
}
document.addEventListener('click',event=>{
  const button=event.target.closest('button');if(!button)return;
  if(button.dataset.category){selectedCategory=selectedCategory===button.dataset.category?'':button.dataset.category;currentPage=1;render();$('resources').scrollIntoView({block:'start'})}
  if(button.dataset.format){format=button.dataset.format;drawEndpoints()}
  if(button.dataset.copy)copy(button.dataset.copy);
  if(button.dataset.help)help(button.dataset.help);
  if(button.classList.contains('close'))button.closest('dialog').close();
  if(button.dataset.resource){const item=data.find(x=>String(x.id)===button.dataset.resource);show(item.name,`<div class="detail-meta"><span>编号 ${item.id}</span><span>${item.parent}</span><span>${item.quality}</span></div><p>此条目用于展示原站资源列表与详情的衔接。正式接入后沿用原有详情链接、影片资料、播放来源和批量复制功能。</p><p>本预览不提供影片播放或采集。</p>`)}
});
$('search').addEventListener('submit',event=>{event.preventDefault();searchTerm=$('keyword').value.trim();currentPage=1;render();$('resources').scrollIntoView({block:'start'})});
$('keyword').addEventListener('search',()=>{if(!$('keyword').value){searchTerm='';currentPage=1;render()}});
$('sort').onchange=()=>{currentPage=1;render()};$('reset').onclick=reset;$('clear-filter').onclick=reset;
$('previous').onclick=()=>{currentPage--;render()};$('next').onclick=()=>{currentPage++;render()};
$('copy-main').onclick=()=>copy(endpoints[format][0]);$('copy-backup').onclick=()=>copy(endpoints[format][1]);
$('select-copy').onclick=()=>{$('manual-copy').focus();$('manual-copy').select()};
$('legacy-toggle').onclick=()=>{const open=$('legacy').hidden;$('legacy').hidden=!open;$('legacy-toggle').setAttribute('aria-expanded',String(open))};
$('density').onclick=()=>{const on=$('density').getAttribute('aria-pressed')!=='true';$('density').setAttribute('aria-pressed',String(on));$('resources').classList.toggle('compact',on)};
$('expand-services').onclick=()=>{const open=$('expand-services').getAttribute('aria-expanded')!=='true';$('expand-services').setAttribute('aria-expanded',String(open));$('interfaces').classList.toggle('expanded',open);$('expand-services').innerHTML=open?'收起接口与公告 <span aria-hidden="true">⌃</span>':'展开全部接口与公告 <span aria-hidden="true">⌄</span>'};
drawCategories();drawEndpoints();render();
  function setupCategories(directory) {
    const panels = [...directory.querySelectorAll('.category-row')];
    const bar = directory.querySelector('.category-tabs');
    if (!panels.length || !bar) return;
    let active = Math.max(0, panels.findIndex(panel => panel.dataset.parent === directory.dataset.currentParent));
    const media = window.matchMedia('(max-width: 700px)');
    const tabs = panels.map((panel, index) => {
      const button = document.createElement('button');
      button.type = 'button'; button.textContent = panel.dataset.name;
      button.id = 'category-tab-' + panel.dataset.parent;
      button.setAttribute('role', 'tab'); button.setAttribute('aria-controls', panel.id);
      button.addEventListener('click', () => select(index, true));
      button.addEventListener('keydown', event => {
        let next = index;
        if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
        else if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = tabs.length - 1;
        else return;
        event.preventDefault(); select(next, true); tabs[next].focus({preventScroll:true});
      });
      bar.append(button); return button;
    });
    function select(index, reveal) {
      active = index;
      tabs.forEach((tab, i) => { tab.setAttribute('aria-selected', String(i === active)); tab.tabIndex = i === active ? 0 : -1; });
      panels.forEach((panel, i) => {
        panel.hidden = media.matches && i !== active;
        if (media.matches) { panel.setAttribute('role', 'tabpanel'); panel.setAttribute('aria-labelledby', tabs[i].id); }
        else { panel.removeAttribute('role'); panel.removeAttribute('aria-labelledby'); }
      });
      if (media.matches && reveal) {
        const selected = tabs[active];
        const left = selected.offsetLeft - bar.offsetLeft - (bar.clientWidth - selected.offsetWidth) / 2;
        bar.scrollTo({left, behavior:'auto'});
      }
    }
    bar.setAttribute('role', 'tablist'); bar.setAttribute('aria-orientation', 'horizontal');
    directory.classList.add('has-tabs');
    media.addEventListener('change', () => select(active, true));
    select(active, true);
  }
  document.querySelectorAll('[data-category-directory]').forEach(setupCategories);

