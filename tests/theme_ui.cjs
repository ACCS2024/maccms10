const {chromium}=require('playwright');
const fs=require('fs');
const path=require('path');
const assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const theme=root+'/template/m1938pc3_v2/assets/v2/';
const base=process.env.THEME_PREVIEW_URL||'';
const output=process.env.THEME_EVIDENCE_DIR||'/tmp/maccms-theme-v2-tests';
fs.mkdirSync(output,{recursive:true});
function group(name,values){return `<section class="address-group detail-section" data-address-group data-test-group="${name}"><div class="address-heading"><h2>${name}</h2><button data-reverse aria-pressed="false">倒序排列</button></div><div data-address-list>${values.map((value,i)=>`<div class="address-row" data-address-row><label class="address-select"><input type="checkbox" checked data-address-select></label><span class="episode-name">第 ${i+1} 集</span><input readonly data-address-value value="${value}"><a href="#">播放</a></div>`).join('')}</div><div class="address-actions"><label><input type="checkbox" checked data-select-all>全选</label><span data-selected-count></span><button data-copy-selected>复制已选地址</button></div></section>`}
const fixture=`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>${fs.readFileSync(theme+'theme.css','utf8')}</style></head><body class="zy-page"><main class="wrap"><section class="category-directory" data-category-directory data-current-parent="3"><div class="category-tabs"></div><div class="category-panels">${Array.from({length:7},(_,i)=>`<div class="category-row" id="category-panel-${i+1}" data-parent="${i+1}" data-name="分类 ${i+1}"><a class="category-parent" href="#"><span class="category-title">分类 ${i+1}</span><span class="category-all">全部</span></a><a href="#">子分类一</a><a href="#">子分类二</a></div>`).join('')}</div></section>${group('来源 A',['第1集$https://media.example.com/a1','第2集$https://media.example.com/a2','第3集$https://media.example.com/a3'])}${group('来源 B',['另一集$https://media.example.com/b1'])}</main><dialog id="copy-dialog"><button data-close-dialog>关闭</button><textarea id="manual-copy"></textarea><button id="select-copy">全选</button></dialog><div id="toast" hidden></div><script>${fs.readFileSync(theme+'theme.js','utf8')}</script></body></html>`;
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const results=[];
 for(const width of [1440,768,390,360]){
  const context=await browser.newContext({viewport:{width,height:1000},isMobile:width<600});
  const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.setContent(fixture);await page.evaluate(()=>document.fonts.ready);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth),width,'Fixture overflow');
  if(width<700){
   assert.equal(await page.locator('.category-row:not([hidden])').count(),1);
   assert.equal(await page.locator('[role=tab][aria-selected=true]').innerText(),'分类 3');
   await page.locator('[role=tab]').last().click();assert.equal(await page.locator('.category-row:not([hidden])').getAttribute('data-parent'),'7');
   await page.keyboard.press('Home');assert.equal(await page.locator('[role=tab][aria-selected=true]').innerText(),'分类 1');
   await page.keyboard.press('ArrowLeft');assert.equal(await page.locator('[role=tab][aria-selected=true]').innerText(),'分类 7');
   await page.setViewportSize({width:1000,height:1000});await page.waitForFunction(()=>document.querySelectorAll('.category-row:not([hidden])').length===7);assert.equal(await page.locator('.category-row:not([hidden])').count(),7,'Desktop panels restored');
   await page.setViewportSize({width,height:1000});await page.waitForFunction(()=>document.querySelectorAll('.category-row:not([hidden])').length===1);assert.equal(await page.locator('.category-row:not([hidden])').count(),1);
  }else{assert.equal(await page.locator('.category-row:not([hidden])').count(),7)}
  await page.evaluate(()=>{Object.defineProperty(window,'isSecureContext',{configurable:true,value:true});Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>window.copied=text}})});
  const a=page.locator('[data-test-group="来源 A"]'),b=page.locator('[data-test-group="来源 B"]');
  await a.locator('[data-address-select]').nth(1).uncheck();await a.locator('[data-copy-selected]').click();
  assert.equal(await page.evaluate(()=>window.copied),'第1集$https://media.example.com/a1\n第3集$https://media.example.com/a3','Selected addresses and group isolation');
  assert(await a.locator('[data-select-all]').evaluate(e=>e.indeterminate));
  await a.locator('[data-reverse]').click();await a.locator('[data-copy-selected]').click();
  assert.equal(await page.evaluate(()=>window.copied),'第3集$https://media.example.com/a3\n第1集$https://media.example.com/a1','Copy follows display order');
  await b.locator('[data-copy-selected]').click();assert.equal(await page.evaluate(()=>window.copied),'另一集$https://media.example.com/b1');
  await a.locator('[data-select-all]').check();await a.locator('[data-select-all]').uncheck();await a.locator('[data-copy-selected]').click();assert((await page.locator('#toast').innerText()).includes('请先选择'));
  await page.evaluate(()=>{navigator.clipboard.writeText=async()=>{throw new Error('Denied')};document.execCommand=()=>false});
  await b.locator('[data-copy-selected]').click();assert(await page.locator('#copy-dialog').isVisible());assert.equal(await page.locator('#manual-copy').inputValue(),'另一集$https://media.example.com/b1');await page.keyboard.press('Escape');
  assert.deepEqual(errors,[]);results.push({width,fixture:'pass',checks:['current parent selection','horizontal tabs and keyboard','resize restores desktop categories','no overflow','copy selected per source','reversed copy order','tri-state select all','empty selection','clipboard denial fallback']});
  await context.close();
 }
 if(base){
  for(const width of [1440,390,360]){
   const context=await browser.newContext({viewport:{width,height:1100},isMobile:width<600});
   const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
   await page.route('**/*',route=>{const request=route.request(),url=request.url();if(request.resourceType()==='media'||request.resourceType()==='image'&&!url.includes('/image/logo.gif')||new URL(url).origin!==new URL(base).origin)return route.abort();return route.continue()});
   const response=await page.goto(base,{waitUntil:'domcontentloaded',timeout:60000});assert.equal(response.status(),200);await page.evaluate(()=>document.fonts.ready);
   assert.equal(await page.locator('.resource-table tbody tr').count(),70);assert.equal(await page.locator('.category-row').count(),7);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth),width,'Live home overflow');
   if(width<700){assert.equal(await page.locator('.category-row:not([hidden])').count(),1);const lastParent=await page.locator('.category-row').last().getAttribute('data-parent');await page.locator('[role=tab]').last().click();assert.equal(await page.locator('.category-row:not([hidden])').getAttribute('data-parent'),lastParent);await page.locator('[role=tab]').first().click()}
   const detail=await page.locator('.resource-title').first().getAttribute('href');
   const firstId=detail.match(/\d+(?=\.html)/)?.[0];
   const metric=await page.evaluate(()=>({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,firstRowY:document.querySelector('.resource-table tbody tr').getBoundingClientRect().y,tabsWidth:document.querySelector('.category-tabs').clientWidth,tabsScroll:document.querySelector('.category-tabs').scrollWidth}));
   // Screenshots retain actual structure but omit content artwork and resource names.
   await page.evaluate(()=>{document.querySelectorAll('.resource-title').forEach((e,i)=>e.textContent='资源条目 '+(i+1));document.querySelectorAll('.category-row>a:not(.category-parent),.type-text a,.resource-subtitle span:nth-child(2)').forEach((e,i)=>e.textContent='分类 '+(i%7+1));document.querySelectorAll('img:not(.logo img)').forEach(e=>{e.alt='';e.style.opacity='0'})});
   await page.screenshot({path:output+`/live-home-${width}.png`});
   await page.goto(new URL(detail,base).href,{waitUntil:'domcontentloaded',timeout:60000});assert(await page.locator('.detail-summary').isVisible());
   assert(await page.locator('[data-address-group]').count()>0);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth),width,'Live detail overflow');
   assert.equal(await page.evaluate(()=>{const ids=[...document.querySelectorAll('[id]')].map(e=>e.id);return ids.length-new Set(ids).size}),0,'Duplicate IDs');
   if(width<700){const currentParent=await page.locator('[data-category-directory]').getAttribute('data-current-parent');assert.equal(await page.locator('[role=tab][aria-selected=true]').getAttribute('id'),'category-tab-'+currentParent)}
   assert.deepEqual(errors,[]);results.push({width,live:'pass',firstId,metric,detailGroups:await page.locator('[data-address-group]').count()});await context.close();
  }
 }
 await browser.close();fs.writeFileSync(output+'/verification.json',JSON.stringify(results,null,2));console.log(JSON.stringify(results,null,2));
})().catch(e=>{console.error(e);process.exit(1)});
