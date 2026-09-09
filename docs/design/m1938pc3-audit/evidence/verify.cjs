const {chromium}=require('playwright');
const fs=require('fs');
const root=require('path').resolve(__dirname, '..');
const assert=(value,message)=>{if(!value)throw new Error(message)};
(async()=>{
 const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const results=[];
 for(const width of [1440,768,390,360]){
  const context=await browser.newContext({viewport:{width,height:900},isMobile:width<600,deviceScaleFactor:1});
  const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('file://'+root+'/prototype.html');await page.evaluate(()=>document.fonts.ready);
  const measure=()=>page.evaluate(()=>({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,firstRowY:document.querySelector('#rows tr')?.getBoundingClientRect().y,firstRowHeight:document.querySelector('#rows tr')?.getBoundingClientRect().height,rowCount:document.querySelectorAll('#rows tr').length,scale:visualViewport.scale}));
  const metrics=await measure();assert(metrics.scrollWidth===width,'Catalog overflow at '+width);assert(metrics.scale===1,'Unexpected scale');
  await page.screenshot({path:root+`/evidence/after-${width}.png`,fullPage:width===390});
  await page.locator('#next').click();assert((await page.locator('#page-number').innerText())==='2','Pagination');await page.locator('#prev').click();
  await page.locator('[data-category="文章"]').click();assert(await page.locator('#rows tr').count()===3,'Category filtering');
  await page.locator('[data-category="全部"]').click();await page.locator('#query').fill('城市');await page.locator('#search-form').evaluate(f=>f.requestSubmit());assert(await page.locator('#rows tr').count()===1,'Search match');
  await page.locator('#query').fill('no-such-item-999');await page.locator('#search-form').evaluate(f=>f.requestSubmit());assert(await page.locator('#empty').isVisible(),'Empty state');await page.locator('#reset').click();
  await page.locator('#sort').selectOption('old');assert((await page.locator('.resource-title').first().innerText()).includes('山野'),'Sort');await page.locator('#sort').selectOption('new');
  await page.locator('.resource-title').first().click();assert(await page.locator('#detail-dialog').isVisible(),'Detail dialog');await page.keyboard.press('Escape');assert(!await page.locator('#detail-dialog').isVisible(),'Escape close');
  await page.locator('.nav-button[data-view="api"]').click();assert(await page.locator('#view-api').isVisible(),'API view');
  assert(await page.evaluate(()=>document.documentElement.scrollWidth===innerWidth),'API overflow');
  await page.locator('summary').first().click();assert(await page.locator('[data-copy^="https://backup"]').isVisible(),'Disclosure');
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async()=>{throw new Error('denied')}}}));
  await page.locator('[data-copy]').first().click();assert(await page.locator('#copy-dialog').isVisible(),'Clipboard fallback');assert((await page.locator('#manual-copy').inputValue()).startsWith('https://api.example.com/'),'Fallback content');await page.keyboard.press('Escape');
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>window.copiedText=text}}));await page.locator('[data-copy]').first().click();assert(await page.locator('#toast').isVisible(),'Copy feedback');assert(await page.evaluate(()=>window.copiedText==='https://api.example.com/api.php/provide/vod/'),'Copy payload');
  if(width===1440)await page.screenshot({path:root+'/evidence/api-1440.png'});
  await page.locator('.nav-button[data-view="docs"]').click();assert(await page.locator('#view-docs').isVisible(),'Docs view');assert(await page.evaluate(()=>document.documentElement.scrollWidth===innerWidth),'Docs overflow');
  assert(!errors.length,'Console errors: '+errors.join(','));results.push({width,metrics,checks:['no horizontal overflow across three views','scale 1','pagination','category filter','search','empty and reset','sort','detail dialog and Escape','view navigation','disclosure','copy rejection fallback','copy success with stub'],pageErrors:errors});await context.close();
 }
 await browser.close();fs.writeFileSync(root+'/evidence/verification.json',JSON.stringify(results,null,2));console.log(JSON.stringify(results,null,2));
})().catch(e=>{console.error(e);process.exit(1)});
