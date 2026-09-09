const {chromium}=require('playwright');
const fs=require('fs');
const path=require('path');
const root=path.resolve(__dirname,'..');
const assert=(condition,message)=>{if(!condition)throw new Error(message)};
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'/usr/bin/chromium',args:['--no-sandbox']});
 const results=[];
 for(const width of [1440,1024,768,390,360]){
  const context=await browser.newContext({viewport:{width,height:1100},isMobile:width<600,deviceScaleFactor:1});
  const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('file://'+root+'/index.html');await page.evaluate(()=>document.fonts.ready);
  const measure=()=>page.evaluate(()=>({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,scale:visualViewport.scale,firstRowY:document.querySelector('#resource-rows tr').getBoundingClientRect().y,categories:document.querySelectorAll('.category-row').length,logoLoaded:document.querySelector('.logo img').naturalWidth>0}));
  const initial=await measure();assert(initial.scrollWidth===width,'Overflow '+width);assert(initial.scale===1,'Viewport scale');assert(initial.categories===7,'Preserved category rows');assert(initial.logoLoaded,'Original logo');
  await page.screenshot({path:root+`/evidence/home-${width}.png`,fullPage:width===390});
  if(width<700){await page.locator('#expand-services').click();assert(await page.locator('#copy-backup').isVisible(),'Mobile service expansion');assert(await page.locator('.updated time').first().evaluate(e=>e.getBoundingClientRect().height<25),'Mobile timestamp does not wrap')}
  await page.locator('#next').click();assert(await page.locator('#page-number').innerText()==='2','Pagination');await page.locator('#previous').click();
  await page.locator('[data-category="视频一区"]').click();assert(await page.locator('#resource-rows tr').count()===3,'Category filter');await page.locator('#clear-filter').click();
  await page.locator('#keyword').fill('长安');await page.locator('#search').evaluate(f=>f.requestSubmit());assert(await page.locator('#resource-rows tr').count()===1,'Search');
  await page.locator('#keyword').fill('zzzzzz999');await page.locator('#search').evaluate(f=>f.requestSubmit());assert(await page.locator('#empty').isVisible(),'No results');await page.locator('#reset').click();
  await page.locator('#sort').selectOption('old');assert((await page.locator('.resource-title').first().innerText()).includes('旅途'),'Sort');await page.locator('#sort').selectOption('new');
  await page.locator('#density').click();assert(await page.locator('#resources').evaluate(e=>e.classList.contains('compact')),'Density');await page.locator('#density').click();
  await page.locator('.resource-title').first().click();assert(await page.locator('#detail-dialog').isVisible(),'Detail');await page.keyboard.press('Escape');
  await page.locator('[data-format="XML"]').click();assert((await page.locator('#main-endpoint').innerText()).endsWith('/at/xml'),'XML');await page.locator('[data-format="JSON"]').click();
  await page.locator('#legacy-toggle').click();assert(await page.locator('#legacy').isVisible(),'Legacy disclosure');assert(await page.evaluate(()=>document.documentElement.scrollWidth===innerWidth),'Legacy overflow');await page.locator('#legacy-toggle').click();
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async()=>{throw new Error('Denied')}}}));await page.locator('#copy-main').click();assert(await page.locator('#copy-dialog').isVisible(),'Manual copy fallback');assert((await page.locator('#manual-copy').inputValue()).includes('json.xingba222.com'),'Correct address');await page.keyboard.press('Escape');
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>window.copied=text}}));await page.locator('#copy-backup').click();assert(await page.locator('#toast').isVisible(),'Copy toast');assert(await page.evaluate(()=>window.copied.includes('json.xgbbk8.com')),'Correct backup payload');
  if(width<700){await page.locator('.category-tabs button').last().click();assert(await page.locator('.category-row').last().isVisible(),'Mobile last tab');assert(await page.locator('.category-row:not([hidden])').count()===1,'One active tab panel');assert(await page.evaluate(()=>document.documentElement.scrollWidth===innerWidth),'Expanded category overflow')}
  assert(!errors.length,'JS errors');results.push({width,initial,checks:'Layout, original logo, seven category groups, pagination, category filter, search, empty/reset, sorting, density, detail, JSON/XML, legacy disclosure, copy success stub and rejected fallback',pageErrors:errors});
  await context.close();
 }
 await browser.close();fs.writeFileSync(root+'/evidence/verification.json',JSON.stringify(results,null,2));console.log(JSON.stringify(results,null,2));
})().catch(e=>{console.error(e);process.exit(1)});
