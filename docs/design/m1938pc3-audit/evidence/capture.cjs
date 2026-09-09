const { chromium } = require('playwright');
const fs = require('fs');
const root = require('path').resolve(__dirname, '..');
(async () => {
  fs.mkdirSync(root + '/evidence', { recursive: true });
  const browser = await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
  const results = [];
  for (const width of [1440, 390]) {
    const context = await browser.newContext({viewport:{width,height:900},isMobile:width<600,deviceScaleFactor:1});
    const page = await context.newPage();
    const failures=[];
    page.on('pageerror',e=>failures.push(e.message));
    await page.route('**/*', route=> {
      const r=route.request();
      if (['image','media'].includes(r.resourceType()) || !r.url().startsWith('http://85.149.233.2/')) return route.abort();
      return route.continue();
    });
    await page.goto('http://85.149.233.2/',{waitUntil:'domcontentloaded',timeout:30000});
    await page.waitForTimeout(1500);
    const metrics=await page.evaluate(()=>{
      const measure=selector=>{const e=document.querySelector(selector);if(!e)return null;const r=e.getBoundingClientRect(),c=getComputedStyle(e);return {x:r.x,y:r.y,width:r.width,height:r.height,radius:c.borderRadius,shadow:c.boxShadow,padding:c.padding,fontSize:c.fontSize}};
      return {viewportMeta:document.querySelector('meta[name="viewport"]')?.content,innerWidth,clientWidth:document.documentElement.clientWidth,scrollWidth:document.documentElement.scrollWidth,scale:visualViewport?.scale,noticeCount:document.querySelectorAll('.notice-card').length,rowCount:document.querySelectorAll('.list .row').length,head:measure('.head'),nav:measure('.nav'),wrapper:measure('.wrapper-card'),notice:measure('.notice-card'),list:measure('.list'),header:measure('.list .title'),row:measure('.list .row .container'),firstCell:measure('.list .row li'),firstHeaderCell:measure('.list .title li'),loadedCss:[...document.styleSheets].map(s=>s.href).filter(Boolean)};
    });
    await page.evaluate(()=>{
      document.querySelectorAll('img').forEach(e=>{e.removeAttribute('src');e.removeAttribute('onerror');e.alt='';e.style.background='#dfe5eb'});
      document.querySelectorAll('.vod-name').forEach((e,i)=>e.textContent=`资源条目示例 ${String(i+1).padStart(2,'0')}`);
      document.querySelectorAll('.nav strong,.list .row li:nth-child(3)').forEach((e,i)=>e.textContent=`分类 ${i%8+1}`);
    });
    await page.screenshot({path:`${root}/evidence/before-${width}.png`,fullPage:false});
    results.push({width,metrics,pageErrors:failures,note:'线上首页；屏蔽图片、媒体与跨域请求，截图替换资源名称及分类，仅用于布局审计。'});
    await context.close();
  }
  fs.writeFileSync(root+'/evidence/baseline.json',JSON.stringify(results,null,2));
  console.log(JSON.stringify(results,null,2));
  await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
