// Functional regression only: actual default Suggest.Init and shipped widget on loopback.
// Uses ordinary search names and storage fixtures; no executable or exploit reproduction inputs.
'use strict';
const {chromium}=require('playwright-core');
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../..'),sourceRoot=process.env.SUGGEST_HISTORY_SOURCE_ROOT||root;
const clients=['template/default/asset/js/public-home-stack.js','template/default/asset/js/user-home-stack.js'];
let checks=0;
function check(value,message){checks++;assert.ok(value,message);}
function method(file){
  const source=fs.readFileSync(path.join(sourceRoot,file),'utf8'),anchor=source.indexOf("'Suggest':"),start=source.indexOf('function',anchor);
  assert.ok(anchor>=0&&start>=0,'Missing Suggest.Init');
  for(let end=source.indexOf('}',start);end!==-1;end=source.indexOf('}',end+1)){
    const body=source.slice(start,end+1);
    try{new vm.Script('('+body+')');return body;}catch(error){if(!(error instanceof SyntaxError))throw error;}
  }
  throw new Error('Cannot extract actual Suggest.Init');
}
async function main(){
  let server,browser,active;const outside=[],errors=[];
  try{
    server=http.createServer((req,res)=>{
      const url=new URL(req.url,'http://127.0.0.1');res.setHeader('Cache-Control','no-store');
      if(url.pathname==='/jquery.js'||url.pathname==='/plugin.js'){
        res.setHeader('Content-Type','application/javascript');res.end(fs.readFileSync(path.join(root,url.pathname==='/jquery.js'?'template/default/asset/js/jquery.js':'static/js/jquery.autocomplete.js')));return;
      }
      if(url.pathname==='/page'){
        res.setHeader('Content-Type','text/html; charset=utf-8');
        res.end('<!doctype html><meta charset="utf-8"><input id="wd"><input id="other"><script src="/jquery.js"></script><script src="/plugin.js"></script><script>window.maccms={base_url:location.origin+"/subdir"};window.MAC={Suggest:{Init:'+method(clients[active.client])+'}};window.ready=true;</script>');return;
      }
      if(url.pathname==='/subdir/index.php/ajax/suggest'){
        active.requests.push(url.searchParams.get('wd'));res.setHeader('Content-Type','application/json');res.end(JSON.stringify(active.response));return;
      }
      if(url.pathname==='/subdir/search'){
        active.selected=url.searchParams.get('wd');res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>selected</title>');return;
      }
      res.statusCode=404;res.end('Not found');
    });
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const base='http://127.0.0.1:'+server.address().port;
    browser=await chromium.launch({executablePath:process.env.CHROMIUM_BINARY||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
    const context=await browser.newContext();
    await context.route('**/*',route=>{if(new URL(route.request().url()).origin!==base){outside.push(route.request().url());return route.abort();}return route.continue();});
    const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
    const literalName="中文 \"历史\" & snow 雪 %20 $&";
    async function setup(client,{keywords=['First hot','Second hot','Third hot','Fourth hot'],history='["Past word"]',response,storageFailure=false,other=false}={}){
      active={client,response:response===undefined?{code:1,site_keywords:keywords,url:'/subdir/search?wd=mac_wd&fixed=1'}:response,requests:[],selected:null};errors.length=0;
      await page.goto(base+'/page');await page.mouse.move(1000,800);await page.waitForFunction(()=>window.ready);
      await page.evaluate(({history,storageFailure,other})=>{
        localStorage.clear();if(history!==null)localStorage.setItem('historyList',history);
        localStorage.setItem('unrelated','keep');localStorage.setItem('mac_vod_search_history_v1','["Other header"]');
        if(storageFailure){Storage.prototype.getItem=function(){throw new DOMException('blocked','SecurityError');};Storage.prototype.removeItem=function(){throw new DOMException('blocked','SecurityError');};}
        window.selected=[];$('#wd').on('result',function(event,data,value){window.selected.push({name:data?.name,value:value,visible:this.value});});
        MAC.Suggest.Init('#wd',1,'');if(other)MAC.Suggest.Init('#other',1,'');
      },{history,storageFailure,other});
      await page.locator('#wd').focus();await page.locator('#wd').pressSequentially('query');
      await page.waitForFunction(()=>!document.querySelector('#wd').classList.contains('mac_loading'));
      for(let i=0;i<30&&active.requests.length===0;i++)await new Promise(resolve=>setTimeout(resolve,30));
      await new Promise(resolve=>setTimeout(resolve,150));
    }
    async function rows(){return page.locator('.mac_results:visible li').allTextContents();}
    for(let client=0;client<clients.length;client++){
      await setup(client,{keywords:[literalName,'Second hot','Third hot','Fourth hot'],history:JSON.stringify([literalName,'Past word'])});
      check((await rows()).length===8,'History/hot headings or valid rows missing');
      check((await rows())[1]===literalName&&(await rows())[4]===('1'+literalName),'Display changed raw name text');
      check(await page.locator('.row-index.active-index').count()===3&&await page.locator('.row-index').count()===4,'Hot numbering/top-three style changed');
      check(errors.length===0,'Valid plugin display emitted errors');
      await setup(client,{keywords:['query'],history:null});
      check(await page.evaluate(()=>{let result;$('#wd').search(x=>result=x);return result?.data.name==='query'&&result?.value==='query'&&result?.result==='query';}),'Actual autocomplete search contract lacks value/result');
      // A title row remains decorative; a real term bearing that same title remains selectable.
      await setup(client);await page.locator('.mac_results li').filter({hasText:'热门搜索'}).hover();await page.locator('.mac_results li').filter({hasText:'热门搜索'}).click();
      check(page.url()===base+'/page'&&await page.locator('#wd').inputValue()==='query','Selecting title navigated or replaced the typed query');
      await setup(client,{keywords:['历史搜索'],history:null});
      await page.locator('.mac_results li').last().hover();await Promise.all([page.waitForURL('**/subdir/search?**'),page.locator('.mac_results li').last().click()]);
      check(active.selected==='历史搜索','Real term matching heading text was disabled');
      for(const select of ['mouse','keyboard']){
        await setup(client,{keywords:[],history:JSON.stringify([literalName])});
        if(select==='mouse'){await page.locator('.mac_results li').nth(1).hover();await Promise.all([page.waitForURL('**/subdir/search?**'),page.locator('.mac_results li').nth(1).click()]);}
        else {await page.locator('#wd').press('ArrowDown');await page.locator('#wd').press('ArrowDown');await Promise.all([page.waitForURL('**/subdir/search?**'),page.locator('#wd').press('Enter')]);}
        check(active.selected===literalName&&new URL(page.url()).searchParams.get('fixed')==='1','Selected name was HTML encoded or URL query escaped incorrectly: '+select);
      }
      for(const clear of ['mouse','keyboard','space']){
        await setup(client);const before=active.requests.length;
        if(clear==='mouse'){await page.locator('.del-list').hover();await page.locator('.del-list').click();}
        else {await page.locator('.del-list').focus();await page.locator('.del-list').press(clear==='space'?'Space':'Enter');}
        await page.waitForFunction(()=>!document.querySelector('.del-list'));
        check(await page.evaluate(()=>localStorage.getItem('historyList')===null&&localStorage.getItem('unrelated')==='keep'&&localStorage.getItem('mac_vod_search_history_v1')==='["Other header"]'),'Clear removed unrelated history/settings or retained old history');
        check((await rows()).length===5&&active.requests.length>before&&page.url()===base+'/page','Clear failed to refresh actual cached plugin rows or navigated');
        await page.mouse.move(1000,800);await page.locator('#wd').press('Escape');await page.locator('#wd').press('ArrowDown');
        await page.waitForSelector('.mac_results:visible');await page.locator('#wd').press('ArrowDown');await page.locator('#wd').press('ArrowDown');
        await Promise.all([page.waitForURL('**/subdir/search?**'),page.locator('#wd').press('Enter')]);
        check(active.selected==='First hot','Keyboard plugin state broke after clearing history');
      }
      for(const history of ['{broken','{}','null','false','"word"','[null,[],{},5,false,"","Valid"]']){
        await setup(client,{history});check(errors.length===0&&(await rows()).includes('1First hot'),'Malformed history blocked hot suggestions');
        check(!(await rows()).some(x=>x.includes('[object Object]')),'History container became a string term');
      }
      await setup(client,{storageFailure:true});check(errors.length===0&&(await rows()).length===5,'Disabled localStorage blocked suggestions');
      for(const response of [null,[],{code:0},{code:1,site_keywords:{}},{code:1,site_keywords:[],url:''}]){
        await setup(client,{response,history:null});check(errors.length===0&&(await rows()).length===0,'Malformed response produced selectable suggestions');
      }
      await setup(client,{keywords:[null,[],{},5,false,'','Valid','\ud800','x'.repeat(4097)],history:null});check(errors.length===0&&JSON.stringify(await rows())===JSON.stringify(['热门搜索','1Valid']),'Invalid hot term container/Unicode was accepted');
      await setup(client,{history:JSON.stringify(['x'.repeat(65536)])});check(errors.length===0&&(await rows()).length===5,'Oversized stored JSON was not bounded');
      for(const url of [base+'/subdir/search?wd=mac_wd&fixed=1','//127.0.0.1:'+new URL(base).port+'/subdir/search?wd=mac_wd&fixed=1']){
        await setup(client,{response:{code:'1',site_keywords:['CJK 中文 & = #'],url},history:null});
        await page.locator('.mac_results li').last().hover();await Promise.all([page.waitForURL('**/subdir/search?**'),page.locator('.mac_results li').last().click()]);
        check(active.selected==='CJK 中文 & = #'&&new URL(page.url()).searchParams.get('fixed')==='1','Same-origin absolute/protocol-relative URL or string success code changed');
      }
      await setup(client,{history:JSON.stringify(Array.from({length:250},(_,i)=>'History '+i))});
      await page.evaluate(()=>$('#wd').setOptions({max:200}));await page.locator('#wd').press('Escape');await page.locator('#wd').press('ArrowDown');
      check(errors.length===0&&(await rows()).length===56,'History processing relies only on the plugin DOM maximum');
      await setup(client,{other:true});
      await page.locator('#other').focus();await page.locator('#other').pressSequentially('query');
      await page.waitForSelector('.mac_results:visible .del-list');await page.waitForTimeout(500);
      await page.locator('.mac_results:visible .del-list').hover();await page.locator('.mac_results:visible .del-list').click();
      await page.waitForFunction(()=>!Array.from(document.querySelectorAll('.mac_results')).filter(e=>getComputedStyle(e).display!=='none').some(e=>e.querySelector('.del-list')));
      check(await page.locator('#other').inputValue()==='query'&&await page.locator('#wd').inputValue()==='query','Clear selected the wrong input or title');
      await page.mouse.move(1000,800);await page.locator('#wd').focus();await page.waitForTimeout(250);await page.locator('#wd').press('Escape');await page.locator('#wd').press('ArrowDown');
      await page.waitForSelector('.mac_results:visible');check(!(await rows()).some(x=>x.includes('Past word')),'Another input replayed cleared cached history');
      console.log(clients[client]+': passed');
    }
    check(outside.length===0,'Suggestion attempted external navigation or a request');
    console.log('Default history suggestions: '+checks+' '+'checks passed');
  }finally{if(browser)await browser.close();if(server)await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
