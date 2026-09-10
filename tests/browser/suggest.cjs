// Real shipped autocomplete and jQuery, isolated loopback responses; names are plain text.
'use strict';
const {chromium}=require('playwright-core');
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const root=process.env.SUGGEST_AUDIT_ROOT||path.resolve(__dirname,'../..');
const clients=['static/js/home.js','static_new/js/home.js','template/m1938pc3_v2/js/home.js','template/vozy/tuo/assets/mac.js'];
const plugins=['static/js/jquery.autocomplete.js','static_new/js/jquery.autocomplete.js','template/m1938pc3_v2/js/jquery.autocomplete.js','static/js/jquery.autocomplete.js'];
const reproduce=process.argv.includes('--reproduce');let checks=0;
function check(value,message){checks++;assert.ok(value,message);}
function method(file){
    const text=fs.readFileSync(path.join(root,file),'utf8'),anchor=text.indexOf("'Suggest':"),start=text.indexOf('function',anchor);
    assert.ok(anchor>=0&&start>=0);
    for(let end=text.indexOf('}',start);end!==-1;end=text.indexOf('}',end+1)){
        const source=text.slice(start,end+1);
        try{new vm.Script('('+source+')');return source;}catch(error){if(!(error instanceof SyntaxError))throw error;}
    }
    throw new Error('Cannot extract shipped Suggest.Init: '+file);
}
async function main(){
    let server,browser;const runs=new Map(),outside=[],errors=[];let sequence=0;
    try{
        server=http.createServer((req,res)=>{
            const url=new URL(req.url,'http://127.0.0.1');
            res.setHeader('Cache-Control','no-store');
            if(url.pathname==='/jquery.js'||url.pathname==='/plugin.js'){
                res.setHeader('Content-Type','application/javascript');
                res.end(fs.readFileSync(path.join(root,url.pathname==='/jquery.js'?'static/js/jquery.js':plugins[Number(url.searchParams.get('client'))])));return;
            }
            if(url.pathname==='/page'){
                const id=url.searchParams.get('run'),run=runs.get(id),index=run.client;
                res.setHeader('Set-Cookie','suggest_run='+id+'; Path=/; SameSite=Lax; HttpOnly');
                res.setHeader('Content-Type','text/html; charset=utf-8');
                res.end('<!doctype html><meta charset="utf-8"><input id="wd" name="wd"><script src="/jquery.js"></script><script src="/plugin.js?client='+index+'"></script><script>'+
                    'window.maccms={path:'+JSON.stringify(run.prefix)+'};window.MAC={Suggest:{Init:'+method(clients[index])+'}};'+
                    '$((function(){ $("#wd").on("result",function(event,data,formatted){sessionStorage.setItem("suggest_selected",JSON.stringify({value:$(this).val(),formatted:formatted,name:data.name}))}); MAC.Suggest.Init("#wd",1);window.ready=true; }));</script>');return;
            }
            const id=(req.headers.cookie||'').match(/(?:^|; )suggest_run=([^;]+)/)?.[1],run=runs.get(id);
            if(run&&url.pathname===run.prefix+'/index.php/ajax/suggest'){
                run.requests.push(req.url);res.setHeader('Content-Type','application/json');res.end(JSON.stringify(run.response));return;
            }
            if(run&&url.pathname===run.prefix+'/search'){
                run.selected=url.searchParams.get('wd');res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>selected</title>');return;
            }
            res.statusCode=404;res.end('Not found');
        });
        await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const base='http://127.0.0.1:'+server.address().port;
        browser=await chromium.launch({executablePath:process.env.CHROMIUM_BINARY||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
        const context=await browser.newContext();await context.route('**/*',route=>{
            if(new URL(route.request().url()).origin!==base){outside.push(route.request().url());return route.abort();}return route.continue();
        });
        const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
        async function open(client,response,prefix='/site',maxDisplay=null){
            const id=String(++sequence),run={client,prefix,response,requests:[]};runs.set(id,run);
            await page.goto(base+'/page?run='+id);await page.waitForFunction(()=>window.ready===true);
            await page.evaluate(max=>{sessionStorage.removeItem('suggest_selected');if(max!==null)$('#wd').setOptions({max:max});},maxDisplay);
            const received=page.waitForResponse(r=>new URL(r.url()).pathname===prefix+'/index.php/ajax/suggest');
            await page.locator('#wd').pressSequentially('needle',{delay:5});await (await received).finished();
            await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));return run;
        }
        for(let client=0;client<clients.length;client++){
            const name='needle <span data-audit-suggest="marker">literal</span> & "雪" \' %20 $&',response={code:1,list:[{id:7,name}],url:'/site/search?wd=mac_wd'};
            let run=await open(client,response);await page.waitForSelector('.mac_results li');
            if(reproduce){
                check(await page.locator('[data-audit-suggest="marker"]').count()===1,'Original name reaches real HTML parser: '+clients[client]);
                await Promise.all([page.waitForURL(base+'/site/search?*'),page.locator('#wd').press('Enter')]);
                const event=JSON.parse(await page.evaluate(()=>sessionStorage.getItem('suggest_selected')));
                check(event.value!==name&&event.name===name&&!Object.hasOwn(event,'formatted'),'Original custom parse lacks actual selected value/result: '+clients[client]);
                continue;
            }
            check(await page.locator('[data-audit-suggest="marker"]').count()===0,'Name cannot create HTML nodes: '+clients[client]);
            check(await page.locator('.mac_results li').textContent()===name,'Escaped display retains literal Unicode, entities and markup');
            check(await page.locator('.mac_results li strong').first().textContent()==='needle','Normal matching is still highlighted');
            await Promise.all([page.waitForURL(base+'/site/search?*'),page.locator('#wd').press('Enter')]);
            const event=JSON.parse(await page.evaluate(()=>sessionStorage.getItem('suggest_selected')));
            check(event.value===name&&event.formatted===name&&event.name===name,'Keyboard selection publishes raw name before result callbacks');
            check(run.selected===name,'Search receives one correctly encoded raw name, without substitution corruption');
            run=await open(client,{code:'1',list:[{id:1,name:'needle first'},{id:2,name:'needle 第二'}],url:'/search?wd=mac_wd'},'');
            await page.waitForSelector('.mac_results li:nth-child(2)');
            await Promise.all([page.waitForURL(base+'/search?*'),page.locator('.mac_results li').nth(1).click()]);
            check(run.selected==='needle 第二','Mouse selection and root installation still work');
            for(const response of [null,{},[],{code:0},{code:1},{code:1,list:{}},{code:1,list:null},
                ...['','javascript:alert(1)','https://foreign.invalid/search?wd=mac_wd','//foreign.invalid/search?wd=mac_wd','/search?fixed=1',base.replace('http://','http://name:password@')+'/search?wd=mac_wd'].map(url=>({code:1,list:[{name:'needle'}],url}))]){
                await open(client,response);
                check(await page.locator('.mac_results li').count()===0,'Malformed/failed response or unsafe destination has no selectable entries');
            }
            run=await open(client,{code:1,url:'/site/search?wd=mac_wd',list:[null,{},[],{name:null},{name:7},{name:''},{name:'\ud800'},{name:'x'.repeat(4097)},{name:'needle valid'}]});
            await page.waitForSelector('.mac_results li');
            check(await page.locator('.mac_results li').count()===1,'Malformed rows are skipped without breaking valid rows');
            await open(client,{code:1,url:'/site/search?wd=mac_wd',list:Array.from({length:70},(_,i)=>({name:'needle '+i}))},'/site',100);
            await page.waitForSelector('.mac_results li');
            check(await page.locator('.mac_results li').count()===50,'Response entries have a bounded display budget');
            console.log('Shipped autocomplete passed: '+clients[client]);
        }
        check(outside.length===0,'Fixture sends no request outside its loopback origin');
        check(errors.length===0,'Real autocomplete raises no browser errors: '+errors.join('; '));
        console.log('Suggestion Chromium '+(reproduce?'original reproduction':'audit')+' passed ('+checks+' checks)');
    }finally{if(browser)await browser.close();if(server)await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
