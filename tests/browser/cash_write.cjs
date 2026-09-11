'use strict';
// Actual shipped clients and jQuery in Chromium. The HTTP fixture records ordinary local requests only.
const {chromium}=require('playwright-core');
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../..');
let checks=0;
function check(condition,message){checks++;assert.ok(condition,message);}
async function main(){
    let server,browser;const runs=new Map();
    try{
        const legacy=fs.readFileSync(path.join(root,'template/m1938pc3_v2/html9/user/cash.html'),'utf8');
        const legacyScript=legacy.slice(legacy.lastIndexOf('<script>')+8,legacy.lastIndexOf('</script>'))
            .replace(/\{:url\('user\/([^']+)'\)\}/g,'/fixture/index.php/user/$1')
            .replace(/\{\$maccms.path\}/g,'/fixture/').replace(/\{\$obj.user_id\}/g,'1');
        server=http.createServer(async(req,res)=>{
            const url=new URL(req.url,'http://127.0.0.1');
            const assets={'/jquery.js':'static/js/jquery.js','/cash-write.js':'static/js/cash-write.js',
                '/utils.js':'template/default/asset/js/mac-member-list-utils.js','/user-cash.js':'template/default/asset/js/user-cash.js'};
            if(assets[url.pathname]){res.setHeader('Content-Type','application/javascript');res.end(fs.readFileSync(path.join(root,assets[url.pathname])));return;}
            if(url.pathname==='/fixture/page'){
                const id=url.searchParams.get('run');
                if(!runs.has(id))runs.set(id,{mode:url.searchParams.get('mode'),requests:[],posts:0,tokens:0,keys:[]});
                res.setHeader('Set-Cookie','cash_run='+id+'; HttpOnly; SameSite=Lax; Path=/');
                res.setHeader('Content-Type','text/html; charset=utf-8');
                const client=url.searchParams.get('client');
                const markup='<div id="mac-user-cash-root" data-cash-storage-key="/fixture/cash-request-1" data-api-base="/fixture/api.php" data-write-token-url="/fixture/index.php/user/write_token">'+
                    '<form id="fm">'+['cash_bank_name','cash_bank_no','cash_payee_name','cash_money'].map(key=>'<input name="'+key+'" value="'+(key==='cash_money'?'0.29':'Ordinary+%20')+'">').join('')+
                    '<input type="button" id="btn_submit" value="Submit"></form><div class="label-item" data-step="2"></div><div data-mac-cash-list></div><div data-mac-cash-page></div></div>';
                res.end('<!doctype html><meta charset="utf-8">'+markup+'<script src="/jquery.js"></script><script src="/cash-write.js"></script><script>'+
                    'window.messages=[];window.alert=function(text){messages.push(text)};window.confirm=function(){return true};window.MAC={alert:alert,GetLang:function(key){return key},CheckBox:{Ids:function(){return "1"}}};'+
                    '</script><script src="/utils.js"></script>'+(client==='default'?'<script src="/user-cash.js"></script>':'<script>'+legacyScript+'</script>')+
                    '<script>$(function(){window.ready=true})</script>');return;
            }
            const id=(req.headers.cookie||'').match(/(?:^|; )cash_run=([^;]+)/)?.[1],run=runs.get(id);
            if(!run){res.statusCode=404;res.end();return;}
            let body='';for await(const chunk of req)body+=chunk;
            run.requests.push({url:req.url,method:req.method,body});
            res.setHeader('Content-Type','application/json');
            if(url.pathname==='/fixture/index.php/user/write_token'){
                run.tokens++;check(req.method==='GET'&&!body,'CSRF token must be fetched by GET before submission');
                if(run.mode==='token-failure'&&run.tokens===1){res.statusCode=503;res.end('{}');return;}
                setTimeout(()=>res.end(JSON.stringify({code:1,info:{csrf_token:'ordinary-session-token'}})),25);return;
            }
            if(url.pathname.endsWith('/cash/get_list')){res.end(JSON.stringify({code:1,info:{list:[],page:1,pagecount:1}}));return;}
            run.posts++;
            const form=new URLSearchParams(body);
            check(req.method==='POST'&&!url.search&&form.get('csrf_token')==='ordinary-session-token','Write must use explicit POST body and current session token');
            if(url.pathname.endsWith('cash_del'))check(form.get('ids')==='1'&&form.get('all')==='0','Legacy cancellation must preserve the selected ID');
            else {
                check(form.get('cash_money')==='0.29'&&form.get('cash_bank_no')==='Ordinary+%20','Cash form must preserve money and literal account characters');
                check(/^[a-f0-9]{64}$/.test(form.get('request_id')),'Every create must carry a persisted random request ID');
                run.keys.push(form.get('request_id'));
            }
            if(run.mode==='empty-disconnect'){req.socket.destroy();return;}
            if(run.mode==='disconnect'){res.writeHead(200);res.write('{');setTimeout(()=>res.destroy(),10);return;}
            if(run.mode==='malformed'){res.end('{}');return;}
            if(run.mode==='unknown'){res.end(JSON.stringify({code:2004,msg:'Unknown reference REF-123',info:{retryable:false,reference:'REF-123',outcome:'commit_unknown'}}));return;}
            if(run.mode==='rejected'){res.end(JSON.stringify({code:1001,msg:'Rejected ordinary amount'}));return;}
            setTimeout(()=>res.end(JSON.stringify({code:1,msg:'Saved',info:{request_id:form.get('request_id'),cash_id:17}})),25);
        });
        await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
        const origin='http://127.0.0.1:'+server.address().port;
        browser=await chromium.launch({executablePath:process.env.CHROMIUM_BINARY||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
        const context=await browser.newContext();const outside=[];
        await context.route('**/*',async route=>{if(new URL(route.request().url()).origin!==origin){outside.push(route.request().url());await route.abort();}else await route.continue();});
        const page=await context.newPage();let sequence=0;
        async function open(client,mode){const id=String(++sequence);await page.goto(origin+'/fixture/page?run='+id+'&client='+client+'&mode='+mode);await page.waitForFunction(()=>window.ready);await page.evaluate(()=>sessionStorage.clear());return runs.get(id);}
        async function submit(){await page.evaluate(()=>{document.querySelector('#btn_submit').click();document.querySelector('#btn_submit').click();});}
        async function response(){await page.waitForFunction(()=>window.messages.length>0);}
        for(const client of ['default','legacy']){
            for(const mode of ['unknown','disconnect','malformed']){
                const run=await open(client,mode);await submit();await response();
                check(run.tokens===1&&run.posts===1,'Duplicate clicks issue one token and one cash write: '+client+'/'+mode+' '+JSON.stringify(run)+' messages='+JSON.stringify(await page.evaluate(()=>messages)));
                check(await page.locator('#btn_submit').isDisabled(),'Unknown result must leave cash submit disabled');
                if(mode==='unknown')check((await page.evaluate(()=>messages.join(' '))).includes('REF-123'),'The server reconciliation reference must remain visible');
                await page.evaluate(()=>document.querySelector('#btn_submit').click());
                check(run.posts===1,'Unknown cash submission must not retry');
                check((await page.evaluate(()=>sessionStorage.getItem('/fixture/cash-request-1')))===run.keys[0],'Unknown result must retain the request ID across reloads');
            }
            for(const mode of ['token-failure','rejected']){
                const run=await open(client,mode);await submit();await response();
                check(await page.locator('#btn_submit').isEnabled(),'Preflight failure or definite rejection must allow a deliberate retry');
                check(run.posts===(mode==='token-failure'?0:1),'A failed token request cannot reach the financial endpoint');
            }
            const run=await open(client,'ok');
            if(client==='legacy'){await Promise.all([page.waitForNavigation(),submit()]);}
            else{await submit();await response();check(await page.locator('#btn_submit').isDisabled(),'Accepted default form cannot immediately submit the same request again');}
            check(run.tokens===1&&run.posts===1,'Success requires exactly one acknowledged write');
            const retry=await open(client,'empty-disconnect');await submit();await response();
            check(retry.posts>=1&&new Set(retry.keys).size===1,'All transparent transport retries must carry the same persisted request ID');
            const originalKey=retry.keys[0];retry.mode='ok';
            await page.reload();await page.waitForFunction(()=>window.ready);
            if(client==='legacy'){await Promise.all([page.waitForNavigation(),submit()]);}else{await submit();await response();}
            check(retry.keys.every(key=>key===originalKey),'A deliberate retry after reload must reuse the unresolved request ID');
            check(await page.evaluate(()=>sessionStorage.getItem('/fixture/cash-request-1'))===null,'A matching acknowledgement may clear the pending request ID');
        }
        const cancel=await open('legacy','unknown');await page.evaluate(()=>{delData(1,0);delData(1,0)});await response();
        await page.waitForFunction(()=>cashWrite.blocked());await page.evaluate(()=>delData(1,0));
        check(cancel.tokens===1&&cancel.posts===1,'Legacy cancellation must share the one-write and unknown-outcome fence');
        check(outside.length===0,'Cash clients must keep all fixture traffic on the same origin');
        console.log('cash_write browser: '+checks+' checks passed');
    }finally{if(browser)await browser.close();if(server)await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
