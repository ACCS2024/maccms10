// Real Chromium + shipped jQuery and purchase handlers, served only by an isolated loopback fixture.
'use strict';
const {chromium}=require('playwright-core');
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const source=require('../fixtures/purchase_frontend_sources.cjs');
let checks=0;
function check(value,message){checks++;assert.ok(value,message);}
async function main(){
    let browser,server;const runs=new Map(),outside=[];
    try {
        server=http.createServer(async(req,res)=>{
            const url=new URL(req.url,'http://127.0.0.1');
            if(url.pathname==='/jquery.js'){res.setHeader('Content-Type','application/javascript');res.end(fs.readFileSync(path.join(source.root,'static/js/jquery.js')));return;}
            if(url.pathname==='/fixture/page'){
                const id=url.searchParams.get('run'),index=Number(url.searchParams.get('client')),gate=url.searchParams.get('gate')==='1';
                if(!runs.has(id))runs.set(id,{requests:[],tokenCount:0,attempts:0,commits:0,mode:url.searchParams.get('mode')||'ok',token:''});
                res.setHeader('Set-Cookie','fixture_run='+id+'; HttpOnly; SameSite=Lax; Path=/');
                res.setHeader('Content-Type','text/html; charset=utf-8');
                const methods=source.methods(source.files[index]);
                let markup='<button id="purchase" data-id="17" data-mid="1" data-type="4" data-sid="2" data-nid="3" onclick="MAC.User.BuyPopedom(this)">Buy</button>';
                if(gate){
                    const start=source.gate.indexOf('<div class="popedom-upgrade-gate"'),end=source.gate.lastIndexOf('<script>');
                    markup=source.gate.slice(start,end).replace(/\{if[^}]*\}|\{else\/\}|\{\/if\}/g,'')
                        .replace(/\{\$__buy_id\}/g,'17').replace(/\{\$__buy_mid\}/g,'12').replace(/\{\$__buy_type\}/g,'1')
                        .replace(/\{\$__buy_sid\}/g,'2').replace(/\{\$__buy_nid\}/g,'3')
                        .replace(/\{[^}]*\}/g,'').replace(/<img\b[^>]*>/g,'');
                }
                const base=url.searchParams.get('mode')==='foreign'?'https://foreign.invalid/site':'/fixture/';
                res.end('<!doctype html><meta charset="utf-8">'+markup+'<script src="/jquery.js"></script><script>'+
                    'window.fixtureMessages=[];window.fixtureRecharge=0;window.confirm=function(){return true};'+
                    'window.maccms={path:'+JSON.stringify(base)+',base_url:"https://must-not-contact.invalid"};'+
                    'window.MAC={confirm:function(message,cb){cb()},alert:function(message){fixtureMessages.push(message)},Pop:{Msg:function(w,h,message){fixtureMessages.push(message)}},User:{IsLogin:1,Login:function(){fixtureMessages.push("login")}}};'+
                    'window.openRechargeModal=function(){fixtureRecharge++};'+
                    Object.entries(methods).map(([name,text])=>'MAC.User.'+name+'='+text+';').join('\n')+
                    (gate?source.gateScript:'')+'$(function(){window.fixtureReady=true});</script>');return;
            }
            const id=(req.headers.cookie||'').match(/(?:^|; )fixture_run=([^;]+)/)?.[1],run=runs.get(id);
            res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','private, no-store');
            if(!run){res.statusCode=401;res.end(JSON.stringify({code:1401,msg:'Please sign in'}));return;}
            let body='';for await(const chunk of req)body+=chunk;
            const entry={method:req.method,url:req.url,body,headers:req.headers};run.requests.push(entry);
            if(url.pathname==='/fixture/index.php/user/write_token'){
                run.tokenCount++;check(req.method==='GET','Actual token request must be GET');
                if(run.mode==='token-failure'&&run.tokenCount===1){res.statusCode=503;res.end(JSON.stringify({code:1001,msg:'Try again'}));return;}
                if(run.mode==='malformed-token'){res.end(JSON.stringify({code:1,msg:'ok',info:{}}));return;}
                run.token='fixture-csrf-'+run.tokenCount;
                setTimeout(()=>res.end(JSON.stringify({code:1,info:{csrf_token:run.token}})),30);return;
            }
            if(url.pathname==='/fixture/index.php/user/ajax_buy_popedom.html'){
                run.attempts++;const data=new URLSearchParams(body);
                check(req.method==='POST'&&url.search===''&&data.get('csrf_token')===run.token,'Actual purchase must POST its fetched token only in the body');
                check(['mid','id','type','sid','nid','csrf_token'].every(field=>data.has(field))&&data.get('id')==='17','Actual browser form encoding must preserve all purchase fields');
                if(run.mode==='post-failure'&&run.attempts===1){res.statusCode=503;res.end(JSON.stringify({code:1001,msg:'Try again'}));return;}
                if(run.mode==='points'||run.mode==='points2002'){res.end(JSON.stringify({code:run.mode==='points'?1005:2002,msg:'Please recharge first!'}));return;}
                run.commits++;setTimeout(()=>res.end(JSON.stringify({code:1,msg:'Purchased'})),30);return;
            }
            res.statusCode=404;res.end(JSON.stringify({code:1001,msg:'Unknown fixture route'}));
        });
        await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const base='http://127.0.0.1:'+server.address().port;
        browser=await chromium.launch({executablePath:process.env.CHROMIUM_BINARY||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
        const context=await browser.newContext();await context.route('**/*',async route=>{
            if(new URL(route.request().url()).origin!==base){outside.push(route.request().url());await route.abort();}else await route.continue();
        });
        const page=await context.newPage();let sequence=0;
        async function open(client,mode='ok',gate=false){
            const id=String(++sequence);await page.goto(base+'/fixture/page?run='+id+'&client='+client+'&mode='+mode+(gate?'&gate=1':''));
            await page.waitForFunction(()=>window.fixtureReady===true);return runs.get(id);
        }
        async function clickTwice(gate=false){await page.evaluate(gate=>{const button=document.querySelector(gate?'.js-popedom-buy-btn':'#purchase');button.click();button.click();},gate);}
        async function waitError(gate=false){await page.waitForFunction(gate=>window.fixtureMessages.length>0&&!$(document.querySelector(gate?'.js-popedom-buy-btn':'#purchase')).data('mac-buy-busy'),gate);}
        for(let client=0;client<source.files.length;client++){
            let run=await open(client);await Promise.all([page.waitForNavigation(),clickTwice()]);
            check(run.requests.length===2&&run.tokenCount===1&&run.attempts===1&&run.commits===1,'Real duplicate clicks must issue exactly token GET then one purchase POST: '+source.files[client]);
            check(run.requests[0].method==='GET'&&run.requests[1].method==='POST','Real purchase order must remain GET token before POST purchase');
            for(const mode of ['token-failure','post-failure']){
                run=await open(client,mode);await clickTwice();await waitError();
                check(run.commits===0&&run.attempts===(mode==='post-failure'?1:0),'An HTTP failure must not cause an automatic retry or commit');
                await Promise.all([page.waitForNavigation(),clickTwice()]);
                check(run.tokenCount===2&&run.commits===1,'Manual retry must fetch a new token and complete once');
                check(new URLSearchParams(run.requests.at(-1).body).get('csrf_token')==='fixture-csrf-2','Retry must use the new token');
            }
            run=await open(client,'malformed-token');await clickTwice();await waitError();
            check(run.tokenCount===1&&run.attempts===0,'Success-shaped JSON without a token must never purchase');
            run=await open(client,'foreign');await clickTwice();await waitError();check(run.requests.length===0,'External installation paths must be rejected before the browser requests them');
            console.log('purchase client passed:',source.files[client]);
        }
        for(const client of [4,5]){
            let run=await open(client,'ok',true);await Promise.all([page.waitForNavigation(),clickTwice(true)]);
            check(run.commits===1&&new URLSearchParams(run.requests.at(-1).body).get('mid')==='12','The actual member gate must preserve manga module 12 and avoid duplicate purchases');
            for(const mode of ['points','points2002']) {
            run=await open(client,mode,true);await clickTwice(true);await page.waitForFunction(()=>window.fixtureRecharge===1);
            check(run.commits===0&&run.attempts===1,'The actual gate must retain the recharge flow on insufficient points');
            check(await page.locator('.js-popedom-buy-btn').getAttribute('aria-disabled')===null,'Gate rejection must release its button for a later attempt');
            }
        }
        check(outside.length===0,'No third-party request or token destination may be attempted');
        console.log('Purchase Chromium HTTP audit passed ('+checks+' checks)');
    } finally {if(browser)await browser.close();if(server)await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
