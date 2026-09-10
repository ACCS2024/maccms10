// Actual browser purchase clients -> real PHP Session/User/controllers/financial ORM on loopback only.
'use strict';
const {chromium}=require('playwright-core');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),net=require('node:net'),assert=require('node:assert/strict');
const {spawn,execFile}=require('node:child_process');
const {randomUUID}=require('node:crypto');
const source=require('../fixtures/purchase_frontend_sources.cjs');
let checks=0;function check(value,message){checks++;assert.ok(value,message);}
async function main(){
    let temporary,server,browser,logs='',serverError,containerName;
    try{
        temporary=fs.mkdtempSync(path.join(os.tmpdir(),'maccms-purchase-php-'));
        for(let client=0;client<source.files.length;client++){
            const methods=source.methods(source.files[client]);
            fs.writeFileSync(path.join(temporary,'client-'+client+'.js'),
                'window.fixtureMessages=[];window.fixtureRecharge=0;window.openRechargeModal=function(){fixtureRecharge++};window.maccms={path:"/fixture/",base_url:"https://must-not-contact.invalid"};window.confirm=function(){return true};'+
                'window.MAC={confirm:function(message,cb){cb()},alert:function(message){fixtureMessages.push(message)},Pop:{Msg:function(w,h,message){fixtureMessages.push(message)}},User:{IsLogin:1,Login:function(){fixtureMessages.push("login")}}};'+
                Object.entries(methods).map(([name,text])=>'MAC.User.'+name+'='+text+';').join('\n'));
        }
        const socket=net.createServer();await new Promise(resolve=>socket.listen(0,'127.0.0.1',resolve));const port=socket.address().port;await new Promise(resolve=>socket.close(resolve));
        const image=process.env.PURCHASE_AUDIT_PHP_IMAGE;
        if(image){
            // This run owns exactly this randomly named container and loopback listener.
            containerName='maccms-purchase-php-'+randomUUID();
            server=spawn('docker',['run','--rm','--name',containerName,'--network','host','-v',source.root+':/app:ro','-v',temporary+':/fixture','-w','/fixture',image,
                'php','-S','127.0.0.1:'+port,'/app/tests/fixtures/purchase_csrf_http.php'],{stdio:['ignore','pipe','pipe']});
        }else{
            server=spawn(process.env.PHP_BINARY||'php',['-S','127.0.0.1:'+port,path.join(source.root,'tests/fixtures/purchase_csrf_http.php')],
                {cwd:temporary,stdio:['ignore','pipe','pipe']});
        }
        server.on('error',error=>{serverError=error;});server.stderr.on('data',data=>{logs+=data;});server.stdout.on('data',data=>{logs+=data;});
        const base='http://127.0.0.1:'+port;
        for(let count=0;count<100;count++){if(serverError)throw serverError;try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(resolve=>setTimeout(resolve,50));}
        check((await fetch(base+'/health')).ok,'PHP fixture did not start: '+logs);
        browser=await chromium.launch({executablePath:process.env.CHROMIUM_BINARY||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
        const context=await browser.newContext(),outside=[];
        await context.route('**/*',async route=>{
            if(new URL(route.request().url()).origin!==base){outside.push(route.request().url());await route.abort();}else await route.continue();
        });
        const page=await context.newPage();let requests=[];
        page.on('request',request=>{if(/user\/(write_token|ajax_buy_popedom)/.test(request.url()))requests.push(request);});
        for(let client=0;client<source.files.length;client++){
            await context.request.post(base+'/fixture/reset');
            await page.goto(base+'/fixture/page?client='+client);await page.waitForFunction(()=>window.fixtureReady===true);requests=[];
            const tokenResponse=page.waitForResponse(response=>response.url().includes('/user/write_token'));
            const postResponse=page.waitForResponse(response=>response.request().method()==='POST'&&response.url().includes('/user/ajax_buy_popedom'));
            await Promise.all([page.waitForNavigation(),page.evaluate(()=>{document.querySelector('#purchase').click();document.querySelector('#purchase').click();})]);
            const token=await tokenResponse,post=await postResponse;
            check(token.headers()['cache-control']==='private, no-store'&&token.headers()['x-audit-unchanged']==='yes','Real token GET must stay private and leave all account/financial rows unchanged');
            check(post.status()===200&&post.headers()['x-audit-balance']==='80'&&post.headers()['x-audit-receipts']==='1','Real PHP purchase must debit once and create one receipt');
            check(requests.length===2&&requests[0].method()==='GET'&&requests[1].method()==='POST','Actual client must fetch a session token before its single purchase POST');
            const payload=new URLSearchParams(requests[1].postData());
            check(payload.get('csrf_token')?.length===64&&!requests[1].url().includes('csrf_token'),'The real issued session token must travel in the POST body');
            const state=await(await context.request.get(base+'/fixture/state')).json();
            check(state.balance===80&&state.receipts===1&&state.ledgers===4&&state.owner===1,'Browser success must correspond to actual owner/referral ledgers and persisted balance');
            const retry=await context.request.post(base+'/fixture/index.php/user/ajax_buy_popedom.html',{form:Object.fromEntries(payload)});
            check((await retry.json()).code===1&&retry.headers()['x-audit-unchanged']==='yes','A repeated real HTTP purchase must not charge again');
            console.log('PHP browser client passed:',source.files[client]);
        }
        await context.request.post(base+'/fixture/reset');await page.goto(base+'/fixture/page?client=4&gate=1');await page.waitForFunction(()=>window.fixtureReady===true);
        await Promise.all([page.waitForNavigation(),page.locator('.js-popedom-buy-btn').click()]);
        const gateState=await(await context.request.get(base+'/fixture/state')).json();
        check(gateState.balance===80&&gateState.receipts===1&&gateState.ledgers===4,'The real rendered manga gate must purchase through the same actual PHP session and transaction');

        await context.request.post(base+'/fixture/reset',{form:{balance:'10'}});
        await page.goto(base+'/fixture/page?client=4&gate=1');await page.waitForFunction(()=>window.fixtureReady===true);
        const insufficient=page.waitForResponse(response=>response.request().method()==='POST'&&response.url().includes('/user/ajax_buy_popedom'));
        await page.locator('.js-popedom-buy-btn').click();await page.waitForFunction(()=>window.fixtureRecharge===1);
        const rejected=await insufficient,english=await rejected.json();
        check(english.code===2002&&english.msg.includes('Please recharge first!'),'The actual index endpoint must keep its existing insufficient-points code and English message');
        check(rejected.headers()['x-audit-unchanged']==='yes'&&rejected.headers()['x-audit-balance']==='10',
            'The real gate must open recharge on code 2002 without changing the low balance or ledger');

        await context.request.post(base+'/fixture/reset');await page.goto(base+'/fixture/page?client=0');await page.waitForFunction(()=>window.fixtureReady===true);
        const sessionToken=(await(await context.request.get(base+'/fixture/index.php/user/write_token')).json()).info.csrf_token;
        const normal={mid:'1',id:'17',type:'4',sid:'2',nid:'3'};
        for(const sample of [
            {body:normal},
            {body:normal,query:'?csrf_token='+sessionToken},
            {body:{...normal,csrf_token:sessionToken},headers:{'X-CSRF-Token':'wrong'}},
            {body:{...normal,csrf_token:sessionToken},headers:{'X-CSRF-Token':''}},
            {body:{...normal,'csrf_token[]':sessionToken}},
            {body:{...normal,mid:undefined,'mid[]':'1',csrf_token:sessionToken}},
            {body:{...normal,'_method[]':'POST',csrf_token:sessionToken},status:400},
            {body:{...normal,_method:'GET',csrf_token:sessionToken}},
            {body:{...normal,csrf_token:sessionToken},headers:{'X-HTTP-Method-Override':'GET'}},
        ]){
            const body=new URLSearchParams(Object.entries(sample.body).filter(([,value])=>value!==undefined));
            const response=await context.request.post(base+'/fixture/index.php/user/ajax_buy_popedom.html'+(sample.query||''),
                {data:body.toString(),headers:{'Content-Type':'application/x-www-form-urlencoded',...sample.headers}});
            check(response.status()===(sample.status||200)&&(await response.json()).code>1,'Malformed real HTTP body/header input must produce a controlled rejection');
            check(response.headers()['x-audit-unchanged']==='yes'&&response.headers()['x-audit-balance']==='100',
                'Rejected actual HTTP requests must not mutate accounts, financial ledgers or receipts');
        }
        for(const headers of [{},{'X-HTTP-Method-Override':'POST'}]){
            const response=await context.request.get(base+'/fixture/index.php/user/ajax_buy_popedom.html?'+new URLSearchParams({...normal,csrf_token:sessionToken}),{headers});
            check((await response.json()).code>1&&response.headers()['x-audit-unchanged']==='yes','Raw GET cannot purchase even with a POST method override');
        }
        check(outside.length===0,'No purchase token or account request may reach an external host');
        console.log('Purchase PHP Chromium audit passed ('+checks+' checks)');
    }finally{
        if(browser)await browser.close();
        if(server&&!serverError&&server.exitCode===null){const exit=new Promise(resolve=>server.once('exit',resolve));const timer=setTimeout(()=>server.kill('SIGKILL'),5000);server.kill();await exit;clearTimeout(timer);}
        if(containerName){
            await new Promise((resolve,reject)=>execFile('docker',['rm','--force',containerName],{timeout:10000},(error,stdout,stderr)=>{
                if(error&&!String(stderr).includes('No such container'))reject(error);else resolve();
            }));
        }
        if(temporary)fs.rmSync(temporary,{recursive:true,force:true});
    }
}
main().catch(error=>{console.error(error);process.exitCode=1;});
