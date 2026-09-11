'use strict';
const {chromium}=require('playwright-core');
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../..');let checks=0;
function check(value,message){checks++;assert.ok(value,message);}
async function main(){
    let server,browser;const runs=new Map();
    try{
        const template=fs.readFileSync(path.join(root,'application/admin/view/cash/index.html'),'utf8');
        const buttons=[...template.matchAll(/<a\b[^>]*js-cash-action[^>]*>/g)].map(match=>match[0]
            .replace(/\{:url\('(del|audit)'\)\}/g,'/fixture/admin.php/cash/$1')
            .replace(/\{:lang\('[^']+'\)\}/g,'Confirm ordinary action').replace(/\{\$vo.cash_id\}/g,'17'));
        check(buttons.length===5&&!/j-ajax|j-page-btns|j-tr-del/.test(template),'Actual cash template must use the dedicated handler for all five action types');
        server=http.createServer(async(req,res)=>{
            const url=new URL(req.url,'http://127.0.0.1');
            if(['/cash-write.js','/admin_cash.js'].includes(url.pathname)){res.setHeader('Content-Type','application/javascript');res.end(fs.readFileSync(path.join(root,'static/js',url.pathname.slice(1))));return;}
            if(url.pathname==='/fixture/page'){
                const id=url.searchParams.get('run');if(!runs.has(id))runs.set(id,{mode:url.searchParams.get('mode'),posts:[]});
                res.setHeader('Set-Cookie','admin_cash_run='+id+'; HttpOnly; SameSite=Lax; Path=/');res.setHeader('Content-Type','text/html; charset=utf-8');
                res.end('<!doctype html><meta charset="utf-8"><meta name="mac-admin-csrf" content="ordinary-admin-session-token">'+
                    '<div id="mac-admin-cash"><input class="checkbox-ids" type="checkbox" value="17" checked><input class="checkbox-ids" type="checkbox" value="31">'+
                    buttons.map((button,i)=>button+'Action '+i+'</a>').join('')+'</div><script>window.messages=[];window.alert=function(t){messages.push(t)};window.confirm=function(){return true};</script>'+
                    '<script src="/cash-write.js"></script><script src="/admin_cash.js"></script>');return;
            }
            const id=(req.headers.cookie||'').match(/(?:^|; )admin_cash_run=([^;]+)/)?.[1],run=runs.get(id);
            if(!run){res.statusCode=404;res.end();return;}
            let body='';for await(const chunk of req)body+=chunk;
            const form=new URLSearchParams(body);run.posts.push({path:url.pathname,body:form});
            check(req.method==='POST'&&url.search===''&&form.get('csrf_token')==='ordinary-admin-session-token'
                &&req.headers['x-csrf-token']==='ordinary-admin-session-token','Admin writes must use body selection and the current token in both supported credential locations');
            res.setHeader('Content-Type','application/json');
            const result=run.mode==='unknown'?{code:2004,msg:'Inspect ADMIN-REF',info:{retryable:false,reference:'ADMIN-REF'}}
                :run.mode==='rejected'?{code:1001,msg:'Selection rejected'}:{code:1,msg:'Confirmed'};
            setTimeout(()=>res.end(JSON.stringify(result)),30);
        });
        await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
        browser=await chromium.launch({executablePath:process.env.CHROMIUM_BINARY||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
        const page=await browser.newPage();const outside=[];
        await page.route('**/*',async route=>{if(new URL(route.request().url()).origin!==origin){outside.push(route.request().url());await route.abort();}else await route.continue();});
        let sequence=0;
        async function open(mode){const id=String(++sequence);await page.goto(origin+'/fixture/page?run='+id+'&mode='+mode);return runs.get(id);}
        async function click(index){await page.evaluate(index=>{const button=document.querySelectorAll('.js-cash-action')[index];button.click();button.click();},index);}
        for(let index=0;index<5;index++){
            const run=await open('ok');await Promise.all([page.waitForNavigation(),click(index)]);
            check(run.posts.length===1,'Duplicate admin clicks must produce one acknowledged action');
            check(run.posts[0].path.endsWith(index===2||index===4?'/audit':'/del'),'Actual template must target the selected cash action');
            check(index===1?run.posts[0].body.get('all')==='1'&&!run.posts[0].body.has('ids')
                :run.posts[0].body.get('all')==='0'&&run.posts[0].body.get('ids')==='17','Clear and checkbox/row actions must preserve their distinct body scope');
        }
        const unknown=await open('unknown');await click(0);await page.waitForFunction(()=>messages.length>0);
        check((await page.evaluate(()=>messages.join(' '))).includes('ADMIN-REF'),'Unknown financial reference must remain visible');
        check(await page.locator('.js-cash-action[aria-disabled="true"]').count()===5,'Unknown outcome must lock subsequent admin cash writes');
        await click(2);check(unknown.posts.length===1,'An unknown cancellation cannot trigger a later settlement from this page');
        const rejected=await open('rejected');await click(0);await page.waitForFunction(()=>messages.length>0);
        check(await page.locator('.js-cash-action[aria-disabled="false"]').count()===5,'Definite selection rejection must restore the admin actions');
        await click(0);await page.waitForFunction(()=>messages.length===2);check(rejected.posts.length===2,'A deliberate retry is possible after a definite rejection');
        const empty=await open('ok');await page.locator('.checkbox-ids:checked').uncheck();await click(0);
        check(empty.posts.length===0,'Empty checkbox selection must not issue any admin write');
        check(outside.length===0,'Admin cash fixture must keep all traffic on the same origin');
        console.log('Admin cash browser: '+checks+' checks passed');
    }finally{if(browser)await browser.close();if(server)await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
