/* Actual shipped browser clients + real isolated PHP Request, authentication, image and ORM writes. */
'use strict';
const {chromium} = require('playwright-core');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const {spawn} = require('node:child_process');
let checks=0;
function check(value,message) { checks++; assert.ok(value,message); }
const root=path.resolve(__dirname,'../..');
async function main() {
  let server, serverError, temporary, browser;
  let base=process.env.UPLOAD_AUDIT_BASE_URL;
  try {
    if (!base) {
      const socket=net.createServer(); await new Promise(resolve=>socket.listen(0,'127.0.0.1',resolve));
      const port=socket.address().port; await new Promise(resolve=>socket.close(resolve));
      temporary=fs.mkdtempSync(path.join(os.tmpdir(),'maccms-upload-http-'));
      server=spawn(process.env.PHP_BINARY || 'php',['-S',`127.0.0.1:${port}`,path.join(root,'tests/fixtures/security_audit_upload_http.php')],{cwd:temporary,stdio:['ignore','pipe','pipe']});
      server.on('error',error=>{serverError=error;});
      let logs='';server.stderr.on('data',data=>{logs+=data;});
      base=`http://127.0.0.1:${port}`;
      for(let i=0;i<100;i++) { if(serverError) throw serverError; try {if ((await fetch(base+'/health')).ok) break;} catch {} await new Promise(resolve=>setTimeout(resolve,50)); }
      check((await fetch(base+'/health')).ok,'Isolated PHP server did not start: '+logs);
    }
    const allowed=new URL(base);
    assert.ok(['127.0.0.1','localhost','[::1]'].includes(allowed.hostname),'Only local fixture servers are allowed');
    browser=await chromium.launch({executablePath:process.env.CHROMIUM_BINARY || '/usr/bin/chromium',headless:true,args:['--no-sandbox']});
    const context=await browser.newContext();
    const uploadedBodies=new Map();
    await context.route('**/*',async route=>{
      const request=route.request();
      if(new URL(request.url()).origin !== allowed.origin) {await route.abort();return;}
      if(request.method()==='POST' && /\/(upload\/upload|user\/portrait)/.test(request.url())) {
        // Preserve the real response before head-defer-public.js reloads its page on success.
        const response=await route.fetch();uploadedBodies.set(request.url(),await response.text());
        await route.fulfill({response});return;
      }
      await route.continue();
    });
    const page=await context.newPage();
    const png=Buffer.from(await (await fetch(base+'/sample.png')).arrayBuffer());
    const file={name:'browser.png',mimeType:'image/png',buffer:png};
    const writes = response=>response.request().method()==='POST' && /\/(upload\/upload|user\/portrait)/.test(response.url());
    async function result(promise, tokenLocation) {
      const response=await promise, body=uploadedBodies.get(response.url()) ?? await response.text();
      check(response.status()===200,`Upload HTTP ${response.status()}: ${body}`);
      let value; try {value=JSON.parse(body);} catch(error) {throw new Error('Invalid upload JSON: '+body, {cause:error});}
      check(value.code===1 || value.state==='SUCCESS','Normal upload failed: '+body);
      check(response.headers()['x-audit-unchanged']==='no' && response.headers()['x-audit-annex-count']==='1','Successful HTTP upload did not write its real image and Annex');
      const request=response.request();
      if(tokenLocation==='header') check(request.headers()['x-csrf-token']==='upload-browser-csrf','Actual client omitted CSRF header');
      else check(request.postDataBuffer()?.toString().includes('name="csrf_token"\r\n\r\nupload-browser-csrf'),'Actual form omitted CSRF hidden field');
      check(!request.url().includes('upload-browser-csrf'),'CSRF token leaked into URL');
      return value;
    }
    for(const client of ['legacy','default','static_new','demo','deferred','layui','native']) {
      await page.goto(`${base}/page?client=${client}`);
      if(client!=='native') await page.waitForFunction(()=>window.clientReady===true);
      const response=page.waitForResponse(writes);
      await page.locator('input[type=file]').first().setInputFiles(file);
      if(client==='native') await page.locator('input[type=submit]').click();
      await result(response,['demo','deferred','layui'].includes(client)?'header':'body');
      if(client==='demo') {
        await page.waitForFunction(()=>document.querySelector('#portrait').getAttribute('src').match(/\/upload\/user\/1\/1-[0-9a-f]{32}\.jpg/));
        check(true,'Demo client accepts the actual payload.file response');
      }
      console.log('client passed:',client);
    }
    // Real template, real editor initialization/configuration and its real WebUploader image dialog.
    await page.goto(`${base}/page?client=ueditor`);
    await page.waitForFunction(()=>window.clientReady===true && window.auditEditor.getOpt('imageActionName'));
    check(await page.evaluate(()=>auditEditor.getOpt('serverHeaders')['X-CSRF-Token']==='upload-browser-csrf'),'UEditor template header did not reach its instance');
    await page.evaluate(()=>auditEditor.getDialog('insertimage').open());
    const dialog=page.frameLocator('iframe[src*="dialogs/image/image.html"]');
    await dialog.locator('[data-content-id=upload]').click();
    const ueResponse=page.waitForResponse(writes);
    await dialog.locator('input[type=file]').first().setInputFiles(file);
    await dialog.locator('.uploadBtn').click();
    await result(ueResponse,'header');
    console.log('client passed: ueditor image dialog');
    for(const token of ['', 'wrong']) {
      await page.goto(`${base}/page?client=ueditor`);
      await page.waitForFunction(()=>window.clientReady===true && window.auditEditor.getOpt('imageActionName'));
      await page.evaluate(token=>{auditEditor.options.serverHeaders=token ? {'X-CSRF-Token':token} : {};auditEditor.getDialog('insertimage').open();},token);
      const frame=page.frameLocator('iframe[src*="dialogs/image/image.html"]');
      await frame.locator('[data-content-id=upload]').click();
      const denied=page.waitForResponse(writes);
      await frame.locator('input[type=file]').first().setInputFiles(file);
      await frame.locator('.uploadBtn').click();
      const response=await denied;
      check(response.status()===403 && response.headers()['x-audit-unchanged']==='yes'
        && response.headers()['x-audit-annex-count']==='0','Actual UEditor accepted missing/incorrect headers or wrote files');
    }
    for(const token of ['', 'wrong']) {
      await page.goto(`${base}/page?client=native`);
      await page.locator('input[name=csrf_token]').evaluate((input,value)=>input.value=value,token);
      await page.locator('input[type=file]').setInputFiles(file);
      const denied=page.waitForResponse(writes);
      await page.locator('input[type=submit]').click();
      const response=await denied;
      check(response.status()===403 && response.headers()['x-audit-unchanged']==='yes'
        && response.headers()['x-audit-annex-count']==='0','Actual native form accepted missing/incorrect token or wrote files');
    }

    // Real HTTP middleware branch (PHP_SAPI=cli-server), even with global CSRF off and legacy exemption.
    await page.goto(`${base}/page?client=demo`);
    for(const target of ['/admin.php/upload/upload?flag=vod','/index.php/user/portrait']) {
      for(const mode of ['missing','wrong','header-precedence','query-only','array-body','cookie-only']) {
        const response=await page.evaluate(async ({target,mode,png})=>{
          const body=new FormData();body.append('file',new Blob([new Uint8Array(png)],{type:'image/png'}),'negative.png');
          const headers={'X-Requested-With':'XMLHttpRequest'};
          if(mode==='wrong'||mode==='header-precedence')headers['X-CSRF-Token']='wrong';
          if(mode==='header-precedence')body.append('csrf_token','upload-browser-csrf');
          if(mode==='array-body')body.append('csrf_token[]','upload-browser-csrf');
          if(mode==='query-only')target+=(target.includes('?')?'&':'?')+'csrf_token=upload-browser-csrf';
          if(mode==='cookie-only')document.cookie='csrf_token=upload-browser-csrf; path=/';
          const r=await fetch(target,{method:'POST',body,headers});return {status:r.status,text:await r.text(),unchanged:r.headers.get('X-Audit-Unchanged'),annex:r.headers.get('X-Audit-Annex-Count')};
        },{target,mode,png:[...png]});
        check(response.unchanged==='yes'&&response.annex==='0','Rejected HTTP request wrote files or DB: '+mode);
        const data=JSON.parse(response.text);
        check(data.code!==1 && (target.includes('admin.php')?response.status===403:response.status===200),'Missing/invalid token succeeded: '+mode+' '+response.text);
      }
    }
    const nativeDenied=await context.request.post(base+'/admin.php/upload/upload',{form:{flag:'vod'}});
    check(nativeDenied.status()===403 && nativeDenied.headers()['x-audit-unchanged']==='yes','Native form denial did not use HTTP 403 with zero writes');
    const config=await context.request.get(base+'/admin.php/upload/upload?from=ueditor&action=config&ueditor_theme=new');
    check(config.status()===200 && (await config.json()).imageActionName==='uploadimage' && config.headers()['x-audit-unchanged']==='yes','Authorized config GET no longer remains read-only');
    // Same-origin token routing only; headers/form fields are not populated for foreign endpoints.
    check(await page.evaluate(()=>{
      const form=document.createElement('form');form.method='POST';form.action='https://foreign.invalid/index.php/user/portrait';
      MacUploadCsrf.prepareForm(form);
      return Object.keys(MacUploadCsrf.headers(form.action)).length===0 && !form.querySelector('[name=csrf_token]')
        && Object.keys(MacUploadCsrf.headers('/not-upload')).length===0
        && MacUploadCsrf.headers('/subdir/admin.php/upload/upload.html?flag=vod')['X-CSRF-Token']==='upload-browser-csrf';
    }),'Client token routing leaks to an unrelated origin/path or loses subdirectory URLs');
    console.log(`Upload HTTP/browser CSRF: ${checks} checks passed`);
  } finally {
    if(browser) await browser.close();
    if(server && !serverError && server.exitCode === null) {
      const exited=new Promise(resolve=>server.once('exit',resolve));
      const timer=setTimeout(()=>server.kill('SIGKILL'),5000);
      server.kill();await exited;clearTimeout(timer);
    }
    if(temporary)fs.rmSync(temporary,{recursive:true,force:true});
  }
}
main().catch(error=>{console.error(error);process.exitCode=1;});
