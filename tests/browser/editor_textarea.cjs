'use strict';
// Actual Think templates -> Chromium's native textarea parser. Page scripts are disabled.
const {chromium}=require('playwright-core');
const {execFileSync}=require('node:child_process');
const path=require('node:path'), assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../..');
const image=process.env.EDITOR_AUDIT_PHP_IMAGE;
const command=image?'docker':(process.env.PHP_BINARY||'php');
const args=image?['run','--rm','--network','none','-v',root+':/app:ro','-w','/app','--entrypoint','php',image,'tests/fixtures/editor_textarea.php']:['tests/fixtures/editor_textarea.php'];
const data=JSON.parse(execFileSync(command,args,{cwd:root,encoding:'utf8',maxBuffer:4*1024*1024,timeout:30000}));
async function main(){
 let browser,checks=0;
 try{
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_BINARY||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
  const context=await browser.newContext({javaScriptEnabled:false,serviceWorkers:'block'});
  const requests=[];await context.route('**/*',route=>{requests.push(route.request().url());return route.abort();});
  const page=await context.newPage();page.setDefaultTimeout(5000);
  for(const sample of data.cases){
   await page.setContent('<!doctype html><html><head><meta charset="UTF-8"></head><body>'+sample.html+'</body></html>');
   const label=sample.template+' / '+sample.case;
   assert.equal(await page.locator('#'+sample.id).inputValue(),sample.expected,label+' must preserve the native editor value');checks++;
   assert.equal(await page.locator('textarea').count(),1,label+' must preserve one editor');checks++;
   assert.equal(await page.locator('#editor-boundary-probe').count(),0,label+' must not produce an element outside the editor');checks++;
  }
  assert.equal(requests.length,0,'Textarea content must not initiate resource requests');checks++;
  assert.equal(data.cases.length,89,'All eight actual editor templates must be covered');checks++;
  console.log('Editor textarea Chromium: '+checks+' checks passed from PHP '+data.php+' ('+data.cases.length+' ordinary data cases; page scripts disabled)');
 }finally{if(browser){await browser.close();}}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
