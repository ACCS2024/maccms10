'use strict';
// Execute the shipped fallback script against forms extracted from real ThinkPHP-rendered HTML.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
const pages=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const source=fs.readFileSync(path.join(__dirname,'../static/js/art-access.js'),'utf8');
let checks=0;
function check(value,message){checks++;assert.ok(value,message);}
function attrs(text){return Object.fromEntries([...text.matchAll(/([\w-]+)="([^"]*)"/g)].map(match=>[match[1],match[2].replace(/&quot;/g,'"').replace(/&amp;/g,'&')]));}
async function exercise(page,kind,responses,options={}){
  const markup=new RegExp('<form ([^>]*data-art-'+kind+'[^>]*)>').exec(page.html);
  check(!!markup,'The requested interaction uses an actual rendered form');
  const attributes=attrs(markup[1]),base=attrs(/<main ([^>]*)>/.exec(page.html)[1]);
  const calls=[],result={textContent:''},button={disabled:false},handlers={};let reloads=0;
  const form={getAttribute(name){return attributes[name]??null;},querySelector(name){if(name==='button')return button;if(name==='[name="pwd"]')return {value:'a +&=0'};return null;},addEventListener(name,handler){handlers[name]=handler;}};
  const root={getAttribute(){return options.base??base['data-art-base'];},querySelector(name){if(name==='[data-art-result]')return result;if(name==='[data-art-'+kind+']')return form;return null;}};
  const location={href:'https://fixture.invalid/index.php/art/read?id=1&page=2',origin:'https://fixture.invalid',reload(){reloads++;}};
  vm.runInNewContext(source,{document:{querySelector(){return root;}},window:{location,setTimeout(){return 1;},clearTimeout(){}},URL,URLSearchParams,AbortController,
    fetch(url,request){calls.push({url,request});const value=responses.shift();if(value instanceof Error)return Promise.reject(value);return Promise.resolve({ok:true,json(){return Promise.resolve(value);}});}
  },{timeout:1000});
  if(handlers.submit){handlers.submit({preventDefault(){}});check(button.disabled,'Form disables immediately during a pending mutation');handlers.submit({preventDefault(){}});}
  await new Promise(resolve=>setImmediate(resolve));
  return {calls,result,button,reloads,attributes,handlers};
}
(async()=>{
  const password=pages.find(page=>page.state==='password'),purchase=pages.find(page=>page.state==='purchase'),whole=pages.find(page=>page.state==='whole-long');
  const prefix=attrs(/<main ([^>]*)>/.exec(password.html)[1])['data-art-base'];
  let result=await exercise(password,'password',[{code:1,msg:'ok'}]);
  check(result.calls.length===1 && result.reloads===1 && !result.button.disabled,'Password submission is single-flight and refreshes for a new server authorization check');
  const pwd=result.calls[0];check(new URL(pwd.url).pathname===prefix+'index.php/ajax/pwd' && pwd.request.method==='POST','Password form posts only to the local article-capable Ajax boundary');
  check(result.attributes.method==='post' && result.attributes.action===prefix+'index.php/ajax/pwd','Without JavaScript, password form submission still uses POST rather than placing the password in the URL');
  const body=new URLSearchParams(pwd.request.body);check(body.get('pwd')==='a +&=0' && body.get('mid')==='2' && body.get('type')==='1' && body.get('id')==='1','Password bytes and the fixed article scope survive form encoding');
  check(pwd.request.credentials==='same-origin' && pwd.request.cache==='no-store','Password verification preserves the session and disables cached responses');
  for(const page of [purchase,whole]){
    result=await exercise(page,'purchase',[{code:1,info:{csrf_token:'fixture+&token'}},{code:1,msg:'purchased'}]);
    check(result.calls.length===2 && result.reloads===1 && !result.button.disabled,'Purchase obtains a current token then makes exactly one mutation');
    const [token,post]=result.calls;check(new URL(token.url).pathname===prefix+'index.php/user/write_token' && !token.request.method && token.request.cache==='no-store','Token request is a same-origin uncached GET');
    const data=new URLSearchParams(post.request.body);check(new URL(post.url).pathname===prefix+'index.php/user/ajax_buy_popedom.html' && post.request.method==='POST' && post.request.headers['X-Requested-With']==='XMLHttpRequest','The purchase uses the real frontend POST contract');
    check(data.get('csrf_token')==='fixture+&token' && data.get('mid')==='2' && data.get('type')==='1' && data.get('nid')==='0' && data.get('sid')===result.attributes['data-page'],'Only the rendered article coordinates and freshly fetched CSRF token are submitted');
    check(!data.has('points') && !data.has('user_id'),'The client cannot select the server price or charged identity');
    check(data.get('sid')===(page.state==='whole-long'?'1':'2'),'Whole-work page300 uses the separately resolved purchase page without changing reader coordinates');
  }
  for(const bad of [{code:1},{code:1,info:{csrf_token:''}},{code:1001,msg:'login required'},new Error('offline')]){
    result=await exercise(purchase,'purchase',[bad]);check(result.calls.length===1 && result.reloads===0 && !result.button.disabled,'Failed or malformed token acquisition never purchases or reports successful navigation');
  }
  result=await exercise(password,'password',[{code:1022,msg:'<img src=x onerror=bad>'}]);check(result.reloads===0 && result.result.textContent==='<img src=x onerror=bad>','Rejected passwords display plain text and never reload as success');
  result=await exercise(password,'password',[{code:1,msg:'ok'}],{base:'https://outside.invalid/'});check(result.calls.length===0 && !result.handlers.submit,'A foreign deployment base cannot redirect a credential-bearing request');
  const long=pages.find(page=>page.state==='long');check(!long.html.includes('data-art-purchase') && !long.html.includes('LONG-CHAPTER'),'Page coordinates outside the current voucher schema expose neither a purchase control nor protected text');
  console.log(`art_resource_frontend: ${checks} checks passed on actual rendered HTML and shipped JavaScript`);
})().catch(error=>{console.error(error);process.exitCode=1;});
