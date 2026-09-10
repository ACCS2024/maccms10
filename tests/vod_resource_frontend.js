'use strict';
// Execute shipped password handlers and the video renderer; no network or site data.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
let checks = 0;
function check(value, message) { checks++; assert.ok(value, message); }
function extractFunction(source, start) {
  for (let end=source.indexOf('}',start); end!==-1; end=source.indexOf('}',end+1)) {
    const candidate=source.slice(start,end+1);
    try { new vm.Script('('+candidate+')'); return candidate; } catch(error) { if(!(error instanceof SyntaxError))throw error; }
  }
  throw new Error('Password handler could not be parsed');
}
for(const file of ['static/js/home.js','static_new/js/home.js','template/default/asset/js/user-home-stack.js','template/default/asset/js/public-home-stack.js']) {
  const source=fs.readFileSync(path.join(__dirname,'..',file),'utf8');
  const anchor=source.indexOf("'Pwd'");check(anchor>0,'Shipped password object exists');
  const handler=extractFunction(source,source.indexOf('function',anchor));
  for(const password of ['a&+b','0','中文#?=','"<>%']) {
    const calls=[];
    const button={attr(name){return {'data-id':'8','data-mid':'1','data-type':'4'}[name];},
      parents(){return this;},find(){return this;},val(){return password;},addClass(){},removeClass(){}};
    const context=vm.createContext({$:()=>button,MAC:{Ajax(...args){calls.push(args);}},maccms:{path:'/fixture',base_url:'/fixture'}});
    vm.runInContext('('+handler+')',context)({});
    check(calls.length===1,'Password verification produces one request');
    const url=new URL(calls[0][0],'https://fixture.invalid');
    check(url.searchParams.get('pwd')===password && url.searchParams.get('id')==='8' && url.searchParams.get('type')==='4','Password punctuation does not alter request parameters or scope');
  }
}
function node(){return {innerHTML:'',textContent:'',style:{},attributes:{},querySelector(){return null;},querySelectorAll(){return [];},getAttribute(k){return this.attributes[k]||'';},setAttribute(k,v){this.attributes[k]=v;},addEventListener(){},classList:{add(){},remove(){},toggle(){},contains(){return false;}}};}
(async()=>{
  const source=node(),catalog=node(),tabs=node(),body=node();body.attributes={'data-detail-id':'7','data-detail-module':'vod'};
  source.querySelector=selector=>selector==='#NumTab'?tabs:selector==='.js-vod-play-source-body'?catalog:null;
  const document={body,readyState:'complete',title:'',addEventListener(){},querySelectorAll(){return [];},getElementById(){return null;},querySelector(selector){return selector==='.play_source'?source:null;}};
  const maccms={path:'',path_tpl:'/template/default/',site_name:'Fixture'};
  const dto={code:1,info:{vod_id:7,vod_name:'Sparse directory',vod_play_list:[{sid:4,from:'fixture',player_info:{show:'线路'},urls:[{nid:3,name:'第三集',play_link:'/controlled/7/4/3'},{nid:9,name:'第九集',play_link:'/controlled/7/4/9'}]}]}};
  const context={document,maccms,window:{maccms,location:{origin:'https://fixture.invalid'},addEventListener(){}},URL,Promise,console,fetch(){return Promise.resolve({json:()=>Promise.resolve(dto)});}};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'..','template/default/asset/js/vod-detail-ajax-render.js'),'utf8'),context,{timeout:2000});
  for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));
  check(catalog.innerHTML.includes('/controlled/7/4/3') && catalog.innerHTML.includes('/controlled/7/4/9'),'Renderer uses returned links for sparse real coordinates');
  check(!catalog.innerHTML.includes('/vod/play/id/7/sid/1/nid/1'),'Compressed array positions never replace the actual source and episode');
  console.log(`vod_resource_frontend: ${checks} checks passed using shipped JavaScript`);
})().catch(error=>{console.error(error);process.exitCode=1;});
