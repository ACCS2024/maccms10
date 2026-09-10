'use strict';
// Execute the actual shipped detail renderers against the PHP DTOs. All DOM/network boundaries are fixtures.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const fixtures = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
let checks = 0;
function check(condition, message) { checks++; assert.ok(condition, message); }
function node() {
  return {innerHTML:'', textContent:'', style:{}, attributes:{},
    querySelector(){return null;}, querySelectorAll(){return [];},
    getAttribute(key){return this.attributes[key] || '';}, setAttribute(key,value){this.attributes[key]=value;},
    addEventListener(){}, classList:{add(){},remove(){},toggle(){},contains(){return false;}}};
}
(async () => {
  for (const kind of ['vod','art','manga']) {
    const catalog=node(), root=node(), tabs=node(), source=node();
    const body=node();body.attributes={'data-detail-id':'1','data-detail-module':kind};
    root.querySelector=selector=>selector===`.js-${kind}-toc-content`?catalog:null;
    source.querySelector=selector=>selector==='#NumTab'?tabs:selector==='.js-vod-play-source-body'?catalog:null;
    const document={body,readyState:'complete',title:'',addEventListener(){},querySelectorAll(){return [];},
      querySelector(selector){return selector==='.play_source'?source:null;},
      getElementById(id){return id==='artcon_page'||id==='manga_detail_page'?root:null;}};
    const maccms={path:'',path_tpl:'/template/default/',site_name:'Fixture'};
    const window={maccms,location:{origin:'https://fixture.invalid'},addEventListener(){}};
    const fetched=[];
    const context={window,document,maccms,console,URL,Promise,fetch(url,options){
      fetched.push([url,options]);
      assert.match(url,new RegExp(`api\\.php/${kind}/get_detail`));
      return Promise.resolve({json:()=>Promise.resolve(fixtures[kind])});
    }};
    vm.runInNewContext(fs.readFileSync(path.join(__dirname,'..','template/default/asset/js',`${kind}-detail-ajax-render.js`),'utf8'),context,{timeout:2000});
    for(let turn=0;turn<8;turn++)await new Promise(resolve=>setImmediate(resolve));
    check(fetched.length===1 && fetched[0][1].credentials==='same-origin',`${kind} must preserve its actual authenticated detail request`);
    const html=catalog.innerHTML;
    check(!html.includes('PRIVATE-MARKER'),`${kind} renderer must not receive or print private resources`);
    if(kind==='vod') {
      check(html.includes('第一集') && html.includes('第2集') && html.includes('备用集'),'Video sources and episode labels must render');
      check((tabs.outerHTML||tabs.innerHTML).includes('线路一'),'Video source display label must render');
      check(html.includes('/play/1/1/1') && !html.includes('https://PRIVATE'),'Video catalog must link to controlled pages');
    } else if(kind==='art') {
      check(html.includes('第一章') && html.includes('第二章'),'Article chapter labels must render');
      check(html.includes('/art/read/'),'Article catalog must preserve the controlled read route');
    } else {
      check(html.includes('第一话') && html.includes('第二话') && html.includes('备用话'),'Manga source and chapter labels must render');
      check(html.includes('/read/manga/1/1/2'),'Manga catalog must use the returned controlled read link');
    }
  }
  console.log(`public_content_default_renderers: ${checks} checks passed using shipped JavaScript`);
})().catch(error=>{console.error(error);process.exitCode=1;});
