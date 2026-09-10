'use strict';
// Execute the local production script against attributes read from actual generated HTML.
// No browser navigation or external request occurs.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
const pages=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));let checks=0;
const script=fs.readFileSync(path.join(__dirname,'../static/js/vod-resource-redirect.js'),'utf8');
function check(value,message){checks++;assert.ok(value,message);}
function decode(value){return value.replace(/&quot;/g,'"').replace(/&#0?39;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');}
for(const page of pages){
  const external=/<script defer src="([^"]+)"><\/script>/.exec(page.html);
  check(!!external && decode(external[1])===page.prefix+'static/js/vod-resource-redirect.js','Generated HTML loads only the local redirect script');
  check((page.html.match(/<script\b/g)||[]).length===1 && [...page.html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)].every(match=>match[1].trim()===''),'No inline script requires a CSP exception');
  const anchor=/<a\s+id="resource-link"([^>]+)>/.exec(page.html);check(!!anchor,'A manual fallback exists without JavaScript');
  const attributes=Object.fromEntries([...anchor[1].matchAll(/([\w-]+)="([^"]*)"/g)].map(match=>[match[1],decode(match[2])]));
  const manual=new URL(attributes.href,'https://fixture.invalid');
  check(manual.origin==='https://fixture.invalid' && manual.pathname===page.prefix+'index.php/vod/resource'
    && ['id','sid','nid'].every(key=>manual.searchParams.get(key)===String(page[key]))
    && manual.searchParams.get('operation')===page.operation,'No-JavaScript fallback names a real, independently authorized resource');
  function run(search,overrides={}){const attrs={...attributes,...overrides},calls=[],link={href:attrs.href,textContent:'',getAttribute(name){return attrs[name]??null;},removeAttribute(name){delete attrs[name];if(name==='href')this.href='';}};
    const location={search,replace(url){calls.push(url);}};
    vm.runInNewContext(script,{location,document:{getElementById(){return link;}}},{timeout:1000});return {calls,link};}
  for(const search of ['', '?42-7-9']){const result=run(search);check(result.calls.length===1,'A valid static link makes one dynamic navigation');const target=new URL(result.calls[0],'https://fixture.invalid');
    check(target.origin==='https://fixture.invalid' && target.pathname===page.prefix+'index.php/vod/resource','Redirect stays on the explicit PHP authorization entry');
    const expected=page.legacy_query&&search?{id:42,sid:7,nid:9}:page;
    check(['id','sid','nid'].every(key=>target.searchParams.get(key)===String(expected[key])) && target.searchParams.get('operation')===page.operation,'View-specific episode selection survives the redirect');
    check(result.link.href===result.calls[0],'Manual fallback follows the same selected episode');
  }
  if(page.legacy_query){for(const bad of ['?0-1-1','?1-0-1','?1-1-0','?4294967296-1-1','?1e0-1-1','?https://outside.invalid','?1-1-1&next=https://outside.invalid','?1-1-1#evil']){const result=run(bad);check(result.calls.length===0 && result.link.href==='','Malformed legacy selectors do not redirect or fall back to another episode');}}
  for(const overrides of [{'data-entry':'//outside.invalid/index.php/vod/resource'},{'data-entry':'/\\outside.invalid/index.php/vod/resource'},
    {'data-entry':'/index.php/vod/resource?next=evil'},{'data-entry':'/../index.php/vod/resource'}, {'data-entry':'/%2foutside.invalid/index.php/vod/resource'},
    {'data-id':'0'}, {'data-sid':'1e0'}, {'data-nid':'4294967296'}, {'data-operation':'player'}, {'data-legacy-query':'true'}, {'data-entry':null}]){
    const result=run('',overrides);check(result.calls.length===0 && result.link.href==='','Malformed data attributes fail closed without an alternate destination');
  }
  check(!/MEDIA-|PWD-|PRIVATE-|user_random|player_aaaa/.test(page.html),'Generated public HTML contains no media, password, server, or authorization payload');
}
console.log(`static_vod_redirects: ${checks} checks passed on actual generated HTML and local production JavaScript`);
