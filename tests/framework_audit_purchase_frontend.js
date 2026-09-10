// Actual purchase handlers executed with controlled browser callbacks; no network or accounts.
'use strict';
const vm=require('node:vm'), fs=require('node:fs'), path=require('node:path'), assert=require('node:assert/strict');
const source=require('./fixtures/purchase_frontend_sources.cjs');
let checks=0;
function check(value,message) {checks++;assert.ok(value,message);}
function setup(file,base='/fixture/') {
    const requests=[],responses=[],handlers={},attrs={'data-id':'17','data-mid':'1','data-type':'4','data-sid':'2','data-nid':'3'}, data={}, classes=new Set();
    const button={attr(name,value){if(arguments.length===2){attrs[name]=value;return this;}return attrs[name];},removeAttr(name){delete attrs[name];return this;},
        data(name,value){if(arguments.length===2){data[name]=value;return this;}return data[name];},removeData(name){delete data[name];return this;},
        addClass(name){classes.add(name);return this;},removeClass(name){classes.delete(name);return this;}};
    const gate={length:1,attr(name){return name==='data-user-buy-url'?'/fixture/index.php/user/buy':'';},on(event,selector,callback){handlers[selector]=callback;}};
    function $(value){if(typeof value==='function'){value();return;}return value==='.popedom-upgrade-gate'?gate:button;}
    $.each=(values,callback)=>values.forEach((value,index)=>callback(index,value));$.ajax=options=>{requests.push(options);};
    const effects={confirm:0,reload:0,login:0,recharge:0},location={href:'https://example.invalid/fixture/index.php/vod/play',origin:'https://example.invalid'};
    const MAC={confirm(message,callback){effects.confirm++;if(effects.accept!==false)callback();},alert(message){responses.push({msg:message});},
        Pop:{Msg(width,height,message){responses.push({msg:message});}},User:{IsLogin:1,Login(){effects.login++;}}};
    const window={location,openRechargeModal(){effects.recharge++;}};
    const context=vm.createContext({$,MAC,URL,maccms:{path:base,base_url:'https://unrelated.invalid'},window,location,top:{location:{reload(){effects.reload++;}}},
        confirm(){effects.confirm++;return effects.accept!==false;},setTimeout(callback){callback();}});
    for(const [name,text] of Object.entries(source.methods(file))) MAC.User[name]=vm.runInContext('('+text+')',context);
    function invoke(){MAC.User.BuyPopedomRequest(button,response=>responses.push(response));}
    function token(value={code:1,info:{csrf_token:'fixture-token'}}){requests.at(-1).success(value);}
    return {requests,responses,attrs,data,classes,button,MAC,effects,location,context,handlers,invoke,token};
}
for(const file of source.files) {
    let env=setup(file);env.MAC.User.BuyPopedom(env.button);
    check(env.effects.confirm===1&&env.requests.length===1,'Purchase confirmation must start only one token fetch: '+file);
    let get=env.requests[0];check(get.type==='get'&&get.url==='https://example.invalid/fixture/index.php/user/write_token'&&get.cache===false&&get.timeout>0,'Token fetch must be bounded and same-origin under the installation path');
    check(env.data['mac-buy-busy']===true&&env.classes.has('disabled'),'A pending token request must disable repeated submission');
    env.MAC.User.BuyPopedom(env.button);check(env.requests.length===1&&env.effects.confirm===1,'Duplicate click before the token response must not confirm or send again');
    env.token();let post=env.requests[1];
    check(post.type==='post'&&post.url==='https://example.invalid/fixture/index.php/user/ajax_buy_popedom.html'&&!post.url.includes('?'),'Purchase endpoint must receive POST without payload in the query');
    check(JSON.stringify(post.data)===JSON.stringify({mid:'1',id:'17',type:'4',sid:'2',nid:'3',csrf_token:'fixture-token'}),'Purchase POST must contain the five original fields and fresh token');
    if(get.complete)get.complete();env.invoke();check(env.requests.length===2&&env.classes.has('disabled'),'Completing the token GET must not unlock an outstanding POST');
    post.success({code:1,msg:'Purchased'});check(env.effects.reload===1&&env.responses.at(-1).msg==='Purchased','Successful normal purchase must keep the actual success message and reload');
    check(!env.data['mac-buy-busy']&&!env.classes.has('disabled')&&!env.attrs['aria-disabled'],'Successful completion must clear busy UI state');
    env=setup(file);env.effects.accept=false;env.MAC.User.BuyPopedom(env.button);check(env.requests.length===0&&!env.data['mac-buy-busy'],'Cancelling confirmation must leave a usable button without requests');
    for(const token of [null,{},[],{code:1},{code:1,msg:'ok',info:{}},{code:1,info:{csrf_token:''}},{code:1,info:{csrf_token:[]}},{code:1002,msg:'Please sign in'}]) {
        env=setup(file);env.invoke();env.token(token);
        check(env.requests.length===1&&env.responses.length===1&&env.responses[0].code>1&&!env.data['mac-buy-busy'],'Malformed or denied token response must never trigger a purchase');
        env.invoke();check(env.requests.length===2,'A failed token attempt must allow a fresh manual retry');
    }
    for(const stage of ['token','purchase']) {
        env=setup(file);env.invoke();if(stage==='purchase')env.token();const count=env.requests.length;
        env.requests.at(-1).error({},'timeout');check(env.requests.length===count&&env.responses.length===1&&!env.data['mac-buy-busy'],'Network failure must release the button without automatically retrying a financial request');
        env.invoke();check(env.requests.length===count+1&&env.requests.at(-1).type==='get','Manual retry must fetch a fresh token after either failure stage');
    }
    for(const base of ['https://foreign.invalid/site','//foreign.invalid/site','/fixture?next=','/fixture#fragment']) {
        env=setup(file,base);env.invoke();check(env.requests.length===0&&env.responses[0].code>1,'Malformed or external installation URLs must not receive tokens or credentials');
    }
    for(const base of ['','/','https://example.invalid/fixture']) {
        env=setup(file,base);env.invoke();check(env.requests.length===1&&env.requests[0].url.startsWith('https://example.invalid/'),'Root and same-origin absolute installation paths remain usable');
    }
    for(const mid of ['2','12']) {env=setup(file);env.attrs['data-mid']=mid;env.attrs['data-type']='1';env.invoke();env.token();check(env.requests[1].data.mid===mid,'Article and manga purchase module identifiers must be preserved');}
    env=setup(file);env.invoke();env.token();env.requests[1].success(null);check(env.responses[0].code>1&&!env.data['mac-buy-busy'],'Invalid purchase JSON must produce a retryable controlled result');
}
for(const file of source.files.filter(file=>file.includes('home-stack'))) {
    let env=setup(file);vm.runInContext(source.gateScript,env.context);
    const click=()=>env.handlers['.js-popedom-buy-btn'].call(env.button,{preventDefault(){}});
    env.MAC.User.IsLogin=0;click();check(env.effects.login===1&&env.requests.length===0,'The actual gate must preserve its login popup');
    env.MAC.User.IsLogin=1;click();click();check(env.requests.length===1,'The actual gate must share the helper duplicate guard');
    env.token();env.requests[1].success({code:1005,msg:'Not enough points'});check(env.effects.recharge===1&&!env.data['mac-buy-busy'],'Insufficient points must retain the gate recharge path and allow retry');
    click();env.token();env.requests.at(-1).success({code:1,msg:'Purchased'});check(env.effects.reload===1,'Gate successful retry must reload the actual page');
    env=setup(file);vm.runInContext(source.gateScript,env.context);
    env.handlers['.js-popedom-buy-btn'].call(env.button,{preventDefault(){}});env.token();env.requests[1].success({code:2002,msg:'Sorry, viewing this page data requires 20 points. You have 10 points left. Please recharge first!'});
    check(env.effects.recharge===1,'Index insufficient-points code must open recharge regardless of translated wording');
    env=setup(file);vm.runInContext(source.gateScript,env.context);vm.runInContext('delete window.openRechargeModal',env.context);
    env.handlers['.js-popedom-buy-btn'].call(env.button,{preventDefault(){}});env.token();env.requests[1].success({code:1005,msg:'Not enough points'});
    check(env.location.href==='/fixture/index.php/user/buy','Gate recharge fallback must keep the configured member purchase URL');
}
for(const [file,method,type] of [['template/default/html/vod/player.html','window.parent.MAC.User.BuyPopedom(this)','4'],['template/m1938pc3_v2/html9/vod/downer.html','window.parent.MAC.User.BuyPopedom(this)','5']]) {
    const markup=fs.readFileSync(path.join(source.root,file),'utf8'),tag=markup.split('<').find(line=>line.includes(method));
    check(tag&&tag.includes('data-mid="1"')&&tag.includes('data-type="'+type+'"'),'Actual iframe purchase button must target its parent and video module');
}
console.log('Purchase frontend audit passed ('+checks+' checks)');
