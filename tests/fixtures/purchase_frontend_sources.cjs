'use strict';
const fs=require('node:fs'), path=require('node:path'), vm=require('node:vm');
const root=path.resolve(__dirname,'../..');
const files=['static/js/home.js','static_new/js/home.js','template/m1938pc3_v2/js/home.js','template/vozy/tuo/assets/mac.js','template/default/asset/js/user-home-stack.js','template/default/asset/js/public-home-stack.js'];
function extract(source,start) {
    for(let end=source.indexOf('}',start);end!==-1;end=source.indexOf('}',end+1)) {
        const candidate=source.slice(start,end+1);
        try { new vm.Script('('+candidate+')'); return candidate; } catch(error) { if(!(error instanceof SyntaxError)) throw error; }
    }
    throw new Error('Unable to parse actual purchase function');
}
function methods(file) {
    const source=fs.readFileSync(path.join(root,file),'utf8'), out={};
    for(const name of ['BuyPopedomRequest','BuyPopedom']) {
        const anchor=source.indexOf("'"+name+"':"); if(anchor<0) throw new Error('Missing '+name+' in '+file);
        out[name]=extract(source,source.indexOf('function',anchor));
    }
    return out;
}
const gate=fs.readFileSync(path.join(root,'template/default/html/widget/popedom_upgrade_gate.html'),'utf8');
module.exports={root,files,methods,gate,gateScript:gate.slice(gate.lastIndexOf('<script>')+8,gate.lastIndexOf('</script>'))};
