importScripts('./nacl-fast.min.js');

let running = true;
const MIN_LENGTH = 5;
const RARE_LETTERS = ['Q','Z','X','W','V'];
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64_INDEX = new Uint8Array(128);
for (let i=0;i<B64.length;i++)B64_INDEX[B64.charCodeAt(i)]=i;

const HD = new Uint8Array([0,0,0,0,0x29,0xA9,0x23,0x17]);
const TH = new Uint8Array(36);
const PL = new Uint8Array(34);
const FL = new Uint8Array(36);

function crc16(d){let c=0;for(let b of d){c^=b<<8;for(let i=0;i<8;i++)c=c&0x8000?((c<<1)^0x1021):(c<<1);c&=0xFFFF}return c}
function fastBase64(fl){
    let a='';
    for(let i=0;i<fl.length;i+=3){
        const b0=fl[i],b1=fl[i+1]||0,b2=fl[i+2]||0;
        const v=(b0<<16)|(b1<<8)|b2;
        a+=B64[(v>>18)&63]+B64[(v>>12)&63];
        if(i+1<fl.length)a+=B64[(v>>6)&63];
        if(i+2<fl.length)a+=B64[v&63];
    }
    while(a.endsWith('A'))a=a.slice(0,-1);
    return a;
}
function checkStart(addr){
    if(addr.length<2+MIN_LENGTH)return null;
    if(addr[0]!=='U'||addr[1]!=='Q')return null;
    const firstChar=addr[2];
    if(B64_INDEX[firstChar.charCodeAt(0)]>=26)return null;
    for(let i=2;i<2+MIN_LENGTH;i++)if(addr[i]!==firstChar)return null;
    let count=MIN_LENGTH;
    for(let i=2+MIN_LENGTH;i<addr.length&&i<30;i++){if(addr[i]===firstChar)count++;else break}
    return{text:count+'x заглавная «'+firstChar+'» подряд СРАЗУ ПОСЛЕ UQ!',rare:RARE_LETTERS.includes(firstChar)};
}

async function go(){
    let localChecked=0;
    while(running){
        try{
            const kp=nacl.sign.keyPair();
            const pb=kp.publicKey,sk=kp.secretKey;
            TH.set(HD,0);TH.set(pb,8);
            const hsBuf=await crypto.subtle.digest('SHA-256',TH);
            const hs=new Uint8Array(hsBuf);
            PL[0]=0x51;PL[1]=0x00;PL.set(hs,2);
            const cr=crc16(PL);
            FL.set(PL,0);FL[34]=cr>>8;FL[35]=cr&0xFF;
            const addr=fastBase64(FL),r=checkStart(addr);
            localChecked++;
            if(r){
                const hx=[...sk.slice(0,32)].map(b=>b.toString(16).padStart(2,'0')).join('');
                postMessage({type:'found',result:r.text,rare:r.rare,addr:addr,privHex:hx});
            }
            if(localChecked>=500){postMessage({type:'progress',checked:localChecked});localChecked=0}
        }catch(e){localChecked++}
    }
    if(localChecked>0)postMessage({type:'progress',checked:localChecked});
    postMessage({type:'stopped'});
}
self.onmessage=function(e){if(e.data&&e.data.type==='stop')running=false};
go();
