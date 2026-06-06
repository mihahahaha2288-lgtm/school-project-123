try {
    importScripts('https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl-fast.min.js');
} catch(e) {
    postMessage({type:'error', msg:'importScripts failed: '+e.message});
}

if (typeof nacl === 'undefined') {
    postMessage({type:'error', msg:'nacl is undefined'});
} else {
    postMessage({type:'ready'});
}

let running = true;
const MIN_LENGTH = 5;
const RARE_LETTERS = ['Q','Z','X','W','V'];
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64_INDEX = new Uint8Array(128);
for (let i = 0; i < B64.length; i++) B64_INDEX[B64.charCodeAt(i)] = i;

const HD = new Uint8Array([0,0,0,0,0x29,0xA9,0x23,0x17]);
const TH = new Uint8Array(36);
const PL = new Uint8Array(34);
const FL = new Uint8Array(36);

// ─── Синхронный SHA-256 (без async/await) ────────────────────────────────────
const SHA256_K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);
const SHA256_W = new Uint32Array(64);

function sha256sync(input) {
    const n = input.length;
    const bitLen = n * 8;
    const padLen = (n % 64 < 56) ? 56 - (n % 64) : 120 - (n % 64);
    const padded = new Uint8Array(n + padLen + 8);
    padded.set(input);
    padded[n] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000), false);
    dv.setUint32(padded.length - 4, bitLen >>> 0, false);

    let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
    let h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    const rotr = (x,n) => (x>>>n)|(x<<(32-n));

    for (let blk = 0; blk < padded.length; blk += 64) {
        const bv = new DataView(padded.buffer, blk, 64);
        for (let i = 0; i < 16; i++) SHA256_W[i] = bv.getUint32(i*4, false);
        for (let i = 16; i < 64; i++) {
            const s0 = rotr(SHA256_W[i-15],7)^rotr(SHA256_W[i-15],18)^(SHA256_W[i-15]>>>3);
            const s1 = rotr(SHA256_W[i-2],17)^rotr(SHA256_W[i-2],19)^(SHA256_W[i-2]>>>10);
            SHA256_W[i] = (SHA256_W[i-16] + s0 + SHA256_W[i-7] + s1) >>> 0;
        }
        let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
        for (let i = 0; i < 64; i++) {
            const S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
            const ch = (e&f)^(~e&g);
            const t1 = (h + S1 + ch + SHA256_K[i] + SHA256_W[i]) >>> 0;
            const S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
            const maj = (a&b)^(a&c)^(b&c);
            const t2 = (S0 + maj) >>> 0;
            h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
        }
        h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
        h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
    }

    const out = new Uint8Array(32);
    const ov = new DataView(out.buffer);
    ov.setUint32(0,h0,false); ov.setUint32(4,h1,false); ov.setUint32(8,h2,false);  ov.setUint32(12,h3,false);
    ov.setUint32(16,h4,false); ov.setUint32(20,h5,false); ov.setUint32(24,h6,false); ov.setUint32(28,h7,false);
    return out;
}
// ─────────────────────────────────────────────────────────────────────────────

function crc16(d) {
    let c = 0;
    for (let byte of d) {
        c ^= byte << 8;
        for (let i = 0; i < 8; i++) c = c & 0x8000 ? ((c << 1) ^ 0x1021) : (c << 1);
        c &= 0xFFFF;
    }
    return c;
}

function fastBase64(fl) {
    let a = '';
    for (let i = 0; i < fl.length; i += 3) {
        const b0=fl[i], b1=fl[i+1]||0, b2=fl[i+2]||0;
        const v = (b0<<16)|(b1<<8)|b2;
        a += B64[(v>>18)&63] + B64[(v>>12)&63];
        if (i+1 < fl.length) a += B64[(v>>6)&63];
        if (i+2 < fl.length) a += B64[v&63];
    }
    // УБРАНА обрезка 'A' — TON-адрес всегда ровно 48 символов
    return a;
}

function checkStart(addr) {
    if (addr.length < 2 + MIN_LENGTH) return null;
    if (addr[0] !== 'U' || addr[1] !== 'Q') return null;
    const firstChar = addr[2];
    if (B64_INDEX[firstChar.charCodeAt(0)] >= 26) return null;
    for (let i = 2; i < 2 + MIN_LENGTH; i++) if (addr[i] !== firstChar) return null;
    let count = MIN_LENGTH;
    for (let i = 2 + MIN_LENGTH; i < addr.length && i < 30; i++) {
        if (addr[i] === firstChar) count++; else break;
    }
    return { text: count + 'x заглавная «' + firstChar + '» подряд СРАЗУ ПОСЛЕ UQ!', rare: RARE_LETTERS.includes(firstChar) };
}

function go() {  // НЕ async — синхронный цикл, максимальная скорость
    let localChecked = 0;
    while (running) {
        try {
            const kp = nacl.sign.keyPair();
            const pb = kp.publicKey, sk = kp.secretKey;
            TH.set(HD, 0); TH.set(pb, 8);
            const hs = sha256sync(TH);   // синхронно, без await
            PL[0] = 0x51; PL[1] = 0x00; PL.set(hs, 2);
            const cr = crc16(PL);
            FL.set(PL, 0); FL[34] = cr >> 8; FL[35] = cr & 0xFF;
            const addr = fastBase64(FL), r = checkStart(addr);
            localChecked++;
            if (r) {
                const hx = [...sk.slice(0,32)].map(b => b.toString(16).padStart(2,'0')).join('');
                postMessage({ type:'found', result:r.text, rare:r.rare, addr:addr, privHex:hx });
            }
            if (localChecked >= 500) {
                postMessage({ type:'progress', checked:localChecked });
                localChecked = 0;
            }
        } catch(e) {
            postMessage({ type:'error', msg:'Loop error: ' + e.message });
            localChecked++;
        }
    }
    if (localChecked > 0) postMessage({ type:'progress', checked:localChecked });
    postMessage({ type:'stopped' });
}

self.onmessage = function(e) { if (e.data && e.data.type === 'stop') running = false; };
go();
