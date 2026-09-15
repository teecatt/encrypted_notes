/* Shared encrypted per-note storage.
   Remote: one flat file per note under notesDir, named by its encrypted name.
   File content = base64( iv(16B) || AES-CTR-256(magic \n order \n title \n markdown) ).
   The encrypted file name = base64url( iv(16B) || AES-CTR-256(id \n title \n ancestors) )
   so both the title and the parent chain are hidden; hierarchy is metadata, not
   directories. Decrypted docs + tree are cached locally in IndexedDB. */
const OWNER='teecatt', REPO='encrypted_notes', BRANCH='dev';
const PARAMS_URL='https://raw.githubusercontent.com/teecatt/encrypted_params/main/params.json';
const RAW_BASE='https://raw.githubusercontent.com/'+OWNER+'/'+REPO+'/'+BRANCH+'/';
const API_BASE='https://api.github.com/repos/'+OWNER+'/'+REPO;
const ARGON2_URL=new URL('vendor/argon2-bundled.min.js', import.meta.url).href;

export let params=null, aesKey=null, macKey=null;
export const keyReady=()=>!!aesKey;
export const macReady=()=>!!macKey;
export const setKey=k=>{ aesKey=k; };
export const setKeys=(k,m)=>{ aesKey=k; macKey=m||null; };
export const getKeys=()=>({enc:aesKey,mac:macKey});

export async function loadParams(){
  if(params) return params;
  const cached=await cacheGet('params');
  if(cached && cached.salt && cached.magic){
    params=cached;
    params.notesDir=params.notesDir||'notes';
    refreshParams(); // revalidate in background; never blocks a render
    return params;
  }
  return await fetchParams();
}
async function fetchParams(){
  const r=await fetch(PARAMS_URL,{cache:'no-store'});
  if(!r.ok) throw new Error('params 加载失败 '+r.status);
  const j=await r.json();
  j.notesDir=j.notesDir||'notes';
  params=j;
  try{ await cachePut('params',j); }catch(e){}
  return params;
}
function refreshParams(){
  fetch(PARAMS_URL,{cache:'no-store'}).then(r=>r.ok?r.json():null).then(j=>{ if(j&&j.salt) cachePut('params',j); }).catch(()=>{});
}

const hexToBytes=h=>{ const a=new Uint8Array(h.length/2); for(let i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16); return a; };
const b64ToBytes=s=>{ const b=atob(s); const a=new Uint8Array(b.length); for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i); return a; };
const bytesToB64=b=>{ let s=''; b.forEach(x=>s+=String.fromCharCode(x)); return btoa(s); };

let noble=null;
async function rawNoble(pw){
  if(!noble){ const m=await import('https://cdn.jsdelivr.net/npm/@noble/hashes@2.4.0/argon2.js'); noble=m.argon2id; }
  return noble(new TextEncoder().encode(pw), hexToBytes(params.salt), {t:params.time,m:params.memKiB,p:params.parallelism,dkLen:params.hashLen});
}
function rawWasm(pw){
  return new Promise((resolve,reject)=>{
    let w;
    try{
      const code="importScripts("+JSON.stringify(ARGON2_URL)+");self.onmessage=async function(e){var d=e.data;try{var salt=new Uint8Array(d.saltHex.match(/../g).map(function(h){return parseInt(h,16)}));var res=await argon2.hash({pass:d.pass,salt:salt,time:d.t,mem:d.m,parallelism:d.p,hashLen:d.dkLen,type:2});var ikm=await crypto.subtle.importKey('raw',res.hash,'HKDF',false,['deriveBits']);var macRaw=new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(0),info:new TextEncoder().encode('notes-mac-v1')},ikm,256));var ck=await crypto.subtle.importKey('raw',res.hash,{name:'AES-CTR'},false,['encrypt','decrypt']);var mk=await crypto.subtle.importKey('raw',macRaw,{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);self.postMessage({ok:true,enc:ck,mac:mk});}catch(err){self.postMessage({ok:false,error:String(err&&err.message||err)});}};";
      w=new Worker(URL.createObjectURL(new Blob([code],{type:'application/javascript'})));
    }catch(e){ return reject(e); }
    w.onmessage=(e)=>{ w.terminate(); e.data.ok?resolve({enc:e.data.enc,mac:e.data.mac}):reject(new Error(e.data.error)); };
    w.onerror=(e)=>{ w.terminate(); reject(new Error(e.message||'WASM worker error')); };
    w.postMessage({pass:pw,saltHex:params.salt,t:params.time,m:params.memKiB,p:params.parallelism,dkLen:params.hashLen});
  });
}
async function macFromIkm(raw){
  // 用 HKDF 从同一 IKM 派生独立的 HMAC 密钥，避免 AES 与 HMAC 复用同一密钥材料
  const ikm=await crypto.subtle.importKey('raw',raw,'HKDF',false,['deriveBits']);
  const macRaw=new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(0),info:new TextEncoder().encode('notes-mac-v1')},ikm,256));
  return crypto.subtle.importKey('raw',macRaw,{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
}
export async function deriveKey(pw){
  if(!params) await loadParams();
  try{ const k=await rawWasm(pw); aesKey=k.enc; macKey=k.mac; }
  catch(e){ const raw=await rawNoble(pw); aesKey=await crypto.subtle.importKey('raw',raw,{name:'AES-CTR'},false,['encrypt','decrypt']); macKey=await macFromIkm(raw); }
  return aesKey;
}

const concatBytes=(...arrs)=>{ const n=arrs.reduce((s,a)=>s+a.length,0); const out=new Uint8Array(n); let o=0; for(const a of arrs){ out.set(a,o); o+=a.length; } return out; };
const V2_PREFIX='N2:', MAC_LEN=32;
/* 新格式：'N2:' + base64(iv(16) || ct || HMAC-SHA256(iv||ct)(32))，解决 AES-CTR 无完整性校验的问题。
   旧格式（纯 base64(iv||ct)）保持可读，历史笔记不受影响；macKey 缺失时拒绝读写新格式并提示重新解锁。 */
export async function encryptText(text){
  if(!macKey) throw new Error('完整性密钥未就绪：请重新输入密码解锁后再保存');
  const data=new TextEncoder().encode(text);
  const iv=crypto.getRandomValues(new Uint8Array(16));
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-CTR',counter:iv,length:128},aesKey,data));
  const mac=new Uint8Array(await crypto.subtle.sign('HMAC',macKey,concatBytes(iv,ct)));
  return V2_PREFIX+bytesToB64(concatBytes(iv,ct,mac));
}
export async function decryptText(b64){
  const s=String(b64||'').trim();
  if(s.startsWith(V2_PREFIX)){
    if(!macKey) throw new Error('完整性密钥未就绪：请重新输入密码解锁');
    const raw=b64ToBytes(s.slice(V2_PREFIX.length));
    if(raw.length<16+MAC_LEN) throw new Error('密文长度异常，可能已损坏');
    const iv=raw.slice(0,16), ct=raw.slice(16,raw.length-MAC_LEN), mac=raw.slice(raw.length-MAC_LEN);
    const ok=await crypto.subtle.verify('HMAC',macKey,mac,concatBytes(iv,ct));
    if(!ok) throw new Error('完整性校验失败：数据被篡改或密钥不匹配');
    const pt=new Uint8Array(await crypto.subtle.decrypt({name:'AES-CTR',counter:iv,length:128},aesKey,ct));
    return new TextDecoder('utf-8',{fatal:false}).decode(pt);
  }
  const raw=b64ToBytes(s);
  const iv=raw.slice(0,16), ct=raw.slice(16);
  const pt=new Uint8Array(await crypto.subtle.decrypt({name:'AES-CTR',counter:iv,length:128},aesKey,ct));
  return new TextDecoder('utf-8',{fatal:false}).decode(pt);
}
/* encrypted names: segment = base64url( iv(16) || AES-CTR(key, id+"\n"+title+"\n"+ancestors) ).
   Same scheme/key as content. Random IV generated once and stored inside the
   name, so it is stable while reused and two same-title siblings never collide.
   ancestors = comma-joined ancestor ids (empty for roots). Old 2-line names
   (id\ntitle) still decrypt, with ancestors=[]. */
const bytesToB64url=b=>bytesToB64(b).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const b64urlToBytes=s=>{ s=String(s).replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='='; return b64ToBytes(s); };
export async function encryptName(id,title,ancestors){
  const data=new TextEncoder().encode(id+'\n'+String(title).replace(/\n/g,' ')+'\n'+(ancestors||[]).join(','));
  const iv=crypto.getRandomValues(new Uint8Array(16));
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-CTR',counter:iv,length:128},aesKey,data));
  const out=new Uint8Array(iv.length+ct.length); out.set(iv,0); out.set(ct,iv.length);
  return bytesToB64url(out);
}
export async function decryptName(seg){
  try{
    const raw=b64urlToBytes(seg);
    if(raw.length<17) return null;
    const pt=new Uint8Array(await crypto.subtle.decrypt({name:'AES-CTR',counter:raw.slice(0,16),length:128},aesKey,raw.slice(16)));
    const s=new TextDecoder('utf-8',{fatal:false}).decode(pt);
    const parts=s.split('\n');
    if(parts.length<2) return null;
    return {id:parts[0], title:parts[1], ancestors:(parts[2]?parts[2].split(',').filter(Boolean):[])};
  }catch(e){ return null; }
}
export function segFromPath(p){ const parts=p.split('/'); return parts[parts.length-1]; }
export function pathFromSegment(seg){ return params.notesDir+'/'+seg; }

export function packNote(order,title,content){ return params.magic+'\n'+order+'\n'+String(title).replace(/\n/g,' ')+'\n'+content; }
export function parseNote(text){
  if(typeof text!=='string' || !text.startsWith(params.magic)) return null;
  const rest=text.slice(params.magic.length);
  if(rest[0]!=='\n') return null;
  const parts=rest.slice(1).split('\n');
  return {order:parseInt(parts[0],10)||0, title:parts[1]||'', content:parts.slice(2).join('\n')};
}

/* remote */
async function jsdelivrNotes(){
  const r=await fetch('https://data.jsdelivr.com/v1/packages/gh/'+OWNER+'/'+REPO+'@'+BRANCH+'?structure=flat',{cache:'no-store'});
  if(!r.ok) throw new Error('列出远端失败 '+r.status);
  const j=await r.json();
  const pre='/'+params.notesDir+'/';
  return (j.files||[])
    .filter(f=>f.name.startsWith(pre))
    .map(f=>({path:f.name.slice(1), sha:f.hash}));
}
export async function remoteNotes(token, fallback){
  try{
    const h={'Accept':'application/vnd.github+json'};
    if(token) h['Authorization']='Bearer '+token;
    const r=await fetch(API_BASE+'/git/trees/'+BRANCH+'?recursive=1',{headers:h,cache:'no-store'});
    if(!r.ok) throw new Error('github '+r.status);
    const j=await r.json();
    const pre=params.notesDir+'/';
    return (j.tree||[])
      .filter(e=>e.type==='blob' && e.path.startsWith(pre))
      .map(e=>({path:e.path, sha:e.sha}));
  }catch(e){
    if(!fallback) throw new Error('列出远端失败 '+(e.message||e));
    console.warn('GitHub API 列表失败，改用 jsDelivr：'+e.message);
    return await jsdelivrNotes();
  }
}
/* plaintext manifest listing note paths (structure only; no titles/contents).
   Viewer reads it via raw CDN -> 0 GitHub API calls. Updated only when the
   directory/file structure changes. */
export async function readManifest(){
  try{
    const r=await fetch(RAW_BASE+'tree.json?t='+Date.now(),{cache:'no-store'});
    if(!r.ok) return null;
    return await r.json();
  }catch(e){ return null; }
}
export async function putManifest(obj, token, message){
  const path='tree.json';
  let sha=null;
  try{ const cur=await gh('GET','/contents/'+path+'?ref='+BRANCH,null,token); sha=cur&&cur.sha; }catch(e){}
  const body={message, content:bytesToB64(new TextEncoder().encode(JSON.stringify(obj)+'\n')), branch:BRANCH};
  if(sha) body.sha=sha;
  const j=await gh('PUT','/contents/'+path,body,token);
  return j.content&&j.content.sha;
}
export async function fetchNote(path){
  const r=await fetch(RAW_BASE+path+'?t='+Date.now(),{cache:'no-store'});
  if(!r.ok) throw new Error('读取失败 '+path);
  return await r.text();
}
async function gh(method,path,body,token){
  const r=await fetch(API_BASE+path,{method,headers:{'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
  const j=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(j.message||(method+' '+path+' 失败 '+r.status));
  return j;
}
export async function putNote(path, b64text, sha, token, message){
  const payload={message, content:bytesToB64(new TextEncoder().encode(b64text+'\n')), branch:BRANCH};
  if(sha) payload.sha=sha;
  let j;
  try{ j=await gh('PUT','/contents/'+path,payload,token); }
  catch(e){
    // stale/missing sha -> fetch current and retry once
    const cur=await gh('GET','/contents/'+path+'?ref='+BRANCH,null,token).catch(()=>null);
    if(cur&&cur.sha){ payload.sha=cur.sha; j=await gh('PUT','/contents/'+path,payload,token); }
    else throw e;
  }
  return j.content&&j.content.sha;
}
export async function deletePath(path, sha, token, message){
  if(!sha){ try{ const cur=await gh('GET','/contents/'+path+'?ref='+BRANCH,null,token); sha=cur&&cur.sha; }catch(e){} }
  try{ await gh('DELETE','/contents/'+path,{message, sha, branch:BRANCH},token); }
  catch(e){
    // stale/missing sha -> refetch and retry once
    const cur=await gh('GET','/contents/'+path+'?ref='+BRANCH,null,token).catch(()=>null);
    if(cur&&cur.sha){ await gh('DELETE','/contents/'+path,{message, sha:cur.sha, branch:BRANCH},token); }
    else throw e;
  }
}

/* local cache (IndexedDB) */
const DB='en-docs', ST='kv';
function open(){ return new Promise((res,rej)=>{ const r=indexedDB.open(DB,1); r.onupgradeneeded=()=>r.result.createObjectStore(ST); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
export async function cacheGet(k){ try{ const db=await open(); return await new Promise((res,rej)=>{ const q=db.transaction(ST,'readonly').objectStore(ST).get(k); q.onsuccess=()=>res(q.result); q.onerror=()=>rej(q.error); }); }catch(e){ return null; } }
export async function cachePut(k,v){ try{ const db=await open(); await new Promise((res,rej)=>{ const q=db.transaction(ST,'readwrite').objectStore(ST).put(v,k); q.onsuccess=()=>res(); q.onerror=()=>rej(q.error); }); }catch(e){} }
export async function cacheDel(k){ try{ const db=await open(); await new Promise((res,rej)=>{ const q=db.transaction(ST,'readwrite').objectStore(ST).delete(k); q.onsuccess=()=>res(); q.onerror=()=>rej(q.error); }); }catch(e){} }
/* wipe every decrypted artifact: cached notes/meta/cloud/nameSeg + local timeline DB.
   Does NOT touch the GitHub token or theme. */
export async function clearDocs(){
  try{ const db=await open(); await new Promise((res,rej)=>{ const tx=db.transaction(ST,'readwrite'); tx.objectStore(ST).clear(); tx.oncomplete=()=>res(); tx.onerror=()=>rej(tx.error); }); }catch(e){}
  await new Promise(res=>{ try{ const r=indexedDB.deleteDatabase('en-versions'); r.onsuccess=r.onerror=r.onblocked=()=>res(); }catch(e){ res(); } });
}

/* tree helpers. notes: { id: {id,title,content,order,ancestors} } */
export function buildNav(notes){
  const byId=notes, childrenOf={};
  Object.values(notes).forEach(n=>{
    let parent=(n.ancestors&&n.ancestors.length)?n.ancestors[n.ancestors.length-1]:'';
    if(parent && !byId[parent]) parent=''; // orphan -> root
    (childrenOf[parent]=childrenOf[parent]||[]).push(n.id);
  });
  const seen=new Set();
  const mk=pid=>(childrenOf[pid]||[])
    .filter(id=>byId[id] && id!==pid && !seen.has(id))
    .sort((a,b)=>(byId[a].order||0)-(byId[b].order||0))
    .map(id=>{ seen.add(id); const node={title:byId[id].title, id}; const kids=mk(id); if(kids.length) node.children=kids; return node; });
  const roots=mk('');
  // cycle-safe: attach anything unreachable (e.g. garbage/cyclic ids) as flat roots
  Object.keys(byId).forEach(id=>{ if(!seen.has(id)){ seen.add(id); roots.push({title:byId[id].title, id}); } });
  return roots;
}
export function flattenNotes(notes){
  return Object.values(notes).map(n=>({id:n.id,title:n.title,content:n.content||'',order:n.order||0,ancestors:(n.ancestors||[]).slice()}));
}
export function newId(){ return 'n'+Date.now().toString(36)+Math.random().toString(36).slice(2,6); }
