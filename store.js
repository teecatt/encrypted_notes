/* Shared encrypted per-note storage.
   Remote: one text file per note under notesDir, mirroring the note hierarchy.
   File content = base64( iv(16B) || AES-CTR-256(magic \n order \n title \n markdown) ).
   Decrypted docs + tree are cached locally in IndexedDB. */
const OWNER='teecatt', REPO='encrypted_notes', BRANCH='dev';
const PARAMS_URL='https://raw.githubusercontent.com/teecatt/encrypted_params/main/params.json';
const RAW_BASE='https://raw.githubusercontent.com/'+OWNER+'/'+REPO+'/'+BRANCH+'/';
const API_BASE='https://api.github.com/repos/'+OWNER+'/'+REPO;
const ARGON2_URL=new URL('vendor/argon2-bundled.min.js', import.meta.url).href;

export let params=null, aesKey=null;
export const keyReady=()=>!!aesKey;
export const setKey=k=>{ aesKey=k; };

export async function loadParams(){
  if(params) return params;
  const r=await fetch(PARAMS_URL,{cache:'no-store'});
  if(!r.ok) throw new Error('params 加载失败 '+r.status);
  params=await r.json();
  params.notesDir=params.notesDir||'notes';
  return params;
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
      const code="importScripts("+JSON.stringify(ARGON2_URL)+");self.onmessage=async function(e){var d=e.data;try{var salt=new Uint8Array(d.saltHex.match(/../g).map(function(h){return parseInt(h,16)}));var res=await argon2.hash({pass:d.pass,salt:salt,time:d.t,mem:d.m,parallelism:d.p,hashLen:d.dkLen,type:2});var ck=await crypto.subtle.importKey('raw',res.hash,{name:'AES-CTR'},false,['encrypt','decrypt']);self.postMessage({ok:true,key:ck});}catch(err){self.postMessage({ok:false,error:String(err&&err.message||err)});}};";
      w=new Worker(URL.createObjectURL(new Blob([code],{type:'application/javascript'})));
    }catch(e){ return reject(e); }
    w.onmessage=(e)=>{ w.terminate(); e.data.ok?resolve(e.data.key):reject(new Error(e.data.error)); };
    w.onerror=(e)=>{ w.terminate(); reject(new Error(e.message||'WASM worker error')); };
    w.postMessage({pass:pw,saltHex:params.salt,t:params.time,m:params.memKiB,p:params.parallelism,dkLen:params.hashLen});
  });
}
export async function deriveKey(pw){
  if(!params) await loadParams();
  try{ aesKey=await rawWasm(pw); }
  catch(e){ const raw=await rawNoble(pw); aesKey=await crypto.subtle.importKey('raw',raw,{name:'AES-CTR'},false,['encrypt','decrypt']); }
  return aesKey;
}

export async function encryptText(text){
  const data=new TextEncoder().encode(text);
  const iv=crypto.getRandomValues(new Uint8Array(16));
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-CTR',counter:iv,length:128},aesKey,data));
  const out=new Uint8Array(iv.length+ct.length); out.set(iv,0); out.set(ct,iv.length);
  return bytesToB64(out);
}
export async function decryptText(b64){
  const raw=b64ToBytes(b64);
  const iv=raw.slice(0,16), ct=raw.slice(16);
  const pt=new Uint8Array(await crypto.subtle.decrypt({name:'AES-CTR',counter:iv,length:128},aesKey,ct));
  return new TextDecoder('utf-8',{fatal:false}).decode(pt);
}
export function packNote(order,title,content){ return params.magic+'\n'+order+'\n'+String(title).replace(/\n/g,' ')+'\n'+content; }
export function parseNote(text){
  if(typeof text!=='string' || !text.startsWith(params.magic)) return null;
  const rest=text.slice(params.magic.length);
  if(rest[0]!=='\n') return null;
  const parts=rest.slice(1).split('\n');
  return {order:parseInt(parts[0],10)||0, title:parts[1]||'', content:parts.slice(2).join('\n')};
}

/* paths */
export function notePath(id, ancestors){ return params.notesDir+'/'+((ancestors&&ancestors.length)?ancestors.join('/')+'/':'')+id+'/note'; }
export function idFromPath(p){ const s=p.split('/'); return s[s.length-2]; }
export function ancestorsFromPath(p){ const s=p.split('/'); return s.slice(1, s.length-2); }

/* remote */
async function jsdelivrNotes(){
  const r=await fetch('https://data.jsdelivr.com/v1/packages/gh/'+OWNER+'/'+REPO+'@'+BRANCH+'?structure=flat',{cache:'no-store'});
  if(!r.ok) throw new Error('列出远端失败 '+r.status);
  const j=await r.json();
  const pre='/'+params.notesDir+'/';
  return (j.files||[])
    .filter(f=>f.name.startsWith(pre) && f.name.endsWith('/note'))
    .map(f=>({path:f.name.slice(1), sha:f.hash, id:idFromPath(f.name.slice(1))}));
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
      .filter(e=>e.type==='blob' && e.path.startsWith(pre) && e.path.endsWith('/note'))
      .map(e=>({path:e.path, sha:e.sha, id:idFromPath(e.path)}));
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
  const j=await gh('PUT','/contents/'+path,payload,token);
  return j.content&&j.content.sha;
}
export async function deletePath(path, sha, token, message){
  await gh('DELETE','/contents/'+path,{message, sha, branch:BRANCH},token);
}

/* local cache (IndexedDB) */
const DB='en-docs', ST='kv';
function open(){ return new Promise((res,rej)=>{ const r=indexedDB.open(DB,1); r.onupgradeneeded=()=>r.result.createObjectStore(ST); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
export async function cacheGet(k){ try{ const db=await open(); return await new Promise((res,rej)=>{ const q=db.transaction(ST,'readonly').objectStore(ST).get(k); q.onsuccess=()=>res(q.result); q.onerror=()=>rej(q.error); }); }catch(e){ return null; } }
export async function cachePut(k,v){ try{ const db=await open(); await new Promise((res,rej)=>{ const q=db.transaction(ST,'readwrite').objectStore(ST).put(v,k); q.onsuccess=()=>res(); q.onerror=()=>rej(q.error); }); }catch(e){} }
export async function cacheDel(k){ try{ const db=await open(); await new Promise((res,rej)=>{ const q=db.transaction(ST,'readwrite').objectStore(ST).delete(k); q.onsuccess=()=>res(); q.onerror=()=>rej(q.error); }); }catch(e){} }

/* tree helpers. notes: { id: {id,title,content,order,ancestors} } */
export function buildNav(notes){
  const byId=notes, childrenOf={};
  Object.values(notes).forEach(n=>{
    const parent=(n.ancestors&&n.ancestors.length)?n.ancestors[n.ancestors.length-1]:'';
    (childrenOf[parent]=childrenOf[parent]||[]).push(n.id);
  });
  const mk=pid=>(childrenOf[pid]||[])
    .sort((a,b)=>(byId[a].order||0)-(byId[b].order||0))
    .map(id=>{ const n=byId[id]; const node={title:n.title, id}; const kids=mk(id); if(kids.length) node.children=kids; return node; });
  return mk('');
}
export function flattenNotes(notes){
  return Object.values(notes).map(n=>({id:n.id,title:n.title,content:n.content||'',order:n.order||0,ancestors:(n.ancestors||[]).slice()}));
}
export function newId(){ return 'n'+Date.now().toString(36)+Math.random().toString(36).slice(2,6); }
