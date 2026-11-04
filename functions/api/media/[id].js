import {getUser} from '../account.js';
const json=(x,status=200)=>new Response(JSON.stringify(x),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
const digest=async t=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(t)))).map(x=>x.toString(16).padStart(2,'0')).join('');
export async function onRequest({request,env,params}){
 if(!env.DB)return json({error:'DB binding missing'},503);
 if(!env.MEDIA)return json({error:'Cloudflare R2 MEDIA binding missing'},503);
 const id=Number(params.id);if(!Number.isSafeInteger(id)||id<1)return json({error:'Invalid ad'},400);
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS ad_media (id INTEGER PRIMARY KEY AUTOINCREMENT,ad_id INTEGER NOT NULL,object_key TEXT NOT NULL,kind TEXT NOT NULL,created_at TEXT DEFAULT (datetime('now')))").run();
 const url=new URL(request.url);
 if(request.method==='GET'){
  const ad=await env.DB.prepare("SELECT status FROM ads WHERE id=?").bind(id).first();
  if(!ad||ad.status!=='approved')return json({error:'Not available'},404);
  const {results}=await env.DB.prepare('SELECT id,kind FROM ad_media WHERE ad_id=? ORDER BY id').bind(id).all();
  return json({media:results||[]});
 }
 if(request.method!=='POST')return json({error:'Method not allowed'},405);
 const origin=request.headers.get('origin');if(origin&&new URL(origin).origin!==url.origin)return json({error:'Invalid origin'},403);
 const token=request.headers.get('x-ad-edit-token')||'';const user=await getUser(request,env);const userOwner=user?await env.DB.prepare('SELECT ad_id FROM sb_user_ads WHERE ad_id=? AND user_id=?').bind(id,user.id).first():null;
 if(!userOwner&&!/^[a-f0-9]{64}$/.test(token))return json({error:'Login required'},401);
 const owner=await env.DB.prepare('SELECT token_hash FROM ad_owners WHERE ad_id=?').bind(id).first();
 if(!userOwner&&(!owner||owner.token_hash!==await digest(token)))return json({error:'Not authorized'},403);
 const form=await request.formData(),file=form.get('file');
 if(!(file instanceof File))return json({error:'Choose a file'},400);
 const isImage=file.type==='image/jpeg'||file.type==='image/webp'||file.type==='image/png';
 const isVideo=file.type==='video/mp4'||file.type==='video/webm';
 if(!isImage&&!isVideo)return json({error:'JPG, PNG, WEBP, MP4 or WEBM only'},400);
 if(file.size>(isImage?5:30)*1024*1024)return json({error:'Photo max 5MB; video max 30MB'},413);
 const kind=isImage?'photo':'video',count=await env.DB.prepare('SELECT COUNT(*) n FROM ad_media WHERE ad_id=? AND kind=?').bind(id,kind).first();
 if(count.n>=(isImage?5:1))return json({error:'Maximum 5 photos and 1 video'},400);
 const ext=({'image/jpeg':'jpg','image/png':'png','image/webp':'webp','video/mp4':'mp4','video/webm':'webm'})[file.type];
 const key='ads/'+id+'/'+crypto.randomUUID()+'.'+ext;
 try{await env.MEDIA.put(key,file.stream(),{httpMetadata:{contentType:file.type}});const result=await env.DB.prepare('INSERT INTO ad_media(ad_id,object_key,kind) VALUES(?,?,?)').bind(id,key,kind).run();return json({ok:true,id:result.meta.last_row_id,kind},201)}
 catch{return json({error:'Upload failed'},500)}
}