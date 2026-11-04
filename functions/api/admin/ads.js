const response=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'}});
async function authorized(request,env){
 const supplied=request.headers.get('authorization')||'';
 if(!env.SUMERPURBAZAR||!supplied.startsWith('Bearer '))return false;
 const candidate=supplied.slice(7);
 if(candidate.length<9||candidate.length>512)return false;
 const hash=async s=>new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)));
 const a=await hash(candidate),b=await hash(env.SUMERPURBAZAR);let mismatch=0;
 for(let i=0;i<a.length;i++)mismatch|=a[i]^b[i];
 return mismatch===0;
}
export async function onRequest({request,env}){
 if(!env.DB)return response({error:'DB binding missing in this deployment'},503);
 if(!env.SUMERPURBAZAR)return response({error:'SUMERPURBAZAR secret missing in this deployment'},503);
 if(!(await authorized(request,env)))return response({error:'अनुमति नहीं है। पासवर्ड जाँचें।'},401);
 if(request.method==='GET'){
  try{await env.DB.prepare("CREATE TABLE IF NOT EXISTS ad_sales (ad_id INTEGER PRIMARY KEY, sold_at TEXT NOT NULL DEFAULT (datetime('now')))").run();const {results}=await env.DB.prepare("SELECT a.id,a.title,a.price,a.category,a.location,a.description,a.phone,a.status,a.created_at,s.sold_at FROM ads a LEFT JOIN ad_sales s ON s.ad_id=a.id ORDER BY a.id DESC LIMIT 200").all();return response({ads:results||[]})}catch{return response({error:'डेटाबेस उपलब्ध नहीं है'},500)}
 }
 if(request.method!=='POST')return response({error:'Method not allowed'},405);
 const origin=request.headers.get('origin');if(origin&&new URL(origin).origin!==new URL(request.url).origin)return response({error:'Invalid origin'},403);
 let body;try{body=await request.json()}catch{return response({error:'Invalid JSON'},400)}
 const id=Number(body?.id),action=body?.action;
 if(!Number.isSafeInteger(id)||id<1||!['approve','reject','delete','sold','unsold'].includes(action))return response({error:'Invalid request'},400);
 try{
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS ad_sales (ad_id INTEGER PRIMARY KEY, sold_at TEXT NOT NULL DEFAULT (datetime('now')))").run();
  if(action==='sold'){const result=await env.DB.prepare("INSERT INTO ad_sales(ad_id,sold_at) SELECT id,datetime('now') FROM ads WHERE id=? AND status='approved' ON CONFLICT(ad_id) DO NOTHING").bind(id).run();return response({ok:true,changed:result.meta?.changes||0})}
  if(action==='unsold'){const result=await env.DB.prepare('DELETE FROM ad_sales WHERE ad_id=?').bind(id).run();return response({ok:true,changed:result.meta?.changes||0})}
  if(action==='delete')await env.DB.prepare('DELETE FROM ad_sales WHERE ad_id=?').bind(id).run();
  const stmt=action==='delete'?"DELETE FROM ads WHERE id=?":"UPDATE ads SET status=? WHERE id=?";
  const result=action==='delete'?await env.DB.prepare(stmt).bind(id).run():await env.DB.prepare(stmt).bind(action==='approve'?'approved':'rejected',id).run();
  return response({ok:true,changed:result.meta?.changes||0});
 }catch{return response({error:'बदलाव सेव नहीं हुआ'},500)}
}
