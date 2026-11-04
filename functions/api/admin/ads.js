const response=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'}});
async function authorized(request,env){
 const supplied=request.headers.get('authorization')||'';
 if(!env.ADMIN_TOKEN||!supplied.startsWith('Bearer '))return false;
 const candidate=supplied.slice(7);
 if(candidate.length<24||candidate.length>512)return false;
 const hash=async s=>new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)));
 const a=await hash(candidate),b=await hash(env.ADMIN_TOKEN);let mismatch=0;
 for(let i=0;i<a.length;i++)mismatch|=a[i]^b[i];
 return mismatch===0;
}
export async function onRequest({request,env}){
 if(!env.DB||!env.ADMIN_TOKEN)return response({error:'DB or ADMIN_TOKEN not configured'},503);
 if(!(await authorized(request,env)))return response({error:'अनुमति नहीं है। पासवर्ड जाँचें।'},401);
 if(request.method==='GET'){
  try{const {results}=await env.DB.prepare("SELECT id,title,price,category,location,description,phone,status,created_at FROM ads ORDER BY id DESC LIMIT 200").all();return response({ads:results||[]})}catch{return response({error:'डेटाबेस उपलब्ध नहीं है'},500)}
 }
 if(request.method!=='POST')return response({error:'Method not allowed'},405);
 const origin=request.headers.get('origin');if(origin&&new URL(origin).origin!==new URL(request.url).origin)return response({error:'Invalid origin'},403);
 let body;try{body=await request.json()}catch{return response({error:'Invalid JSON'},400)}
 const id=Number(body?.id),action=body?.action;
 if(!Number.isSafeInteger(id)||id<1||!['approve','reject','delete'].includes(action))return response({error:'Invalid request'},400);
 try{
  const stmt=action==='delete'?"DELETE FROM ads WHERE id=?":"UPDATE ads SET status=? WHERE id=?";
  const result=action==='delete'?await env.DB.prepare(stmt).bind(id).run():await env.DB.prepare(stmt).bind(action==='approve'?'approved':'rejected',id).run();
  return response({ok:true,changed:result.meta?.changes||0});
 }catch{return response({error:'बदलाव सेव नहीं हुआ'},500)}
}
