import {getUser} from './account.js';
const out=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
export async function onRequest({request,env}){
 if(!env.DB)return out({error:'DB binding missing'},503);
 if(!env.ADMIN_EMAIL)return out({error:'Admin email not configured in Cloudflare Pages'},503);
 let user;try{user=await getUser(request,env)}catch{return out({error:'Authentication unavailable'},503)}
 if(!user||user.email.toLowerCase()!==String(env.ADMIN_EMAIL).trim().toLowerCase())return out({error:'केवल अधिकृत Admin को अनुमति है'},403);
 if(request.method==='GET'){
  try{const status=new URL(request.url).searchParams.get('status')||'pending';if(!['pending','approved','rejected','all'].includes(status))return out({error:'Invalid status'},400);
  const sql="SELECT a.id,a.title,a.price,a.category,a.location,a.description,a.phone,a.status,a.photo_url,a.created_at,u.name AS seller_name,u.email AS seller_email FROM ads a LEFT JOIN sb_user_ads ua ON ua.ad_id=a.id LEFT JOIN sb_users u ON u.id=ua.user_id"+(status==='all'?'':" WHERE a.status=?")+" ORDER BY a.id DESC LIMIT 200";
  const stmt=env.DB.prepare(sql);const {results}=await(status==='all'?stmt:stmt.bind(status)).all();return out({ads:results||[],admin:user.email})}catch{return out({error:'Could not load ads'},500)}
 }
 if(request.method!=='POST')return out({error:'Method not allowed'},405);
 const origin=request.headers.get('origin');if(origin&&new URL(origin).origin!==new URL(request.url).origin)return out({error:'Invalid origin'},403);
 if(!request.headers.get('content-type')?.includes('application/json'))return out({error:'JSON required'},415);
 let b;try{b=await request.json()}catch{return out({error:'Invalid JSON'},400)}
 const id=Number(b?.id),action=b?.action;if(!Number.isSafeInteger(id)||id<1||!['approve','reject'].includes(action))return out({error:'Invalid request'},400);
 try{const next=action==='approve'?'approved':'rejected';const r=await env.DB.prepare('UPDATE ads SET status=? WHERE id=?').bind(next,id).run();if(!r.meta?.changes)return out({error:'विज्ञापन नहीं मिला'},404);return out({ok:true,status:next})}catch{return out({error:'Update failed'},500)}
}
