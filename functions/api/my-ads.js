import {getUser} from './account.js';
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
const categories=new Set(['कार','बाइक','मोबाइल','फर्नीचर','इलेक्ट्रॉनिक्स','प्रॉपर्टी','नौकरी','अन्य वस्तुएँ']);
const locations=new Set(['सुमेरपुर','शिवगंज','आसपास के गाँव']);
const hash=async token=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token)))).map(x=>x.toString(16).padStart(2,'0')).join('');
export async function onRequest({request,env}){
 if(!env.DB)return reply({error:'DB binding missing'},503);
 if(request.method!=='POST')return reply({error:'Method not allowed'},405);
 const origin=request.headers.get('origin');if(origin&&new URL(origin).origin!==new URL(request.url).origin)return reply({error:'Invalid origin'},403);
 let body;try{body=await request.json()}catch{return reply({error:'Invalid JSON'},400)}
 const user=await getUser(request,env);const id=Number(body?.id),token=body?.token,action=body?.action;
 if(body?.action==='list'){if(!user)return reply({error:'लॉगिन करें'},401);try{await env.DB.prepare("CREATE TABLE IF NOT EXISTS ad_sales (ad_id INTEGER PRIMARY KEY, sold_at TEXT NOT NULL DEFAULT (datetime('now')))").run();const {results}=await env.DB.prepare('SELECT a.id,a.title,a.price,a.category,a.location,a.description,a.phone,a.status,s.sold_at FROM sb_user_ads ua JOIN ads a ON a.id=ua.ad_id LEFT JOIN ad_sales s ON s.ad_id=a.id WHERE ua.user_id=? ORDER BY a.id DESC').bind(user.id).all();return reply({ads:results||[]})}catch{return reply({error:'डेटाबेस त्रुटि'},500)}}
 if(!Number.isSafeInteger(id)||id<1)return reply({error:'Invalid ad'},400);
 try{
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS ad_owners (ad_id INTEGER PRIMARY KEY,token_hash TEXT NOT NULL)').run();
  const owner=await env.DB.prepare('SELECT token_hash FROM ad_owners WHERE ad_id=?').bind(id).first();
  const owned=user?await env.DB.prepare('SELECT ad_id FROM sb_user_ads WHERE ad_id=? AND user_id=?').bind(id,user.id).first():null;if(!owned&&(!owner||typeof token!=='string'||!/^[a-f0-9]{64}$/.test(token)||owner.token_hash!==await hash(token)))return reply({error:'इस विज्ञापन को बदलने की अनुमति नहीं है'},403);
  if(action==='get'){
   await env.DB.prepare("CREATE TABLE IF NOT EXISTS ad_sales (ad_id INTEGER PRIMARY KEY, sold_at TEXT NOT NULL DEFAULT (datetime('now')))").run();
   const ad=await env.DB.prepare('SELECT a.id,a.title,a.price,a.category,a.location,a.description,a.phone,a.status,a.created_at,s.sold_at FROM ads a LEFT JOIN ad_sales s ON s.ad_id=a.id WHERE a.id=?').bind(id).first();
   return ad?reply({ad}):reply({error:'विज्ञापन नहीं मिला'},404);
  }
  if(action==='edit'){
   const a=body.ad||{},str=(key,max)=>typeof a[key]==='string'&&a[key].trim().length>0&&a[key].trim().length<=max?a[key].trim():null;
   const title=str('title',70),description=str('description',500),phone=str('phone',10),category=str('category',40),location=str('location',40),price=Number(a.price);
   if(!title||!description||!phone||!/^[6-9]\d{9}$/.test(phone)||!categories.has(category)||!locations.has(location)||!Number.isSafeInteger(price)||price<0||price>999999999)return reply({error:'जानकारी सही भरें'},400);
   const result=await env.DB.prepare('UPDATE ads SET title=?,price=?,category=?,location=?,description=?,phone=? WHERE id=?').bind(title,price,category,location,description,phone,id).run();
   return reply({ok:true,changed:result.meta?.changes||0});
  }
  if(action==='sold'||action==='unsold'){
   await env.DB.prepare("CREATE TABLE IF NOT EXISTS ad_sales (ad_id INTEGER PRIMARY KEY, sold_at TEXT NOT NULL DEFAULT (datetime('now')))").run();
   const ad=await env.DB.prepare('SELECT status FROM ads WHERE id=?').bind(id).first();
   if(!ad||ad.status!=='approved')return reply({error:'केवल LIVE विज्ञापन SOLD OUT किया जा सकता है'},400);
   if(action==='sold')await env.DB.prepare("INSERT INTO ad_sales(ad_id,sold_at) VALUES(?,datetime('now')) ON CONFLICT(ad_id) DO NOTHING").bind(id).run();
   else await env.DB.prepare('DELETE FROM ad_sales WHERE ad_id=?').bind(id).run();
   return reply({ok:true});
  }
  if(action==='delete'){
   await env.DB.prepare('DELETE FROM ad_sales WHERE ad_id=?').bind(id).run().catch(()=>{});
   await env.DB.prepare('DELETE FROM ad_owners WHERE ad_id=?').bind(id).run();
   await env.DB.prepare('DELETE FROM ads WHERE id=?').bind(id).run();
   return reply({ok:true});
  }
  return reply({error:'Invalid action'},400);
 }catch{return reply({error:'डेटाबेस में बदलाव नहीं हुआ'},500)}
}