import {getUser} from './account.js';
const categories=new Set(['कार','बाइक','मोबाइल','फर्नीचर','इलेक्ट्रॉनिक्स','प्रॉपर्टी','नौकरी','अन्य वस्तुएँ']);
const locations=new Set(['सुमेरपुर','शिवगंज','आसपास के गाँव']);
const reply=(obj,status=200)=>new Response(JSON.stringify(obj),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
export async function onRequestGet({env}) {
 if(!env.DB)return reply({error:'DB binding missing'},503);
 try {await env.DB.prepare("CREATE TABLE IF NOT EXISTS ad_sales (ad_id INTEGER PRIMARY KEY, sold_at TEXT NOT NULL DEFAULT (datetime('now')))").run();const {results}=await env.DB.prepare("SELECT a.id,a.title,a.price,a.category,a.location,a.description,a.phone,(SELECT '/api/file/' || m.id FROM ad_media m JOIN ad_media_screening sc ON sc.media_id=m.id WHERE m.ad_id=a.id AND m.kind='photo' AND sc.verdict='safe' ORDER BY m.id LIMIT 1) AS photo_url,a.created_at,s.sold_at FROM ads a LEFT JOIN ad_sales s ON s.ad_id=a.id WHERE a.status='approved' AND EXISTS (SELECT 1 FROM ad_media m JOIN ad_media_screening sc ON sc.media_id=m.id WHERE m.ad_id=a.id AND m.kind='photo' AND sc.verdict='safe') AND (s.sold_at IS NULL OR s.sold_at > datetime('now','-7 days')) ORDER BY a.id DESC LIMIT 100").all();return reply({ads:results||[]});}
 catch {return reply({error:'Database unavailable'},500);}
}
export async function onRequestPost({request,env}) {
 if(!env.DB)return reply({error:'DB binding missing'},503);
 const user=await getUser(request,env);if(!user)return reply({error:'पहले अकाउंट बनाकर लॉगिन करें'},401);
 const origin=request.headers.get('origin');
 if(origin&&new URL(origin).hostname!==new URL(request.url).hostname)return reply({error:'Invalid origin'},403);
 if(!request.headers.get('content-type')?.includes('application/json'))return reply({error:'JSON required'},415);
 let a;try{a=await request.json()}catch{return reply({error:'Invalid JSON'},400)}
 if(!a||typeof a!=='object'||Array.isArray(a))return reply({error:'Invalid data'},400);
 const get=(k,max)=>typeof a[k]==='string'&&a[k].trim().length>0&&a[k].trim().length<=max?a[k].trim():null;
 const title=get('title',70),description=get('description',500),phone=get('phone',10),category=get('category',40),location=get('location',40),price=Number(a.price);
 if(!title||!description||!phone||!/^[6-9]\d{9}$/.test(phone)||!categories.has(category)||!locations.has(location)||!Number.isSafeInteger(price)||price<0||price>999999999)return reply({error:'जानकारी सही भरें'},400);
 try {await env.DB.prepare('CREATE TABLE IF NOT EXISTS ad_owners (ad_id INTEGER PRIMARY KEY,token_hash TEXT NOT NULL)').run();const token=Array.from(crypto.getRandomValues(new Uint8Array(32))).map(x=>x.toString(16).padStart(2,'0')).join('');const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token)))).map(x=>x.toString(16).padStart(2,'0')).join('');const inserted=await env.DB.prepare("INSERT INTO ads(title,price,category,location,description,phone,status) VALUES(?,?,?,?,?,?,'pending')").bind(title,price,category,location,description,phone).run();const id=inserted.meta?.last_row_id;if(!id)throw Error('Missing id');await env.DB.prepare('INSERT INTO ad_owners(ad_id,token_hash) VALUES(?,?)').bind(id,digest).run();await env.DB.prepare('INSERT INTO sb_user_ads(ad_id,user_id) VALUES(?,?)').bind(id,user.id).run();return reply({ok:true,status:'pending',id,edit_token:token},201);}
 catch{return reply({error:'Save failed'},500)}
}
