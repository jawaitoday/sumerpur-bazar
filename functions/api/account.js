const out=(x,status=200,cookie)=>new Response(JSON.stringify(x),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...(cookie?{'set-cookie':cookie}:{})}});
const sha=async x=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(x)))).map(v=>v.toString(16).padStart(2,'0')).join('');
const random=(n=32)=>Array.from(crypto.getRandomValues(new Uint8Array(n))).map(v=>v.toString(16).padStart(2,'0')).join('');
const cookie=(token,maxAge)=>'sb_session='+token+'; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age='+maxAge;
async function setup(db){
 await db.batch([
 db.prepare('CREATE TABLE IF NOT EXISTS sb_users (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,phone TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,salt TEXT NOT NULL,verified INTEGER NOT NULL DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP)'),
 db.prepare('CREATE TABLE IF NOT EXISTS sb_otps (user_id INTEGER PRIMARY KEY,otp_hash TEXT NOT NULL,expires_at TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,sent_at TEXT NOT NULL)'),
 db.prepare('CREATE TABLE IF NOT EXISTS sb_sessions (token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at TEXT NOT NULL)'),
 db.prepare('CREATE TABLE IF NOT EXISTS sb_user_ads (ad_id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL)')
 ]);
}
const passwordHash=async(pass,salt)=>{let bytes=new TextEncoder().encode(pass+':'+salt);for(let i=0;i<10000;i++)bytes=new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));return Array.from(bytes).map(v=>v.toString(16).padStart(2,'0')).join('')};
export async function getUser(request,env){const token=(request.headers.get('cookie')||'').match(/(?:^|;\s*)sb_session=([a-f0-9]{64})/)?.[1];if(!token)return null;await setup(env.DB);return await env.DB.prepare("SELECT u.id,u.name,u.email,u.phone FROM sb_sessions s JOIN sb_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>datetime('now') AND u.verified=1").bind(await sha(token)).first()}
export async function onRequestPost({request,env}){
 if(!env.DB)return out({error:'Database unavailable'},503);
 const origin=request.headers.get('origin');if(origin&&new URL(origin).origin!==new URL(request.url).origin)return out({error:'Invalid origin'},403);
 let b;try{b=await request.json()}catch{return out({error:'Invalid JSON'},400)}
 try{
 await setup(env.DB);
 if(b.action==='register'){
 const name=String(b.name||'').trim().slice(0,80),email=String(b.email||'').trim().toLowerCase(),phone=String(b.phone||'').trim(),pass=String(b.password||'');
 if(name.length<2||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>150||!/^[6-9]\d{9}$/.test(phone)||pass.length<10||pass.length>128)return out({error:'नाम, ईमेल, मोबाइल और कम से कम 10 अक्षरों का पासवर्ड भरें'},400);
 if(!env.RESEND_API_KEY)return out({error:'Email service अभी सेट नहीं है'},503);
 const existing=await env.DB.prepare('SELECT id,verified FROM sb_users WHERE email=? OR phone=?').bind(email,phone).first();
 if(existing?.verified)return out({error:'ईमेल या मोबाइल पहले से रजिस्टर्ड है'},409);
 const salt=random(16),ph=await passwordHash(pass,salt);
 let uid;
 if(existing){await env.DB.prepare('UPDATE sb_users SET name=?,email=?,phone=?,password_hash=?,salt=? WHERE id=?').bind(name,email,phone,ph,salt,existing.id).run();uid=existing.id}
 else{const r=await env.DB.prepare('INSERT INTO sb_users(name,email,phone,password_hash,salt) VALUES(?,?,?,?,?)').bind(name,email,phone,ph,salt).run();uid=r.meta.last_row_id}
 const last=await env.DB.prepare('SELECT sent_at FROM sb_otps WHERE user_id=?').bind(uid).first();
 if(last&&Date.now()-Date.parse(last.sent_at.replace(' ','T')+'Z')<60000)return out({error:'नया OTP भेजने से पहले 60 सेकंड रुकें'},429);
 const otp=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,'0'),h=await sha(uid+':'+otp+':'+env.RESEND_API_KEY);
 const res=await fetch('https://api.resend.com/emails',{method:'POST',headers:{authorization:'Bearer '+env.RESEND_API_KEY,'content-type':'application/json'},body:JSON.stringify({from:'Sumerpur Bazar <support@sumerpurbazar.in>',to:[email],subject:'Sumerpur Bazar - Email Verification OTP',text:'आपका Sumerpur Bazar OTP: '+otp+'\nयह OTP 5 मिनट तक मान्य है। किसी को न बताएं।'})});
 if(!res.ok)return out({error:'Email OTP नहीं भेजा जा सका। Domain verification जाँचें।'},503);
 await env.DB.prepare("INSERT INTO sb_otps(user_id,otp_hash,expires_at,attempts,sent_at) VALUES(?,?,datetime('now','+5 minutes'),0,datetime('now')) ON CONFLICT(user_id) DO UPDATE SET otp_hash=excluded.otp_hash,expires_at=excluded.expires_at,attempts=0,sent_at=excluded.sent_at").bind(uid,h).run();
 return out({ok:true,message:'ईमेल पर OTP भेज दिया'});
 }
 if(b.action==='verify'){
 const email=String(b.email||'').trim().toLowerCase(),otp=String(b.otp||'');
 if(!/^\d{6}$/.test(otp))return out({error:'6 अंकों का OTP भरें'},400);
 const u=await env.DB.prepare('SELECT id FROM sb_users WHERE email=? AND verified=0').bind(email).first();
 if(!u)return out({error:'अकाउंट नहीं मिला'},404);
 const row=await env.DB.prepare('SELECT * FROM sb_otps WHERE user_id=?').bind(u.id).first();
 if(!row||row.expires_at<=new Date().toISOString().slice(0,19).replace('T',' ')||row.attempts>=5)return out({error:'OTP समाप्त हो गया। नया OTP लें'},400);
 await env.DB.prepare('UPDATE sb_otps SET attempts=attempts+1 WHERE user_id=?').bind(u.id).run();
 if(row.otp_hash!==await sha(u.id+':'+otp+':'+env.RESEND_API_KEY))return out({error:'गलत OTP'},400);
 await env.DB.batch([env.DB.prepare('UPDATE sb_users SET verified=1 WHERE id=?').bind(u.id),env.DB.prepare('DELETE FROM sb_otps WHERE user_id=?').bind(u.id)]);
 return await issueSession(env,u.id);
 }
 if(b.action==='login'){
 const login=String(b.login||'').trim().toLowerCase(),pass=String(b.password||'');
 const u=await env.DB.prepare('SELECT * FROM sb_users WHERE (email=? OR phone=?) AND verified=1').bind(login,login).first();
 if(!u||await passwordHash(pass,u.salt)!==u.password_hash)return out({error:'लॉगिन जानकारी गलत है'},401);
 return await issueSession(env,u.id);
 }
 if(b.action==='logout'){const token=(request.headers.get('cookie')||'').match(/sb_session=([a-f0-9]{64})/)?.[1];if(token)await env.DB.prepare('DELETE FROM sb_sessions WHERE token_hash=?').bind(await sha(token)).run();return out({ok:true},200,cookie('',0))}
 if(b.action==='me'){const user=await getUser(request,env);return out({user:user||null})}
 return out({error:'Invalid action'},400);
 }catch{return out({error:'सर्वर त्रुटि। कृपया दोबारा कोशिश करें'},500)}
}
async function issueSession(env,uid){const token=random();await env.DB.prepare("INSERT INTO sb_sessions(token_hash,user_id,expires_at) VALUES(?,?,datetime('now','+30 days'))").bind(await sha(token),uid).run();return out({ok:true},200,cookie(token,2592000))}
