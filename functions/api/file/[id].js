export async function onRequestGet({env,params}){
 if(!env.DB||!env.MEDIA)return new Response('Media unavailable',{status:503});
 const id=Number(params.id);if(!Number.isSafeInteger(id)||id<1)return new Response('Not found',{status:404});
 try{
 const m=await env.DB.prepare("SELECT m.object_key,m.kind,a.status,s.sold_at FROM ad_media m JOIN ads a ON a.id=m.ad_id LEFT JOIN ad_sales s ON s.ad_id=a.id WHERE m.id=?").bind(id).first();
 if(!m||m.status!=='approved'||(m.sold_at&&Date.parse(m.sold_at+'Z')<Date.now()-7*86400000))return new Response('Not found',{status:404});
 const obj=await env.MEDIA.get(m.object_key);if(!obj)return new Response('Not found',{status:404});
 const headers=new Headers();obj.writeHttpMetadata(headers);headers.set('Cache-Control','public,max-age=300');headers.set('X-Content-Type-Options','nosniff');headers.set('Content-Security-Policy',"default-src 'none'; sandbox");
 return new Response(obj.body,{headers});
 }catch{return new Response('Unavailable',{status:500})}
}