// Cloudflare Worker API for Dog Day Out. This is a secure starter, not a complete production backend.
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json','cache-control':'no-store'}});
const bytes=(s)=>new TextEncoder().encode(s);
const hex=(arr)=>Array.from(new Uint8Array(arr)).map(b=>b.toString(16).padStart(2,'0')).join('');
const rand=()=>crypto.randomUUID();
async function hashPassword(password,salt){const k=await crypto.subtle.importKey('raw',bytes(password),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:bytes(salt),iterations:210000,hash:'SHA-256'},k,256));}
async function sha(s){return hex(await crypto.subtle.digest('SHA-256',bytes(s)));}
async function current(request,env){const token=(request.headers.get('cookie')||'').match(/(?:^|;\s*)ddo_session=([^;]+)/)?.[1];if(!token)return null;return await env.DB.prepare('SELECT u.id,u.email,u.role,u.email_verified,u.approved FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').bind(await sha(token),Date.now()).first();}
async function body(request){try{return await request.json()}catch{return {}}}
function cookie(token){return `ddo_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`;}
const err=(message,status=400)=>json({error:message},status);
const allowedOrigin=(request,env)=>{const origin=request.headers.get('origin');return !origin||origin===new URL(request.url).origin||(env.SITE_ORIGIN&&origin===env.SITE_ORIGIN)};
export default {async fetch(request,env){
 const url=new URL(request.url),p=url.pathname; if(!p.startsWith('/api/'))return err('Not found',404);
 if(!allowedOrigin(request,env))return err('Origin not allowed',403);
 if(!env.DB)return err('D1 binding missing',503);
 try{
  if(p==='/api/health'&&request.method==='GET')return json({ok:true,service:'Dog Day Out API'});
  if(p==='/api/auth/register'&&request.method==='POST'){
   const b=await body(request),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');
   if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<12)return err('Use a valid email and password of at least 12 characters');
   const salt=rand();try{await env.DB.prepare('INSERT INTO users(id,email,password_hash,salt) VALUES(?,?,?,?)').bind(rand(),email,await hashPassword(password,salt),salt).run()}catch{return err('Account cannot be created',409)}
   return json({message:'Registration received. Email verification and staff approval are required before access. Email delivery is not configured yet.'},201);
  }
  if(p==='/api/auth/login'&&request.method==='POST'){
   const b=await body(request),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');
   const u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
   if(!u||await hashPassword(password,u.salt)!==u.password_hash)return err('Invalid credentials',401);
   if(!u.email_verified)return err('Email not verified',403);
   if(!u.approved)return err('Account awaiting approval',403);
   const token=rand()+rand(),expires=Date.now()+7*86400000;
   await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(await sha(token),u.id,expires).run();
   const response=json({user:{id:u.id,email:u.email,role:u.role}});response.headers.set('set-cookie',cookie(token));return response;
  }
  const u=await current(request,env);
  if(p==='/api/auth/me'&&request.method==='GET')return json({user:u});
  if(p==='/api/auth/logout'&&request.method==='POST'){const token=(request.headers.get('cookie')||'').match(/ddo_session=([^;]+)/)?.[1];if(token)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(token)).run();const r=json({ok:true});r.headers.set('set-cookie','ddo_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');return r;}
  if(p==='/api/schedule'&&request.method==='GET')return json({days:(await env.DB.prepare('SELECT * FROM schedule ORDER BY day').all()).results});
  if(p==='/api/updates'&&request.method==='GET')return json({updates:(await env.DB.prepare('SELECT * FROM updates ORDER BY created_at DESC LIMIT 50').all()).results});
  if(!u)return err('Sign in required',401);
  const staff=u.role==='staff'||u.role==='admin';
  if(p==='/api/dogs'&&request.method==='GET')return json({dogs:(await env.DB.prepare(staff?'SELECT * FROM dogs ORDER BY created_at DESC':'SELECT * FROM dogs WHERE parent_id=? ORDER BY created_at DESC').bind(...(staff?[]:[u.id])).all()).results});
  if(p==='/api/dogs'&&request.method==='POST'){
   if(u.role!=='parent')return err('Parent account required',403);const b=await body(request),name=String(b.name||'').trim();if(!name||name.length>100)return err('Enter a dog name (100 characters max)');
   const id=rand();await env.DB.prepare('INSERT INTO dogs(id,parent_id,name,breed,notes) VALUES(?,?,?,?,?)').bind(id,u.id,name,String(b.breed||'').slice(0,100),String(b.notes||'').slice(0,2000)).run();return json({id},201);
  }
  if(p==='/api/bookings'&&request.method==='GET')return json({bookings:(await env.DB.prepare(staff?'SELECT b.*,d.name FROM bookings b JOIN dogs d ON d.id=b.dog_id ORDER BY b.day':'SELECT b.*,d.name FROM bookings b JOIN dogs d ON d.id=b.dog_id WHERE d.parent_id=? ORDER BY b.day').bind(...(staff?[]:[u.id])).all()).results});
  if(p==='/api/bookings'&&request.method==='POST'){
   if(u.role!=='parent')return err('Parent account required',403);const b=await body(request),day=String(b.day||''),dogId=String(b.dog_id||'');
   if(!/^\d{4}-\d{2}-\d{2}$/.test(day))return err('Invalid date');
   const today=new Date().toLocaleDateString('en-CA',{timeZone:'America/New_York'}),now=new Date(today+'T12:00:00Z'),target=new Date(day+'T12:00:00Z'),delta=Math.round((target-now)/86400000);
   if(!Number.isFinite(target.getTime())||delta<0||delta>30)return err('Choose a date within the next 30 days');
   const dog=await env.DB.prepare('SELECT id FROM dogs WHERE id=? AND parent_id=?').bind(dogId,u.id).first();if(!dog)return err('Dog not found',404);
   try{await env.DB.prepare('INSERT INTO bookings(id,dog_id,day) VALUES(?,?,?)').bind(rand(),dogId,day).run()}catch{return err('A request already exists for that dog and date',409)}return json({status:'pending'},201);
  }
  if(p.startsWith('/api/bookings/')&&request.method==='PATCH'){
   if(!staff)return err('Staff only',403);const b=await body(request);if(!['approved','declined'].includes(b.status))return err('Invalid status');
   const result=await env.DB.prepare('UPDATE bookings SET status=? WHERE id=?').bind(b.status,p.split('/')[3]).run();return json({ok:result.meta.changes>0});
  }
  if(p==='/api/staff/parents'&&request.method==='GET'){if(!staff)return err('Staff only',403);return json({parents:(await env.DB.prepare("SELECT id,email,email_verified,approved,created_at FROM users WHERE role='parent' ORDER BY created_at DESC").all()).results});}
  if(p.startsWith('/api/staff/parents/')&&request.method==='PATCH'){
   if(!staff)return err('Staff only',403);const b=await body(request);if(typeof b.approved!=='boolean')return err('Invalid approval');const result=await env.DB.prepare("UPDATE users SET approved=? WHERE id=? AND role='parent' AND email_verified=1").bind(b.approved?1:0,p.split('/')[4]).run();return json({ok:result.meta.changes>0});
  }
  if(p==='/api/schedule'&&request.method==='PUT'){
   if(!staff)return err('Staff only',403);const b=await body(request),day=Number(b.day);if(!Number.isInteger(day)||day<0||day>6)return err('Invalid weekday');
   await env.DB.prepare('INSERT INTO schedule(day,destination,route,running) VALUES(?,?,?,?) ON CONFLICT(day) DO UPDATE SET destination=excluded.destination,route=excluded.route,running=excluded.running').bind(day,String(b.destination||'').slice(0,150),String(b.route||'').slice(0,2000),b.running?1:0).run();return json({ok:true});
  }
  if(p==='/api/updates'&&request.method==='POST'){
   if(!staff)return err('Staff only',403);const b=await body(request),message=String(b.message||'').trim();if(!message||message.length>2000)return err('Enter an update (up to 2000 characters)');
   await env.DB.prepare('INSERT INTO updates(id,message,latitude,longitude) VALUES(?,?,?,?)').bind(rand(),message,Number.isFinite(b.latitude)?b.latitude:null,Number.isFinite(b.longitude)?b.longitude:null).run();return json({ok:true},201);
  }
  return err('Not found',404);
 }catch(e){return err('Server request failed',500)}
}};
