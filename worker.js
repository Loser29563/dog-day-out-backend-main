// Dog Day Out Cloudflare API — parent signup, booking eligibility and staff administration.
const J=(v,s=200)=>new Response(JSON.stringify(v),{status:s,headers:{'content-type':'application/json','cache-control':'no-store'}});
const E=(message,status=400)=>J({error:message},status);
const enc=new TextEncoder();
const hex=b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');
const uid=()=>crypto.randomUUID();
const digest=async s=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
async function hash(p,s){const k=await crypto.subtle.importKey('raw',enc.encode(p),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(s),iterations:210000,hash:'SHA-256'},k,256));}
const parse=async r=>{try{return await r.json()}catch{return {}}};
const cookie=(t,max=604800)=>`ddo_session=${t}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${max}`;
async function who(r,env){const t=(r.headers.get('cookie')||'').match(/(?:^|;\s*)ddo_session=([^;]+)/)?.[1];if(!t)return null;return env.DB.prepare('SELECT u.id,u.email,u.role,u.approved FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').bind(await digest(t),Date.now()).first();}
async function signin(u,env){const t=uid()+uid();await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(await digest(t),u.id,Date.now()+604800000).run();const r=J({user:{id:u.id,email:u.email,role:u.role,booking_approved:!!u.approved}});r.headers.set('set-cookie',cookie(t));return r;}
const validEmail=e=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
export default {async fetch(request,env){
 const url=new URL(request.url),p=url.pathname,method=request.method;
 if(!p.startsWith('/api/'))return E('Not found',404);
 if(!env.DB)return E('D1 binding missing',503);
 const origin=request.headers.get('origin');if(origin&&origin!==url.origin&&origin!==env.SITE_ORIGIN)return E('Origin not allowed',403);
 try{
  if(p==='/api/health'&&method==='GET')return J({ok:true,service:'Dog Day Out API'});
  if(p==='/api/auth/register'&&method==='POST'){
   const b=await parse(request),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');
   if(!validEmail(email)||password.length<12||password.length>200)return E('Enter a valid email and password of at least 12 characters');
   const id=uid(),salt=uid();try{await env.DB.prepare("INSERT INTO users(id,email,password_hash,salt,role,email_verified,approved) VALUES(?,?,?,?,'parent',0,0)").bind(id,email,await hash(password,salt),salt).run();}catch{return E('This email may already have an account',409)}
   // Email verification is not yet configured. Do not claim it is enabled.
   return signin({id,email,role:'parent',approved:0},env);
  }
  if(p==='/api/auth/login'&&method==='POST'){
   const b=await parse(request),email=String(b.email||'').trim().toLowerCase(),u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
   if(!u||await hash(String(b.password||''),u.salt)!==u.password_hash)return E('Incorrect email or password',401);
   return signin(u,env);
  }
  if(p==='/api/auth/staff-setup'&&method==='POST'){
   if(!env.STAFF_SETUP_KEY||env.STAFF_SETUP_KEY.length<24)return E('Staff setup is not configured. Set STAFF_SETUP_KEY as a Worker secret.',503);
   const b=await parse(request),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');
   if(!validEmail(email)||password.length<12||password.length>200)return E('Enter a valid staff email and password of at least 12 characters');
   if(String(b.setup_key||'')!==env.STAFF_SETUP_KEY)return E('Invalid staff setup key',403);
   // Bootstrap only once. Further staff provisioning requires a separate invitation feature.
   const existing=await env.DB.prepare("SELECT id FROM users WHERE role IN ('staff','admin') LIMIT 1").first();if(existing)return E('Staff account already exists. Additional staff accounts require administrator setup.',409);
   const id=uid(),salt=uid();try{await env.DB.prepare("INSERT INTO users(id,email,password_hash,salt,role,email_verified,approved) VALUES(?,?,?,?,'admin',0,1)").bind(id,email,await hash(password,salt),salt).run();}catch{return E('Unable to create staff account',409)}
   return signin({id,email,role:'admin',approved:1},env);
  }
  const u=await who(request,env);
  if(p==='/api/auth/me'&&method==='GET')return J({user:u?{...u,booking_approved:!!u.approved}:null});
  if(p==='/api/auth/logout'&&method==='POST'){const t=(request.headers.get('cookie')||'').match(/ddo_session=([^;]+)/)?.[1];if(t)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(t)).run();const r=J({ok:true});r.headers.set('set-cookie',cookie('',0));return r;}
  if(p==='/api/schedule'&&method==='GET')return J({days:(await env.DB.prepare('SELECT * FROM schedule ORDER BY day').all()).results});
  if(p==='/api/updates'&&method==='GET')return J({updates:(await env.DB.prepare('SELECT * FROM updates ORDER BY created_at DESC LIMIT 50').all()).results});
  if(!u)return E('Please sign in',401);
  const staff=u.role==='staff'||u.role==='admin';
  if(p==='/api/dogs'&&method==='GET')return J({dogs:(await (staff?env.DB.prepare('SELECT * FROM dogs ORDER BY created_at DESC'):env.DB.prepare('SELECT * FROM dogs WHERE parent_id=? ORDER BY created_at DESC').bind(u.id)).all()).results});
  if(p==='/api/dogs'&&method==='POST'){
   if(staff)return E('Parent account required',403);const b=await parse(request),name=String(b.name||'').trim();if(!name||name.length>100)return E('Enter your dog’s name');
   const id=uid();await env.DB.prepare('INSERT INTO dogs(id,parent_id,name,breed,notes) VALUES(?,?,?,?,?)').bind(id,u.id,name,String(b.breed||'').slice(0,100),String(b.notes||'').slice(0,2000)).run();return J({id},201);
  }
  if(p==='/api/bookings'&&method==='GET')return J({bookings:(await (staff?env.DB.prepare('SELECT b.*,d.name,d.parent_id FROM bookings b JOIN dogs d ON d.id=b.dog_id ORDER BY b.day'):env.DB.prepare('SELECT b.*,d.name FROM bookings b JOIN dogs d ON d.id=b.dog_id WHERE d.parent_id=? ORDER BY b.day').bind(u.id)).all()).results});
  if(p==='/api/bookings'&&method==='POST'){
   if(staff)return E('Parent account required',403);if(!u.approved)return E('Staff must approve your reservation eligibility before you can request bus days',403);
   const b=await parse(request),day=String(b.day||''),dog=String(b.dog_id||'');if(!/^\d{4}-\d{2}-\d{2}$/.test(day))return E('Choose a valid date');
   const now=new Date(),today=new Date(new Intl.DateTimeFormat('en-CA',{timeZone:'America/New_York',year:'numeric',month:'2-digit',day:'2-digit'}).format(now)+'T12:00:00Z'),target=new Date(day+'T12:00:00Z'),delta=Math.round((target-today)/86400000);
   if(!Number.isFinite(target.getTime())||target.toISOString().slice(0,10)!==day||delta<0||delta>30)return E('Choose a date within the next 30 days');
   if(!await env.DB.prepare('SELECT id FROM dogs WHERE id=? AND parent_id=?').bind(dog,u.id).first())return E('Dog not found',404);
   try{await env.DB.prepare('INSERT INTO bookings(id,dog_id,day) VALUES(?,?,?)').bind(uid(),dog,day).run();}catch{return E('You already requested this date for this dog',409)}return J({status:'pending'},201);
  }
  if(p.startsWith('/api/bookings/')&&method==='PATCH'){
   if(!staff)return E('Staff only',403);const b=await parse(request);if(!['approved','declined'].includes(b.status))return E('Invalid status');const r=await env.DB.prepare('UPDATE bookings SET status=? WHERE id=?').bind(b.status,p.split('/')[3]).run();return J({ok:r.meta.changes>0});
  }
  if(p==='/api/staff/parents'&&method==='GET'){if(!staff)return E('Staff only',403);return J({parents:(await env.DB.prepare("SELECT id,email,approved,created_at FROM users WHERE role='parent' ORDER BY created_at DESC").all()).results});}
  if(p.startsWith('/api/staff/parents/')&&method==='PATCH'){
   if(!staff)return E('Staff only',403);const b=await parse(request);if(typeof b.approved!=='boolean')return E('Invalid approval');const r=await env.DB.prepare("UPDATE users SET approved=? WHERE id=? AND role='parent'").bind(b.approved?1:0,p.split('/')[4]).run();return J({ok:r.meta.changes>0});
  }
  if(p==='/api/schedule'&&method==='PUT'){
   if(!staff)return E('Staff only',403);const b=await parse(request),day=Number(b.day);if(!Number.isInteger(day)||day<0||day>6)return E('Invalid weekday');await env.DB.prepare('INSERT INTO schedule(day,destination,route,running) VALUES(?,?,?,?) ON CONFLICT(day) DO UPDATE SET destination=excluded.destination,route=excluded.route,running=excluded.running').bind(day,String(b.destination||'').slice(0,150),String(b.route||'').slice(0,2000),b.running?1:0).run();return J({ok:true});
  }
  if(p==='/api/updates'&&method==='POST'){
   if(!staff)return E('Staff only',403);const b=await parse(request),message=String(b.message||'').trim();if(!message||message.length>2000)return E('Enter an update');await env.DB.prepare('INSERT INTO updates(id,message,latitude,longitude) VALUES(?,?,?,?)').bind(uid(),message,Number.isFinite(b.latitude)?b.latitude:null,Number.isFinite(b.longitude)?b.longitude:null).run();return J({ok:true},201);
  }
  return E('Not found',404);
 }catch(e){console.error('API request failed',e);return E('Server request failed',500)}
}};
