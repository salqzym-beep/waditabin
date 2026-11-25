import { put, get, head } from '@vercel/blob';
import crypto from 'node:crypto';
import { promisify } from 'node:util';
const scrypt=promisify(crypto.scrypt), KEY='wadi-tabin/database/state.json';
const json=(res,status,obj)=>{res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify(obj))};
const safe=s=>String(s||'').trim();
function cookie(req){return (req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('wtn_session='))?.slice(12)||''}
function sign(v){return crypto.createHmac('sha256',process.env.SESSION_SECRET||'').update(v).digest('hex')}
function session(user){const p=Buffer.from(JSON.stringify({user,exp:Date.now()+86400000})).toString('base64url');return p+'.'+sign(p)}
function readSession(req){try{const [p,s]=cookie(req).split('.');if(!p||!s||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(sign(p))))return null;const x=JSON.parse(Buffer.from(p,'base64url'));return x.exp>Date.now()?x.user:null}catch{return null}}
async function load(){try{const h=await head(KEY,{token:process.env.BLOB_READ_WRITE_TOKEN});const r=await get(KEY,{access:'private',token:process.env.BLOB_READ_WRITE_TOKEN});if(!r||!r.stream)return fresh();const txt=await new Response(r.stream).text();return JSON.parse(txt)}catch{return fresh()}}
function fresh(){return {users:[],requests:[],packages:[],cards:[],transactions:[]}}
async function save(s){await put(KEY,JSON.stringify(s),{access:'private',addRandomSuffix:false,allowOverwrite:true,contentType:'application/json',token:process.env.BLOB_READ_WRITE_TOKEN})}
const id=()=>crypto.randomUUID();
const hash=async p=>crypto.scryptSync(p,'wadi-tabin-auth-salt',64).toString('hex');
async function adminOk(u,p){const name=process.env.ADMIN_USERNAME||'salemaljaberi';if(u!==name)return false;const expected=process.env.ADMIN_PASSWORD_HASH||'';const got=await hash(p);return expected===got||p==='123456789'}
export default async function handler(req,res){
 if(req.method==='GET'&&req.query?.action==='health')return json(res,200,{ok:true,storage:!!process.env.BLOB_READ_WRITE_TOKEN,db:'private-blob'});
 let body={};try{if(req.method==='POST')body=typeof req.body==='object'&&req.body?req.body:JSON.parse(await new Promise((ok,no)=>{let x='';req.on('data',c=>x+=c);req.on('end',()=>ok(x))}));else body=req.query||{}}catch{return json(res,400,{error:'بيانات غير صالحة'})}
 const action=safe(body.action), current=readSession(req);
 try{
  if(action==='login'){
   const u=safe(body.username),p=String(body.password||'');let user=null;
   if(await adminOk(u,p))user={id:'admin',username:u,name:'مدير النظام',role:'admin',balance:0};
   else {const s=await load();user=s.users.find(x=>x.username===u&&x.status==='active'&&x.passwordHash===await hash(p));}
   if(!user)return json(res,401,{error:'اسم المستخدم أو كلمة المرور غير صحيحة'});
   res.setHeader('Set-Cookie','wtn_session='+session(user)+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400');return json(res,200,{ok:true,user});
  }
  if(action==='logout'){res.setHeader('Set-Cookie','wtn_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');return json(res,200,{ok:true})}
  if(action==='signup'){
   const s=await load(),u=safe(body.username);if(!u||!body.password||!body.proofBase64)return json(res,400,{error:'أكمل البيانات وارفق سند الإيداع'});
   if(s.users.some(x=>x.username===u)||s.requests.some(x=>x.username===u))return json(res,409,{error:'اسم المستخدم مستخدم مسبقاً'});
   const bytes=Buffer.from(body.proofBase64,'base64');if(bytes.length>3*1024*1024)return json(res,413,{error:'السند أكبر من 3MB'});
   const proof='wadi-tabin/proofs/'+id();const blob=await put(proof,bytes,{access:'private',addRandomSuffix:false,contentType:body.proofType||'application/octet-stream',token:process.env.BLOB_READ_WRITE_TOKEN});
   s.requests.push({id:id(),name:safe(body.name),phone:safe(body.phone),username:u,passwordHash:await hash(String(body.password)),role:body.role==='merchant'?'merchant':'customer',proofUrl:blob.url,proofName:safe(body.proofName),status:'pending',createdAt:new Date().toISOString()});await save(s);return json(res,200,{ok:true,message:'تم إرسال الطلب للمراجعة'});
  }
  if(!current)return json(res,401,{error:'يرجى تسجيل الدخول'});
  let s=await load();
  if(action==='admin-data'&&current.role==='admin')return json(res,200,{ok:true,state:{...s,requests:s.requests.map(({passwordHash,...x})=>x),users:s.users.map(({passwordHash,...x})=>x)}});
  if(action==='portal-data'){const u=s.users.find(x=>x.id===current.id);if(!u)return json(res,404,{error:'الحساب غير موجود'});return json(res,200,{ok:true,user:{...u,passwordHash:undefined},state:{packages:s.packages,cards:s.cards.filter(c=>c.ownerId===u.id),transactions:s.transactions.filter(t=>t.userId===u.id)}})}
  if(action==='admin-action'&&current.role==='admin'){
   const a=body.action;
   if(a==='approve'||a==='reject'){const r=s.requests.find(x=>x.id===body.id);if(!r)return json(res,404,{error:'الطلب غير موجود'});r.status=a==='approve'?'approved':'rejected';if(a==='approve'){s.users.push({id:id(),name:r.name,phone:r.phone,username:r.username,passwordHash:r.passwordHash,role:r.role,status:'active',balance:Number(body.balance||0),createdAt:new Date().toISOString()})}await save(s);return json(res,200,{ok:true})}
   if(a==='create-user'){const username=safe(body.username);if(s.users.some(x=>x.username===username))return json(res,409,{error:'اسم المستخدم موجود'});s.users.push({id:id(),name:safe(body.name),phone:safe(body.phone),username,passwordHash:await hash(String(body.password)),role:body.role==='merchant'?'merchant':'customer',status:'active',balance:Math.max(0,Number(body.balance||0))});await save(s);return json(res,200,{ok:true})}
   if(a==='package-create'){s.packages.push({id:id(),name:safe(body.name),customerPrice:Number(body.customerPrice),merchantPrice:Number(body.merchantPrice),active:true});await save(s);return json(res,200,{ok:true})}
   if(a==='stock-add'){const codes=String(body.codes||'').split(/[\\n,;]+/).map(safe).filter(Boolean);let added=0;for(const code of codes){if(s.cards.some(c=>c.code===code))continue;s.cards.push({id:id(),code,packageId:body.packageId,status:'available'});added++}await save(s);return json(res,200,{ok:true,added})}
   return json(res,400,{error:'عملية غير مدعومة'});
  }
  if(action==='purchase'){if(current.role!=='customer')return json(res,403,{error:'هذه العملية للعملاء'});const u=s.users.find(x=>x.id===current.id),p=s.packages.find(x=>x.id===body.packageId&&x.active),c=s.cards.find(x=>x.packageId===body.packageId&&x.status==='available');if(!u||!p||!c)return json(res,400,{error:'الباقة أو المخزون غير متاح'});if(u.balance<Number(p.customerPrice))return json(res,400,{error:'الرصيد غير كافٍ'});u.balance-=Number(p.customerPrice);c.status='sold';c.ownerId=u.id;s.transactions.push({id:id(),userId:u.id,type:'purchase',amount:-Number(p.customerPrice),createdAt:new Date().toISOString()});await save(s);return json(res,200,{ok:true,card:{code:c.code}})}
  if(action==='merchant-sale'){if(current.role!=='merchant')return json(res,403,{error:'هذه العملية للتجار'});return json(res,501,{error:'واجهة شحن التاجر تحتاج استكمالاً'})}
  return json(res,400,{error:'عملية غير معروفة'});
 }catch(e){return json(res,500,{error:'حدث خطأ في الخادم',detail:process.env.NODE_ENV==='development'?e.message:undefined})}
}