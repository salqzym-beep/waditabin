import { put, get, head } from '@vercel/blob';
import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
const KEY = process.env.DATA_KEY || 'wadi-tabin/database/state.json';
const json = (res, status, obj) => { res.statusCode=status; res.setHeader('Content-Type','application/json; charset=utf-8'); res.end(JSON.stringify(obj)); };
const safe = v => String(v ?? '').trim();
const id = () => crypto.randomUUID();
const fresh = () => ({users:[],requests:[],packages:[],cards:[],transactions:[]});
const hash = async p => (await scrypt(String(p), 'wadi-tabin-auth-salt', 64)).toString('hex');
let writeQueue = Promise.resolve();

function cookie(req) {
  return (req.headers.cookie || '').split(';').map(x=>x.trim()).find(x=>x.startsWith('wtn_session='))?.slice(12) || '';
}
function sign(v) {
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters');
  return crypto.createHmac('sha256', process.env.SESSION_SECRET).update(v).digest('hex');
}
function session(user) {
  const p=Buffer.from(JSON.stringify({user,exp:Date.now()+86400000})).toString('base64url');
  return p+'.'+sign(p);
}
function readSession(req) {
  try {
    const [p,s]=cookie(req).split('.');
    if(!p||!s)return null;
    const expected=sign(p);
    const a=Buffer.from(s), b=Buffer.from(expected);
    if(a.length!==b.length || !crypto.timingSafeEqual(a,b))return null;
    const x=JSON.parse(Buffer.from(p,'base64url'));
    return x.exp>Date.now()?x.user:null;
  } catch { return null; }
}
function isMissingBlob(e) {
  return e?.status===404 || e?.statusCode===404 || e?.code==='BLOB_NOT_FOUND' || e?.code==='not_found';
}
async function load() {
  try {
    const r=await get(KEY,{access:'private',token:process.env.BLOB_READ_WRITE_TOKEN,useCache:false});
    if(!r) return fresh();
    if(!r.stream)throw new Error('تعذر قراءة ملف قاعدة البيانات من التخزين');
    const state=JSON.parse(await new Response(r.stream).text());
    if(!state || !Array.isArray(state.users) || !Array.isArray(state.cards))throw new Error('ملف قاعدة البيانات غير صالح');
    const result={...fresh(),...state}; Object.defineProperty(result,'_etag',{value:r.blob?.etag||undefined,writable:true,configurable:true,enumerable:false}); return result;
  } catch(e) {
    if(isMissingBlob(e))return fresh();
    throw e;
  }
}
async function save(state) {
  const write = async () => {
    const result=await put(KEY,JSON.stringify(state),{
      access:'private',addRandomSuffix:false,allowOverwrite:true,
      contentType:'application/json',token:process.env.BLOB_READ_WRITE_TOKEN,
      ...(state._etag && process.env.BLOB_DISABLE_ETAG!=='true'?{ifMatch:state._etag}:{})
    });
    Object.defineProperty(state,'_etag',{value:result.etag,writable:true,configurable:true,enumerable:false});
    return result;
  };
  const task=writeQueue.then(write,write);
  writeQueue=task.then(()=>undefined,()=>undefined);
  await task;
}
async function adminOk(username,password) {
  if(username!==(process.env.ADMIN_USERNAME||'') || !process.env.ADMIN_PASSWORD_HASH)return false;
  return (await hash(password))===process.env.ADMIN_PASSWORD_HASH;
}
function cleanUser(u) { const {passwordHash,...rest}=u; return rest; }

export default async function handler(req,res) {
  if(req.method==='GET' && req.query?.action==='health') {
    return json(res,200,{ok:true,storage:!!process.env.BLOB_READ_WRITE_TOKEN,db:'private-blob',sessionConfigured:!!process.env.SESSION_SECRET && process.env.SESSION_SECRET.length>=32,adminConfigured:!!process.env.ADMIN_USERNAME && !!process.env.ADMIN_PASSWORD_HASH});
  }
  let body={};
  try {
    if(req.method==='POST') body=typeof req.body==='object'&&req.body?req.body:JSON.parse(await new Promise((resolve,reject)=>{let raw='';req.on('data',c=>raw+=c);req.on('end',()=>resolve(raw));req.on('error',reject)}));
    else body=req.query||{};
  } catch { return json(res,400,{error:'بيانات غير صالحة'}); }

  const action=safe(body.action);
  const current=readSession(req);
  try {
    if(action==='login') {
      const username=safe(body.username), password=String(body.password||'');
      let user=null;
      if(await adminOk(username,password)) user={id:'admin',username,name:'مدير النظام',role:'admin',balance:0};
      else {
        const state=await load(), passwordHash=await hash(password);
        user=state.users.find(x=>x.username===username&&x.status==='active'&&x.passwordHash===passwordHash);
      }
      if(!user)return json(res,401,{error:'اسم المستخدم أو كلمة المرور غير صحيحة'});
      const token=session(user);
      res.setHeader('Set-Cookie','wtn_session='+token+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400');
      return json(res,200,{ok:true,user:cleanUser(user)});
    }
    if(action==='logout') {
      res.setHeader('Set-Cookie','wtn_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
      return json(res,200,{ok:true});
    }
    if(action==='signup') {
      const state=await load(), username=safe(body.username), password=String(body.password||'');
      if(!username||password.length<8||!body.proofBase64||!safe(body.name)||!safe(body.phone))return json(res,400,{error:'أكمل البيانات، وكلمة المرور 8 أحرف على الأقل، وأرفق سند الإيداع'});
      if(state.users.some(x=>x.username===username)||state.requests.some(x=>x.username===username))return json(res,409,{error:'اسم المستخدم مستخدم مسبقاً'});
      const bytes=Buffer.from(body.proofBase64,'base64');
      if(!bytes.length||bytes.length>3*1024*1024)return json(res,413,{error:'السند فارغ أو أكبر من 3MB'});
      const proof='wadi-tabin/proofs/'+id();
      const blob=await put(proof,bytes,{access:'private',addRandomSuffix:false,contentType:body.proofType||'application/octet-stream',token:process.env.BLOB_READ_WRITE_TOKEN});
      state.requests.push({id:id(),name:safe(body.name),phone:safe(body.phone),username,passwordHash:await hash(password),role:body.role==='merchant'?'merchant':'customer',proofUrl:blob.url,proofName:safe(body.proofName),status:'pending',createdAt:new Date().toISOString()});
      await save(state);
      return json(res,200,{ok:true,message:'تم إرسال الطلب للمراجعة'});
    }
    if(!current)return json(res,401,{error:'يرجى تسجيل الدخول'});
    const state=await load();
    if(action==='admin-data'&&current.role==='admin') {
      return json(res,200,{ok:true,state:{...state,requests:[...state.requests].sort((a,b)=>(a.status==='pending'?-1:1)-(b.status==='pending'?-1:1)),users:state.users.map(cleanUser)}});
    }
    if(action==='portal-data') {
      const user=state.users.find(x=>x.id===current.id);
      if(!user)return json(res,404,{error:'الحساب غير موجود'});
      return json(res,200,{ok:true,user:cleanUser(user),state:{packages:state.packages,cards:state.cards.filter(c=>c.ownerId===user.id),transactions:state.transactions.filter(t=>t.userId===user.id)}});
    }
    if(action==='admin-action'&&current.role==='admin') {
      const operation=safe(body.operation);
      if(operation==='approve'||operation==='reject') {
        const request=state.requests.find(x=>x.id===body.id&&x.status==='pending');
        if(!request)return json(res,404,{error:'الطلب غير موجود أو تمت معالجته مسبقاً'});
        if(operation==='approve') {
          const balance=Number(body.balance??0);
          if(!Number.isFinite(balance)||balance<0)return json(res,400,{error:'الرصيد غير صحيح'});
          if(state.users.some(x=>x.username===request.username))return json(res,409,{error:'الحساب موجود مسبقاً'});
          const approvedPassword=String(body.newPassword||'');
          if(approvedPassword && approvedPassword.length<8)return json(res,400,{error:'كلمة المرور الجديدة يجب ألا تقل عن 8 أحرف'});
          state.users.push({id:id(),name:request.name,phone:request.phone,username:request.username,passwordHash:approvedPassword?await hash(approvedPassword):request.passwordHash,role:request.role,status:'active',balance,createdAt:new Date().toISOString()});
        }
        request.status=operation==='approve'?'approved':'rejected';
        await save(state);
        return json(res,200,{ok:true});
      }
      if(operation==='user-update') {
        const user=state.users.find(x=>x.id===body.id);
        if(!user)return json(res,404,{error:'الحساب غير موجود'});
        const name=safe(body.name), phone=safe(body.phone), username=safe(body.username);
        const balance=Number(body.balance), role=body.role==='merchant'?'merchant':'customer';
        if(!name||!username||!Number.isFinite(balance)||balance<0)return json(res,400,{error:'تحقق من الاسم واسم المستخدم والرصيد'});
        if(state.users.some(x=>x.id!==user.id&&x.username===username))return json(res,409,{error:'اسم المستخدم مستخدم لحساب آخر'});
        user.name=name; user.phone=phone; user.username=username; user.role=role; user.balance=balance;
        if(body.status==='active'||body.status==='suspended')user.status=body.status;
        const newPassword=String(body.newPassword||'');
        if(newPassword){if(newPassword.length<8)return json(res,400,{error:'كلمة المرور يجب ألا تقل عن 8 أحرف'});user.passwordHash=await hash(newPassword);}
        await save(state); return json(res,200,{ok:true});
      }
      if(operation==='create-user') {
        const username=safe(body.username), password=String(body.password||''), balance=Number(body.balance||0);
        if(!username||password.length<8||!safe(body.name)||!Number.isFinite(balance)||balance<0)return json(res,400,{error:'تحقق من البيانات وكلمة المرور والرصيد'});
        if(state.users.some(x=>x.username===username)||state.requests.some(x=>x.username===username))return json(res,409,{error:'اسم المستخدم موجود'});
        state.users.push({id:id(),name:safe(body.name),phone:safe(body.phone),username,passwordHash:await hash(password),role:body.role==='merchant'?'merchant':'customer',status:'active',balance,createdAt:new Date().toISOString()});
        await save(state); return json(res,200,{ok:true});
      }
      if(operation==='package-create') {
        const customerPrice=Number(body.customerPrice), merchantPrice=Number(body.merchantPrice);
        if(!safe(body.name)||!Number.isFinite(customerPrice)||!Number.isFinite(merchantPrice)||customerPrice<0||merchantPrice<0)return json(res,400,{error:'بيانات الباقة أو الأسعار غير صحيحة'});
        state.packages.push({id:id(),name:safe(body.name),customerPrice,merchantPrice,active:true});
        await save(state); return json(res,200,{ok:true});
      }
      if(operation==='stock-add') {
        const pkg=state.packages.find(x=>x.id===body.packageId);
        if(!pkg)return json(res,400,{error:'اختر باقة صحيحة'});
        const codes=String(body.codes||'').split(/[\n,;]+/).map(safe).filter(Boolean);
        const seen=new Set(state.cards.map(c=>c.code)); let added=0,duplicates=0;
        for(const code of codes){if(seen.has(code)){duplicates++;continue;}seen.add(code);state.cards.push({id:id(),code,packageId:pkg.id,status:'available'});added++;}
        if(!added)return json(res,400,{error:'لم تتم إضافة كروت جديدة؛ تحقق من الأكواد أو التكرار'});
        await save(state); return json(res,200,{ok:true,added,duplicates});
      }
      return json(res,400,{error:'عملية المدير غير مدعومة'});
    }
    if(action==='purchase') {
      if(current.role!=='customer')return json(res,403,{error:'هذه العملية للعملاء'});
      const user=state.users.find(x=>x.id===current.id), pkg=state.packages.find(x=>x.id===body.packageId&&x.active), card=state.cards.find(x=>x.packageId===body.packageId&&x.status==='available');
      if(!user||!pkg||!card)return json(res,400,{error:'الباقة أو المخزون غير متاح'});
      const price=Number(pkg.customerPrice);
      if(!Number.isFinite(price)||price<0||user.balance<price)return json(res,400,{error:'الرصيد غير كافٍ أو سعر الباقة غير صحيح'});
      user.balance-=price; card.status='sold'; card.ownerId=user.id;
      state.transactions.push({id:id(),userId:user.id,type:'purchase',amount:-price,createdAt:new Date().toISOString()});
      await save(state); return json(res,200,{ok:true,card:{code:card.code},balance:user.balance});
    }
    if(action==='merchant-sale') {
      if(current.role!=='merchant')return json(res,403,{error:'هذه العملية للتجار'});
      return json(res,501,{error:'بيع التاجر لم يكتمل بعد؛ لم يتم خصم أي رصيد'});
    }
    return json(res,400,{error:'عملية غير معروفة'});
  } catch(e) {
    console.error('wadi-tabin api error',e);
    if(e?.status===412 || e?.statusCode===412 || e?.name==='BlobPreconditionFailedError') return json(res,409,{code:'CONCURRENT_UPDATE',error:'تغيرت البيانات أثناء الحفظ. حدّث الصفحة ثم أعد المحاولة.'});
    return json(res,500,{error:'تعذر إتمام العملية بأمان. لم يتم تأكيد الحفظ؛ أعد تحميل الصفحة وتحقق من البيانات.'});
  }
}
