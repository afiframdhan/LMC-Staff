const JSON_HEADERS = {'content-type':'application/json; charset=utf-8','cache-control':'no-store'};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/health') return json({ok:true,service:'legacy-staff',supabase:hasSupabase(env)});
    if (url.pathname === '/api/admin/login' && request.method === 'POST') return adminLogin(request, env);
    if (url.pathname === '/api/admin/refresh' && request.method === 'POST') return adminRefresh(request, env);
    if (url.pathname.startsWith('/api/staff-biometric/')) return handleStaffBiometricApi(request, env);
    if (url.pathname.startsWith('/api/kiosk/')) return handleKioskApi(request, env);
    if (url.pathname.startsWith('/api/admin/')) return handleAdminApi(request, env);
    return env.ASSETS.fetch(request);
  }
};

function json(data,status=200,headers={}) { return new Response(JSON.stringify(data),{status,headers:{...JSON_HEADERS,...headers}}); }
function publicKey(env){ return env.SUPABASE_PUBLISHABLE_KEY || env.SUPABASE_ANON_KEY || ''; }
function secretKey(env){ return env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY || ''; }
function hasSupabase(env){ return Boolean(env.SUPABASE_URL && publicKey(env) && secretKey(env)); }
function sbBase(env){ return String(env.SUPABASE_URL||'').replace(/\/$/,''); }
async function supabaseRest(env,path,opts={}){
  if(!hasSupabase(env)) throw new Error('Konfigurasi Supabase belum lengkap.');
  const key=secretKey(env); const authHeaders=key.startsWith('eyJ')?{authorization:`Bearer ${key}`}:{ };
  const r=await fetch(sbBase(env)+path,{...opts,headers:{apikey:key,...authHeaders,...(opts.headers||{})}});
  const t=await r.text(); let data=null; if(t){try{data=JSON.parse(t)}catch{data=t}}
  if(!r.ok) throw new Error(typeof data==='object' ? (data.message||data.error||data.hint||`Supabase ${r.status}`) : String(data||`Supabase ${r.status}`));
  return data;
}
async function sbRows(env,table,q={}){
  const p=new URLSearchParams();
  p.set('select',q.select||'*');
  for(const [k,v] of Object.entries(q)){ if(['select','order','limit'].includes(k) || v==null) continue; p.set(k,String(v)); }
  if(q.order)p.set('order',q.order); if(q.limit)p.set('limit',String(q.limit));
  return await supabaseRest(env,`/rest/v1/${table}?${p.toString()}`)||[];
}

async function readJson(request){try{return await request.json()}catch{throw new Error('Body JSON tidak valid.')}}
function bearer(request){const h=request.headers.get('authorization')||''; return h.startsWith('Bearer ')?h.slice(7).trim():'';}
async function authUser(env,token){
  if(!token) return null;
  const r=await fetch(sbBase(env)+'/auth/v1/user',{headers:{apikey:publicKey(env),authorization:`Bearer ${token}`}});
  if(!r.ok) return null; return await r.json();
}
async function requireAdmin(request,env){
  const token=bearer(request), user=await authUser(env,token); if(!user?.email) throw Object.assign(new Error('Sesi Admin tidak valid.'),{status:401});
  const rows=await sbRows(env,'staff_admins',{email:`eq.${user.email}`,active:'eq.true',limit:'1'}); if(!rows[0]) throw Object.assign(new Error('Akun ini tidak memiliki akses Admin Staff.'),{status:403});
  return {email:user.email,name:rows[0].full_name||user.email,user};
}
async function adminLogin(request,env){
  try{
    const b=await readJson(request); const email=String(b.email||'').trim(), password=String(b.password||''); if(!email||!password) throw new Error('Email dan password wajib diisi.');
    const r=await fetch(sbBase(env)+'/auth/v1/token?grant_type=password',{method:'POST',headers:{apikey:publicKey(env),'content-type':'application/json'},body:JSON.stringify({email,password})});
    const d=await r.json(); if(!r.ok) return json({ok:false,error:d.error_description||d.msg||'Login gagal.'},401);
    const rows=await sbRows(env,'staff_admins',{email:`eq.${email}`,active:'eq.true',limit:'1'}); if(!rows[0]) return json({ok:false,error:'Akun belum terdaftar sebagai Admin Staff.'},403);
    return json({ok:true,data:{access_token:d.access_token,refresh_token:d.refresh_token,expires_in:d.expires_in,user:{email,name:rows[0].full_name||email}}});
  }catch(e){return json({ok:false,error:e.message||String(e)},400)}
}
async function adminRefresh(request,env){
  try{const b=await readJson(request); const rt=String(b.refresh_token||''); if(!rt) throw new Error('Refresh token kosong.'); const r=await fetch(sbBase(env)+'/auth/v1/token?grant_type=refresh_token',{method:'POST',headers:{apikey:publicKey(env),'content-type':'application/json'},body:JSON.stringify({refresh_token:rt})}); const d=await r.json(); if(!r.ok)return json({ok:false,error:d.error_description||d.msg||'Refresh session gagal.'},401); return json({ok:true,data:d});}catch(e){return json({ok:false,error:e.message||String(e)},400)}
}

async function handleAdminApi(request,env){
  try{
    const admin=await requireAdmin(request,env); const url=new URL(request.url), p=url.pathname;
    if(p==='/api/admin/dashboard' && request.method==='GET') return json({ok:true,data:await getAdminDashboard(env)});
    if(p==='/api/admin/staff' && request.method==='POST') return json({ok:true,data:await saveStaff(env,admin,await readJson(request))});
    if(p.startsWith('/api/admin/staff/') && request.method==='DELETE') return json({ok:true,data:await deleteStaff(env,admin,p.split('/').pop())});
    if(p.match(/^\/api\/admin\/staff\/[^/]+\/enroll$/) && request.method==='POST') return json({ok:true,data:await createEnrollment(env,admin,p.split('/')[4],request)});
    if(p.match(/^\/api\/admin\/staff\/[^/]+\/reset-passkeys$/) && request.method==='POST') return json({ok:true,data:await resetPasskeys(env,admin,p.split('/')[4])});
    if(p==='/api/admin/attendance' && request.method==='POST') return json({ok:true,data:await saveAttendance(env,admin,await readJson(request))});
    if(p.startsWith('/api/admin/attendance/') && request.method==='DELETE') return json({ok:true,data:await deleteAttendance(env,admin,p.split('/').pop())});
    if(p==='/api/admin/audit' && request.method==='GET') return json({ok:true,data:{rows:await sbRows(env,'staff_audit_logs',{order:'created_at.desc',limit:'300'})}});
    if(p==='/api/admin/kiosks' && request.method==='GET') return json({ok:true,data:{rows:await listKiosks(env)}});
    if(p==='/api/admin/kiosk/activate' && request.method==='POST') return json({ok:true,data:await activateKiosk(env,admin,await readJson(request))});
    if(p.match(/^\/api\/admin\/kiosk\/[^/]+\/revoke$/) && request.method==='POST') return json({ok:true,data:await revokeKiosk(env,admin,p.split('/')[4])});
    return json({ok:false,error:'Endpoint Admin tidak ditemukan.'},404);
  }catch(e){return json({ok:false,error:e.message||String(e)},e.status||400)}
}
async function audit(env,admin,action,entityType,entityId,details={}){try{await supabaseRest(env,'/rest/v1/staff_audit_logs',{method:'POST',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({actor_email:admin?.email||'system',action,entity_type:entityType,entity_id:String(entityId||''),details})})}catch{}}
function mapStaff(r,counts=new Map()){return{staffId:r.staff_id,employeeCode:r.employee_code||'',name:r.full_name||'',position:r.position||'',email:r.email||'',phone:r.phone||'',joinedOn:r.joined_on||'',endedOn:r.ended_on||'',status:r.status||'Aktif',notes:r.notes||'',photoUrl:r.photo_url||'',biometricCount:counts.get(String(r.staff_id))||0}}
function trimTime(v){const s=String(v||'');return /^\d{2}:\d{2}/.test(s)?s.slice(0,5):s}
function mapAttendance(r){return{attendanceId:r.attendance_id,staffId:r.staff_id,staffName:r.staff_name_snapshot||'',position:r.position_snapshot||'',date:r.attendance_date||'',status:r.status||'',checkIn:trimTime(r.check_in),checkOut:trimTime(r.check_out),notes:r.notes||'',verificationMethod:r.verification_method||'admin',verifiedAt:r.biometric_verified_at||'',recordedBy:r.recorded_by||''}}
async function getAdminDashboard(env){
  const [staff,att,creds]=await Promise.all([sbRows(env,'staff_employees',{order:'full_name.asc'}),sbRows(env,'staff_attendance',{order:'attendance_date.desc,created_at.desc',limit:'1200'}),sbRows(env,'staff_webauthn_credentials',{active:'eq.true',select:'staff_id,credential_id'}).catch(()=>[])]);
  const c=new Map(); for(const x of creds)c.set(String(x.staff_id),(c.get(String(x.staff_id))||0)+1);
  return{staff:staff.map(x=>mapStaff(x,c)),attendance:att.map(mapAttendance),serverTime:new Date().toISOString()};
}
async function saveStaff(env,admin,b){
  const id=String(b.staffId||'').trim(), code=String(b.employeeCode||'').trim().toUpperCase(), name=String(b.name||'').trim(), position=String(b.position||'').trim(); if(!code||!name||!position)throw new Error('Kode staff, nama, dan jabatan wajib diisi.');
  const row={employee_code:code,full_name:name,position,email:String(b.email||'').trim()||null,phone:String(b.phone||'').trim()||null,joined_on:b.joinedOn||null,ended_on:b.endedOn||null,status:['Aktif','Cuti','Nonaktif'].includes(b.status)?b.status:'Aktif',notes:String(b.notes||'').trim()||null,photo_url:String(b.photoUrl||'').trim()||null,updated_at:new Date().toISOString()};
  let d;if(id)d=await supabaseRest(env,`/rest/v1/staff_employees?staff_id=eq.${encodeURIComponent(id)}`,{method:'PATCH',headers:{'content-type':'application/json',Prefer:'return=representation'},body:JSON.stringify(row)});else d=await supabaseRest(env,'/rest/v1/staff_employees',{method:'POST',headers:{'content-type':'application/json',Prefer:'return=representation'},body:JSON.stringify(row)});
  const saved=d?.[0]; await audit(env,admin,id?'update_staff':'create_staff','staff',saved?.staff_id||id,{name,position,code}); return{message:id?'Data staff diperbarui.':'Staff ditambahkan.',staff:saved?mapStaff(saved):null};
}
async function deleteStaff(env,admin,id){if(!id)throw new Error('Staff tidak valid.'); await supabaseRest(env,`/rest/v1/staff_employees?staff_id=eq.${encodeURIComponent(id)}`,{method:'DELETE',headers:{Prefer:'return=minimal'}}); await audit(env,admin,'delete_staff','staff',id); return{message:'Staff dan seluruh data terkait berhasil dihapus.'}}
async function saveAttendance(env,admin,b){
  const id=String(b.attendanceId||''), sid=String(b.staffId||''), date=String(b.date||''); if(!sid||!date)throw new Error('Staff dan tanggal wajib dipilih.'); const s=(await sbRows(env,'staff_employees',{staff_id:`eq.${sid}`,limit:'1'}))[0]; if(!s)throw new Error('Staff tidak ditemukan.');
  const row={staff_id:sid,staff_name_snapshot:s.full_name,position_snapshot:s.position,attendance_date:date,status:['Hadir','Izin','Sakit','Alpa','Cuti'].includes(b.status)?b.status:'Hadir',check_in:b.checkIn||null,check_out:b.checkOut||null,notes:String(b.notes||'').trim()||null,verification_method:'admin',recorded_by:admin.name,updated_at:new Date().toISOString()};
  let target=id;if(!target){const ex=(await sbRows(env,'staff_attendance',{staff_id:`eq.${sid}`,attendance_date:`eq.${date}`,limit:'1'}))[0];if(ex)target=ex.attendance_id}
  let d;if(target)d=await supabaseRest(env,`/rest/v1/staff_attendance?attendance_id=eq.${encodeURIComponent(target)}`,{method:'PATCH',headers:{'content-type':'application/json',Prefer:'return=representation'},body:JSON.stringify(row)});else d=await supabaseRest(env,'/rest/v1/staff_attendance',{method:'POST',headers:{'content-type':'application/json',Prefer:'return=representation'},body:JSON.stringify(row)});
  await audit(env,admin,target?'update_attendance':'create_attendance','attendance',d?.[0]?.attendance_id||target,{staff:s.full_name,date}); return{message:'Absensi berhasil disimpan.',attendance:d?.[0]?mapAttendance(d[0]):null};
}

async function listKiosks(env){
  const rows=await sbRows(env,'staff_kiosk_devices',{order:'created_at.desc',limit:'50'}).catch(()=>[]);
  return rows.map(x=>({kioskId:x.kiosk_id,deviceName:x.device_name,active:!!x.active,createdBy:x.created_by||'',createdAt:x.created_at,lastUsedAt:x.last_used_at||'',revokedAt:x.revoked_at||''}));
}
async function activateKiosk(env,admin,b){
  const deviceName=String(b.deviceName||'').trim()||'HP Kantor';
  const token=randomValue(40), tokenHash=await shaB64(new TextEncoder().encode(token));
  const d=await supabaseRest(env,'/rest/v1/staff_kiosk_devices',{method:'POST',headers:{'content-type':'application/json',Prefer:'return=representation'},body:JSON.stringify({device_name:deviceName,token_hash:tokenHash,active:true,created_by:admin.email})});
  await audit(env,admin,'activate_kiosk','kiosk',d?.[0]?.kiosk_id||'',{deviceName});
  return{message:'Perangkat berhasil diaktifkan sebagai Kiosk Absensi.',kioskId:d?.[0]?.kiosk_id,deviceName,token};
}
async function revokeKiosk(env,admin,id){
  if(!id)throw new Error('Kiosk tidak valid.');
  await supabaseRest(env,`/rest/v1/staff_kiosk_devices?kiosk_id=eq.${encodeURIComponent(id)}`,{method:'PATCH',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({active:false,revoked_at:new Date().toISOString()})});
  await audit(env,admin,'revoke_kiosk','kiosk',id);
  return{message:'Akses Kiosk perangkat dinonaktifkan.'};
}
async function requireKiosk(request,env){
  const token=String(request.headers.get('x-kiosk-token')||'').trim();
  if(!token)throw Object.assign(new Error('Perangkat ini belum diaktifkan sebagai Kiosk Absensi.'),{status:401});
  const tokenHash=await shaB64(new TextEncoder().encode(token));
  const row=(await sbRows(env,'staff_kiosk_devices',{token_hash:`eq.${tokenHash}`,active:'eq.true',limit:'1'}))[0];
  if(!row)throw Object.assign(new Error('Akses Kiosk tidak valid atau sudah dinonaktifkan.'),{status:403});
  return row;
}
async function handleKioskApi(request,env){
  try{
    const kiosk=await requireKiosk(request,env), url=new URL(request.url), p=url.pathname;
    if(p==='/api/kiosk/status' && request.method==='GET') return json({ok:true,data:{active:true,kioskId:kiosk.kiosk_id,deviceName:kiosk.device_name}});
    if(p==='/api/kiosk/staff' && request.method==='GET'){
      const code=String(url.searchParams.get('code')||'').trim().toUpperCase(); if(!code)throw new Error('Kode staff kosong.');
      const s=(await sbRows(env,'staff_employees',{employee_code:`eq.${code}`,status:'eq.Aktif',limit:'1'}))[0]; if(!s)throw new Error('Staff tidak ditemukan atau tidak aktif.');
      const now=jakartaNow(), ex=(await sbRows(env,'staff_attendance',{staff_id:`eq.${s.staff_id}`,attendance_date:`eq.${now.date}`,limit:'1'}))[0];
      let nextAction='check-in',state='Belum absen hari ini'; if(ex?.check_in&&!ex?.check_out){nextAction='check-out';state=`Sudah masuk ${trimTime(ex.check_in)}`;} else if(ex?.check_in&&ex?.check_out){nextAction='complete';state=`Absensi lengkap • ${trimTime(ex.check_in)}–${trimTime(ex.check_out)}`;}
      return json({ok:true,data:{staffId:s.staff_id,employeeCode:s.employee_code,name:s.full_name,position:s.position,photoUrl:s.photo_url||'',date:now.date,nextAction,state}});
    }
    if(p==='/api/kiosk/attendance' && request.method==='POST'){
      const b=await readJson(request), sid=String(b.staffId||''); if(!sid)throw new Error('Staff tidak valid.');
      const s=(await sbRows(env,'staff_employees',{staff_id:`eq.${sid}`,status:'eq.Aktif',limit:'1'}))[0]; if(!s)throw new Error('Staff tidak ditemukan atau tidak aktif.');
      const now=jakartaNow(), ex=(await sbRows(env,'staff_attendance',{staff_id:`eq.${sid}`,attendance_date:`eq.${now.date}`,limit:'1'}))[0];
      let action='check-in',message=`Jam masuk ${now.time.slice(0,5)} berhasil dicatat.`;
      if(!ex){
        await supabaseRest(env,'/rest/v1/staff_attendance',{method:'POST',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({staff_id:sid,staff_name_snapshot:s.full_name,position_snapshot:s.position,attendance_date:now.date,status:'Hadir',check_in:now.time,verification_method:'kiosk',recorded_by:`Kiosk: ${kiosk.device_name}`})});
      }else if(!ex.check_out){
        action='check-out';message=`Jam pulang ${now.time.slice(0,5)} berhasil dicatat.`;
        await supabaseRest(env,`/rest/v1/staff_attendance?attendance_id=eq.${ex.attendance_id}`,{method:'PATCH',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({check_out:now.time,verification_method:'kiosk',recorded_by:`Kiosk: ${kiosk.device_name}`,updated_at:new Date().toISOString()})});
      }else{action='complete';message=`Absensi hari ini sudah lengkap. Masuk ${trimTime(ex.check_in)} • Pulang ${trimTime(ex.check_out)}.`;}
      await supabaseRest(env,`/rest/v1/staff_kiosk_devices?kiosk_id=eq.${encodeURIComponent(kiosk.kiosk_id)}`,{method:'PATCH',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({last_used_at:new Date().toISOString()})});
      await audit(env,{email:`kiosk:${kiosk.device_name}`},'kiosk_attendance','attendance',sid,{staff:s.full_name,action,date:now.date,time:now.time.slice(0,5)});
      return json({ok:true,data:{staffName:s.full_name,action,message,date:now.date,time:now.time.slice(0,5)}});
    }
    return json({ok:false,error:'Endpoint Kiosk tidak ditemukan.'},404);
  }catch(e){return json({ok:false,error:e.message||String(e)},e.status||400)}
}

async function deleteAttendance(env,admin,id){await supabaseRest(env,`/rest/v1/staff_attendance?attendance_id=eq.${encodeURIComponent(id)}`,{method:'DELETE',headers:{Prefer:'return=minimal'}});await audit(env,admin,'delete_attendance','attendance',id);return{message:'Absensi dihapus.'}}

function randomValue(n=32){const a=new Uint8Array(n);crypto.getRandomValues(a);return b64e(a)}
function b64e(bytes){let s='';for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function b64d(v){v=String(v).replace(/-/g,'+').replace(/_/g,'/');while(v.length%4)v+='=';const s=atob(v),a=new Uint8Array(s.length);for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return a}
async function sha(bytes){return new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))}
async function shaB64(bytes){return b64e(await sha(bytes))}
function waCtx(request){const u=new URL(request.url);return{origin:u.origin,rpId:u.hostname}}
async function createEnrollment(env,admin,staffId,request){
  const s=(await sbRows(env,'staff_employees',{staff_id:`eq.${staffId}`,limit:'1'}))[0]; if(!s)throw new Error('Staff tidak ditemukan.'); const token=randomValue(32), hash=await shaB64(new TextEncoder().encode(token));
  await supabaseRest(env,'/rest/v1/staff_biometric_enrollments',{method:'POST',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({staff_id:staffId,token_hash:hash,expires_at:new Date(Date.now()+30*60000).toISOString(),created_by:admin.email})}); const origin=new URL(request.url).origin; await audit(env,admin,'create_passkey_enrollment','staff',staffId,{name:s.full_name}); return{url:`${origin}/attendance.html?enroll=${encodeURIComponent(token)}`,expiresMinutes:30,staffName:s.full_name};
}
async function resetPasskeys(env,admin,staffId){await supabaseRest(env,`/rest/v1/staff_webauthn_credentials?staff_id=eq.${encodeURIComponent(staffId)}`,{method:'DELETE',headers:{Prefer:'return=minimal'}});await audit(env,admin,'reset_passkeys','staff',staffId);return{message:'Semua Passkey staff direset.'}}

async function handleStaffBiometricApi(request,env){
  if(request.method!=='POST')return json({ok:false,error:'Method tidak didukung.'},405); try{const b=await readJson(request),p=new URL(request.url).pathname; if(p.endsWith('/enroll/options'))return json({ok:true,data:await enrollOptions(env,request,b)});if(p.endsWith('/enroll/finish'))return json({ok:true,data:await enrollFinish(env,request,b)});if(p.endsWith('/auth/options'))return json({ok:true,data:await authOptions(env,request,b)});if(p.endsWith('/auth/verify'))return json({ok:true,data:await authVerify(env,request,b)});return json({ok:false,error:'Endpoint tidak ditemukan.'},404)}catch(e){return json({ok:false,error:e.message||String(e)},400)}
}
async function createChallenge(env,staffId,purpose,request){const {origin,rpId}=waCtx(request),challenge=randomValue(32);await supabaseRest(env,'/rest/v1/staff_webauthn_challenges',{method:'POST',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({staff_id:staffId,purpose,challenge,origin,rp_id:rpId,expires_at:new Date(Date.now()+2*60000).toISOString()})});return{challenge,origin,rpId}}
async function consumeChallenge(env,staffId,purpose,challenge){const r=(await sbRows(env,'staff_webauthn_challenges',{staff_id:`eq.${staffId}`,purpose:`eq.${purpose}`,challenge:`eq.${challenge}`,used_at:'is.null',order:'created_at.desc',limit:'1'}))[0];if(!r||new Date(r.expires_at).getTime()<Date.now())throw new Error('Challenge biometrik kedaluwarsa.');await supabaseRest(env,`/rest/v1/staff_webauthn_challenges?challenge_id=eq.${encodeURIComponent(r.challenge_id)}`,{method:'PATCH',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({used_at:new Date().toISOString()})});return r}
async function enrollmentByToken(env,token){const h=await shaB64(new TextEncoder().encode(token));const e=(await sbRows(env,'staff_biometric_enrollments',{token_hash:`eq.${h}`,used_at:'is.null',order:'created_at.desc',limit:'1'}))[0];if(!e||new Date(e.expires_at).getTime()<Date.now())throw new Error('Link pendaftaran sudah kedaluwarsa.');return e}
async function enrollOptions(env,request,b){const e=await enrollmentByToken(env,String(b.token||'')),s=(await sbRows(env,'staff_employees',{staff_id:`eq.${e.staff_id}`,limit:'1'}))[0];if(!s)throw new Error('Staff tidak ditemukan.');const existing=await sbRows(env,'staff_webauthn_credentials',{staff_id:`eq.${s.staff_id}`,active:'eq.true',select:'credential_id'});const c=await createChallenge(env,String(s.staff_id),'register',request);return{staffName:s.full_name,publicKey:{challenge:c.challenge,rp:{name:'Legacy Music Center Staff',id:c.rpId},user:{id:b64e(new TextEncoder().encode(String(s.staff_id))),name:s.employee_code,displayName:s.full_name},pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],timeout:60000,attestation:'none',authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'preferred',userVerification:'required'},excludeCredentials:existing.map(x=>({type:'public-key',id:x.credential_id}))}}}
async function enrollFinish(env,request,b){const e=await enrollmentByToken(env,String(b.token||'')),c=b.credential||{},r=c.response||{};if(!c.id||!r.clientDataJSON||!r.authenticatorData||!r.publicKey)throw new Error('Data pendaftaran tidak lengkap.');const cdBytes=b64d(r.clientDataJSON),cd=JSON.parse(new TextDecoder().decode(cdBytes));if(cd.type!=='webauthn.create')throw new Error('Jenis WebAuthn tidak valid.');const cr=await consumeChallenge(env,String(e.staff_id),'register',cd.challenge),{origin,rpId}=waCtx(request);if(cd.origin!==origin||cr.origin!==origin||cr.rp_id!==rpId)throw new Error('Domain Passkey tidak cocok.');const ad=b64d(r.authenticatorData);await validateAuthData(ad,rpId,true);const alg=Number(r.publicKeyAlgorithm);if(![-7,-257].includes(alg))throw new Error('Algoritma Passkey tidak didukung.');await supabaseRest(env,'/rest/v1/staff_webauthn_credentials',{method:'POST',headers:{'content-type':'application/json',Prefer:'resolution=merge-duplicates,return=minimal'},body:JSON.stringify({credential_id:c.id,staff_id:e.staff_id,public_key_spki:r.publicKey,algorithm:alg,sign_count:counter(ad),transports:Array.isArray(r.transports)?r.transports:[],device_label:String(b.deviceLabel||'').trim()||null,active:true})});await supabaseRest(env,`/rest/v1/staff_biometric_enrollments?enrollment_id=eq.${e.enrollment_id}`,{method:'PATCH',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({used_at:new Date().toISOString()})});return{message:'Passkey berhasil didaftarkan.'}}
async function authOptions(env,request,b){const code=String(b.employeeCode||'').trim().toUpperCase();const s=(await sbRows(env,'staff_employees',{employee_code:`eq.${code}`,status:'eq.Aktif',limit:'1'}))[0];if(!s)throw new Error('Kode Staff tidak ditemukan/aktif.');const creds=await sbRows(env,'staff_webauthn_credentials',{staff_id:`eq.${s.staff_id}`,active:'eq.true'});if(!creds.length)throw new Error('Passkey belum didaftarkan. Hubungi Admin.');const c=await createChallenge(env,String(s.staff_id),'authenticate',request);return{staffId:s.staff_id,staffName:s.full_name,publicKey:{challenge:c.challenge,rpId:c.rpId,timeout:60000,userVerification:'required',allowCredentials:creds.map(x=>({type:'public-key',id:x.credential_id,transports:Array.isArray(x.transports)?x.transports:undefined}))}}}
async function authVerify(env,request,b){const sid=String(b.staffId||''),c=b.credential||{},r=c.response||{};const st=(await sbRows(env,'staff_webauthn_credentials',{credential_id:`eq.${c.id}`,staff_id:`eq.${sid}`,active:'eq.true',limit:'1'}))[0];if(!st)throw new Error('Passkey tidak terdaftar.');const cdBytes=b64d(r.clientDataJSON),cd=JSON.parse(new TextDecoder().decode(cdBytes));if(cd.type!=='webauthn.get')throw new Error('Jenis autentikasi tidak valid.');const cr=await consumeChallenge(env,sid,'authenticate',cd.challenge),{origin,rpId}=waCtx(request);if(cd.origin!==origin||cr.origin!==origin||cr.rp_id!==rpId)throw new Error('Domain Passkey tidak cocok.');const ad=b64d(r.authenticatorData);await validateAuthData(ad,rpId,true);const ch=await sha(cdBytes), signed=new Uint8Array(ad.length+ch.length);signed.set(ad);signed.set(ch,ad.length);if(!await verifySig(Number(st.algorithm),st.public_key_spki,b64d(r.signature),signed))throw new Error('Verifikasi kriptografi gagal.');const cnt=counter(ad);if(cnt>0&&Number(st.sign_count||0)>0&&cnt<=Number(st.sign_count))throw new Error('Counter Passkey tidak valid.');await supabaseRest(env,`/rest/v1/staff_webauthn_credentials?credential_id=eq.${encodeURIComponent(c.id)}`,{method:'PATCH',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({sign_count:cnt,last_used_at:new Date().toISOString()})});const s=(await sbRows(env,'staff_employees',{staff_id:`eq.${sid}`,limit:'1'}))[0];if(!s)throw new Error('Staff tidak ditemukan.');const now=jakartaNow(),ex=(await sbRows(env,'staff_attendance',{staff_id:`eq.${sid}`,attendance_date:`eq.${now.date}`,limit:'1'}))[0];let action='check-in',message=`Absen masuk berhasil ${now.time.slice(0,5)}.`;if(!ex){await supabaseRest(env,'/rest/v1/staff_attendance',{method:'POST',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({staff_id:sid,staff_name_snapshot:s.full_name,position_snapshot:s.position,attendance_date:now.date,status:'Hadir',check_in:now.time,verification_method:'webauthn',biometric_credential_id:c.id,biometric_verified_at:new Date().toISOString(),recorded_by:'Biometrik Staff'})})}else if(!ex.check_out){action='check-out';message=`Absen pulang berhasil ${now.time.slice(0,5)}.`;await supabaseRest(env,`/rest/v1/staff_attendance?attendance_id=eq.${ex.attendance_id}`,{method:'PATCH',headers:{'content-type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({check_out:now.time,verification_method:'webauthn',biometric_credential_id:c.id,biometric_verified_at:new Date().toISOString(),recorded_by:'Biometrik Staff',updated_at:new Date().toISOString()})})}else{action='complete';message=`Absensi hari ini sudah lengkap. Masuk ${trimTime(ex.check_in)} • Pulang ${trimTime(ex.check_out)}.`}return{staffName:s.full_name,action,message,date:now.date,time:now.time.slice(0,5)}}
async function validateAuthData(ad,rpId,uv=false){if(ad.length<37)throw new Error('Authenticator data tidak valid.');const exp=await sha(new TextEncoder().encode(rpId));for(let i=0;i<32;i++)if(ad[i]!==exp[i])throw new Error('RP ID tidak cocok.');const f=ad[32];if(!(f&1))throw new Error('User presence gagal.');if(uv&&!(f&4))throw new Error('Verifikasi perangkat belum dilakukan.')}
function counter(ad){return ((ad[33]<<24)>>>0)+(ad[34]<<16)+(ad[35]<<8)+ad[36]}
function derToRaw(sig,size=32){const b=sig;if(b.length===size*2)return b;if(b[0]!==0x30)throw new Error('Signature ECDSA invalid.');let p=2;if(b[1]&0x80)p=2+(b[1]&0x7f);if(b[p++]!==2)throw new Error('R invalid');let rl=b[p++],rv=b.slice(p,p+rl);p+=rl;if(b[p++]!==2)throw new Error('S invalid');let sl=b[p++],sv=b.slice(p,p+sl);while(rv.length>size&&rv[0]===0)rv=rv.slice(1);while(sv.length>size&&sv[0]===0)sv=sv.slice(1);const o=new Uint8Array(size*2);o.set(rv.slice(-size),size-rv.slice(-size).length);o.set(sv.slice(-size),2*size-sv.slice(-size).length);return o}
async function verifySig(alg,spki,sig,data){const keyData=b64d(spki);if(alg===-7){const key=await crypto.subtle.importKey('spki',keyData,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);const raw=derToRaw(sig);return await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,raw,data)}if(alg===-257){const key=await crypto.subtle.importKey('spki',keyData,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);return await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,sig,data)}return false}
function jakartaNow(){const parts=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Jakarta',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).formatToParts(new Date());const m=Object.fromEntries(parts.map(x=>[x.type,x.value]));return{date:`${m.year}-${m.month}-${m.day}`,time:`${m.hour}:${m.minute}:${m.second}`}}
