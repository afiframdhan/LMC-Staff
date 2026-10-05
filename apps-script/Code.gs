/** Legacy Staff - upload foto staff ke Google Drive.
 * Script Properties wajib:
 * STAFF_PHOTO_FOLDER_ID = ID folder Google Drive tujuan
 * STAFF_UPLOAD_SECRET = secret panjang yang sama dengan Cloudflare STAFF_PHOTO_UPLOAD_SECRET
 * Deploy sebagai Web App: Execute as Me, Who has access: Anyone.
 */
function doPost(e) {
  try {
    const body = JSON.parse((e && e.postData && e.postData.contents) || '{}');
    const props = PropertiesService.getScriptProperties();
    const secret = props.getProperty('STAFF_UPLOAD_SECRET') || '';
    if (!secret || String(body.secret || '') !== secret) return json_({ok:false,error:'Unauthorized'});
    if (body.action !== 'uploadStaffPhoto') return json_({ok:false,error:'Action tidak dikenali'});

    const folderId = props.getProperty('STAFF_PHOTO_FOLDER_ID') || '';
    if (!folderId) throw new Error('STAFF_PHOTO_FOLDER_ID belum diisi di Script Properties.');
    const folder = DriveApp.getFolderById(folderId);
    const data = String(body.imageData || '');
    const match = data.match(/^data:(image\/(?:jpeg|jpg|png|webp));base64,(.+)$/i);
    if (!match) throw new Error('Data gambar tidak valid.');
    const mime = match[1].toLowerCase().replace('image/jpg','image/jpeg');
    const bytes = Utilities.base64Decode(match[2]);
    if (bytes.length > 3500000) throw new Error('Ukuran gambar terlalu besar.');

    const code = safe_(body.employeeCode || 'STAFF').toUpperCase();
    const name = safe_(body.staffName || 'Staff');
    const ext = mime === 'image/png' ? 'png' : mime === 'image/webp' ? 'webp' : 'jpg';
    const filename = `${code}_${name}_${Utilities.formatDate(new Date(), Session.getScriptTimeZone() || 'Asia/Jakarta', 'yyyyMMdd_HHmmss')}.${ext}`;
    const blob = Utilities.newBlob(bytes, mime, filename);
    const file = folder.createFile(blob);
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);

    // Hapus foto lama jika URL lama memang menunjuk file Drive dan file tersebut berada di folder yang sama.
    try {
      const oldId = extractDriveId_(String(body.oldPhotoUrl || ''));
      if (oldId && oldId !== file.getId()) {
        const old = DriveApp.getFileById(oldId);
        const parents = old.getParents();
        let sameFolder = false;
        while (parents.hasNext()) if (parents.next().getId() === folderId) { sameFolder = true; break; }
        if (sameFolder) old.setTrashed(true);
      }
    } catch (_) {}

    const url = `https://drive.google.com/thumbnail?id=${file.getId()}&sz=w1200`;
    return json_({ok:true,url:url,fileId:file.getId(),name:file.getName()});
  } catch (err) {
    return json_({ok:false,error:String(err && err.message || err)});
  }
}
function safe_(v) { return String(v || '').trim().replace(/[^A-Za-z0-9 _.-]+/g,'').replace(/\s+/g,' ').slice(0,60) || 'Staff'; }
function extractDriveId_(url) {
  const s = String(url || '');
  let m = s.match(/[?&]id=([A-Za-z0-9_-]{10,})/); if (m) return m[1];
  m = s.match(/\/d\/([A-Za-z0-9_-]{10,})/); return m ? m[1] : '';
}
function json_(obj) { return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON); }
