import { corsHeaders, json } from '../_shared/cors.ts';
import { service, authenticatedUser, audit, errorMessage } from '../_shared/clients.ts';
import { encryptFile } from '../_shared/crypto.ts';
Deno.serve(async req => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  try {
    const { user, profile } = await authenticatedUser(req);
    if (!['admin','researcher'].includes(profile.role)) return json({ error: 'Your role cannot upload research files.' }, 403);
    const body = await req.json();
    const { title, project_code, description = '', filename, mime_type, content_base64, assigned_user_ids = [] } = body;
    if (!title?.trim() || !project_code?.trim() || !filename || !content_base64) return json({ error: 'Title, project code and file are required.' }, 400);
    if (typeof content_base64 !== 'string' || content_base64.length > 5_600_000) return json({ error: 'File exceeds the 4 MB limit.' }, 413);
    const bytes = Uint8Array.from(atob(content_base64), c => c.charCodeAt(0));
    if (!bytes.length || bytes.length > 4 * 1024 * 1024) return json({ error: 'File must be between 1 byte and 4 MB.' }, 400);
    const allowed = ['application/pdf','text/plain','text/csv','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/msword','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.presentationml.presentation','application/vnd.ms-powerpoint','image/png','image/jpeg','application/zip','application/octet-stream'];
    if (!allowed.includes(mime_type)) return json({ error: 'File type is not allowed.' }, 400);
    const encrypted = await encryptFile(bytes);
    const id = crypto.randomUUID(), path = `${user.id}/${id}.enc`;
    const { error: uploadError } = await service.storage.from('research-vault').upload(path, encrypted, { contentType: 'application/octet-stream', upsert: false });
    if (uploadError) throw uploadError;
    const { data: record, error: insertError } = await service.from('research_files').insert({ id, title: title.trim(), project_code: project_code.trim(), description: String(description).slice(0,2000), original_filename: filename.replace(/[\\/]/g,'_').slice(0,255), mime_type, file_size: bytes.length, storage_path: path, uploaded_by: user.id }).select().single();
    if (insertError) { await service.storage.from('research-vault').remove([path]); throw insertError; }
    if (profile.role === 'admin' && Array.isArray(assigned_user_ids) && assigned_user_ids.length) {
      const ids = [...new Set(assigned_user_ids.filter((v: unknown) => typeof v === 'string' && v !== user.id))] as string[];
      if (ids.length > 100) {
        await service.from('research_files').delete().eq('id', id);
        await service.storage.from('research-vault').remove([path]);
        return json({ error: 'A file can be assigned to at most 100 users.' }, 400);
      }
      if (ids.length) {
        const { data: activeUsers, error: lookupError } = await service.from('profiles').select('id').in('id', ids).eq('is_active', true);
        if (lookupError || activeUsers?.length !== ids.length) {
          await service.from('research_files').delete().eq('id', id);
          await service.storage.from('research-vault').remove([path]);
          return json({ error: 'One or more selected users are unavailable.' }, 400);
        }
        const { error: assignmentError } = await service.from('file_assignments').insert(ids.map(user_id => ({ file_id: id, user_id, assigned_by: user.id })));
        if (assignmentError) {
          await service.from('research_files').delete().eq('id', id);
          await service.storage.from('research-vault').remove([path]);
          throw assignmentError;
        }
      }
    }
    await audit(user.id, profile.username || user.email || 'user', 'FILE_UPLOAD', id, `Uploaded ${filename} (${bytes.length} bytes)`, req);
    return json({ file: record });
  } catch (e) { return json({ error: errorMessage(e) }, 400); }
});
