import { corsHeaders, json } from '../_shared/cors.ts';
import { service, authenticatedUser, audit, errorMessage } from '../_shared/clients.ts';
import { decryptFile } from '../_shared/crypto.ts';
Deno.serve(async req => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  try {
    const { user, profile } = await authenticatedUser(req);
    const { file_id } = await req.json();
    const { data: file, error } = await service.from('research_files').select('*').eq('id', file_id).single();
    if (error || !file) return json({ error: 'File not found.' }, 404);
    let permitted = profile.role === 'admin' || file.uploaded_by === user.id;
    if (!permitted) {
      const { data: assignment } = await service.from('file_assignments').select('id').eq('file_id', file.id).eq('user_id', user.id).maybeSingle();
      permitted = Boolean(assignment);
    }
    if (!permitted) { await audit(user.id, profile.username || user.email || 'user', 'FILE_ACCESS_DENIED', file.id, 'Unauthorised download attempt', req, 'failed'); await service.from('security_alerts').insert({ user_id: user.id, alert_type: 'UNAUTHORISED_FILE_ACCESS', message: `User ${profile.username || user.email || user.id} attempted to download a file without permission.`, severity: 'high' }); return json({ error: 'You are not authorised to access this file.' }, 403); }
    const { data: object, error: storageError } = await service.storage.from('research-vault').download(file.storage_path);
    if (storageError || !object) throw storageError || new Error('Encrypted file unavailable');
    const encrypted = new Uint8Array(await object.arrayBuffer());
    const plain = await decryptFile(encrypted);
    const encoded = btoa(Array.from(plain, b => String.fromCharCode(b)).join(''));
    await audit(user.id, profile.username || user.email || 'user', 'FILE_DOWNLOAD', file.id, `Downloaded ${file.original_filename}`, req);
    return json({ filename: file.original_filename, mime_type: file.mime_type, content_base64: encoded });
  } catch (e) { return json({ error: errorMessage(e) }, 400); }
});
