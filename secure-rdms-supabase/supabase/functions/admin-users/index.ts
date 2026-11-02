import { corsHeaders, json } from '../_shared/cors.ts';
import { service, authenticatedUser, audit, errorMessage } from '../_shared/clients.ts';
Deno.serve(async req => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  try {
    const { user, profile } = await authenticatedUser(req);
    if (profile.role !== 'admin') return json({ error: 'Administrator access required.' }, 403);
    const body = await req.json();
    if (body.action === 'create') {
      const { full_name, email, password, role } = body;
      if (!full_name?.trim() || !email?.trim() || typeof password !== 'string' || password.length < 10 || !['admin','researcher','viewer'].includes(role)) return json({ error: 'Provide a name, valid email, password of at least 10 characters and valid role.' }, 400);
      const { data, error } = await service.auth.admin.createUser({ email: email.trim().toLowerCase(), password, email_confirm: true, user_metadata: { full_name: full_name.trim() } });
      if (error || !data.user) throw error || new Error('Could not create account');
      const { error: roleError } = await service.from('profiles').update({ full_name: full_name.trim(), role }).eq('id', data.user.id);
      if (roleError) { await service.auth.admin.deleteUser(data.user.id); throw roleError; }
      await audit(user.id, profile.username || user.email || 'admin', 'USER_CREATED', data.user.id, `Created ${role} account ${email}`, req);
      return json({ user_id: data.user.id });
    }
    if (body.action === 'status') {
      if (body.user_id === user.id) return json({ error: 'You cannot disable your own account.' }, 400);
      const { error } = await service.from('profiles').update({ is_active: Boolean(body.is_active) }).eq('id', body.user_id);
      if (error) throw error;
      await audit(user.id, profile.username || user.email || 'admin', 'USER_STATUS_CHANGED', body.user_id, `Account active: ${Boolean(body.is_active)}`, req);
      return json({ success: true });
    }
    if (body.action === 'role') {
      if (body.user_id === user.id) return json({ error: 'You cannot change your own role.' }, 400);
      if (!['admin','researcher','viewer'].includes(body.role)) return json({ error: 'Invalid role.' }, 400);
      const { error } = await service.from('profiles').update({ role: body.role }).eq('id', body.user_id);
      if (error) throw error;
      await audit(user.id, profile.username || user.email || 'admin', 'USER_ROLE_CHANGED', body.user_id, `Role changed to ${body.role}`, req);
      return json({ success: true });
    }
    return json({ error: 'Unsupported action.' }, 400);
  } catch (e) { return json({ error: errorMessage(e) }, 400); }
});
