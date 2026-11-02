import { corsHeaders, json } from '../_shared/cors.ts';
import { service, errorMessage } from '../_shared/clients.ts';
Deno.serve(async req => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  try {
    const body = await req.json();
    const kind = body.kind;
    let username = '';
    if (kind === 'login') {
      username = String(body.email || '').trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(username)) return json({ error: 'Invalid account identifier.' }, 400);
    } else if (kind === 'mfa') {
      const header = req.headers.get('Authorization');
      if (!header?.startsWith('Bearer ')) return json({ error: 'Authentication required.' }, 401);
      const token = header.slice(7);
      const { data, error } = await service.auth.getUser(token);
      const { data: claims } = await service.auth.getClaims(token);
      if (error || !data.user || !claims?.claims?.aal) return json({ error: 'Invalid session.' }, 401);
      username = data.user.email || data.user.id;
    } else return json({ error: 'Unsupported failure type.' }, 400);
    const ip = (req.headers.get('x-forwarded-for') || '').split(',')[0].trim().slice(0, 64) || 'unknown';
    const { error } = await service.rpc('record_auth_failure', { p_username: username, p_event_type: kind === 'mfa' ? 'mfa_failed' : 'login_failed', p_ip: ip });
    if (error) throw error;
    return json({ success: true });
  } catch (e) { return json({ error: errorMessage(e) }, 400); }
});
