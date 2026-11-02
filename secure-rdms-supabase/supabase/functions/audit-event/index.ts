import { corsHeaders, json } from '../_shared/cors.ts';
import { service, authenticatedUser, audit, errorMessage } from '../_shared/clients.ts';
Deno.serve(async req => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  try {
    const { user, profile } = await authenticatedUser(req);
    const { action, resource = 'system', details = '' } = await req.json();
    const allowed = ['LOGIN','LOGOUT'];
    if (!allowed.includes(action)) return json({ error: 'Unsupported audit event.' }, 400);
    await audit(user.id, profile.username || user.email || 'user', action, String(resource).slice(0,150), String(details).slice(0,1000), req);
    return json({ success: true });
  } catch (e) { return json({ error: errorMessage(e) }, 400); }
});
