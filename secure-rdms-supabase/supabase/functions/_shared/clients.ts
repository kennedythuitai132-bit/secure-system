import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.0';
export const service = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false, autoRefreshToken: false } });
export async function authenticatedUser(req: Request) {
  const header = req.headers.get('Authorization');
  if (!header?.startsWith('Bearer ')) throw new Error('Authentication required');
  const token = header.slice(7);
  const { data, error } = await service.auth.getUser(token);
  if (error || !data.user) throw new Error('Invalid or expired session');
  const { data: claimsData, error: claimsError } = await service.auth.getClaims(token);
  if (claimsError || claimsData?.claims?.aal !== 'aal2') throw new Error('Complete multi-factor authentication before accessing protected resources.');
  const { data: profile, error: profileError } = await service.from('profiles').select('*').eq('id', data.user.id).single();
  if (profileError || !profile || !profile.is_active) throw new Error('Account is inactive or unavailable');
  return { user: data.user, profile };
}
export async function audit(userId: string | null, username: string, action: string, resource: string, details: string, req: Request, status = 'success') {
  await service.from('audit_logs').insert({ user_id: userId, username, action, resource, details, ip_address: req.headers.get('x-forwarded-for')?.split(',')[0] || null, user_agent: req.headers.get('user-agent') || null, status });
}
export function errorMessage(error: unknown) { return error instanceof Error ? error.message : 'Unexpected server error'; }
