# Secure Research Data Management System (Secure RDMS)

A responsive research document portal based on the supplied Secure RDMS system documentation. This implementation uses React + TypeScript + Vite, Supabase Auth/Postgres/Storage and Supabase Edge Functions.

## Implemented capabilities

- Email/password registration and sign-in through Supabase Auth.
- Mandatory authenticator-app MFA (TOTP). Protected data policies and Edge Functions require Supabase AAL2.
- Roles: `admin`, `researcher`, `viewer`; self-registration always creates a researcher.
- Role- and ownership/assignment-aware repository metadata access.
- Private `research-vault` bucket; files are encrypted with AES-256-GCM in Edge Functions before storage. The encryption key is never sent to the browser.
- Server-side file download authorization and authenticated decryption.
- Admin user creation, role assignment and account activation/deactivation.
- Audit event records, administrator audit view, security alert centre and activity reports.
- Responsive dark dashboard for overview, files, audit, alerts, reports and user management.

## Requirements

- Node.js 20+
- A Supabase project
- Supabase CLI (for migrations and Edge Functions)

## 1. Configure Supabase

1. Create a Supabase project.
2. Copy `.env.example` to `.env` and set:

   ```env
   VITE_SUPABASE_URL=https://YOUR_PROJECT_ID.supabase.co
   VITE_SUPABASE_ANON_KEY=YOUR_SUPABASE_PUBLISHABLE_OR_ANON_KEY
   ```

   Only the publishable/anon key belongs in the frontend. **Never** put the service-role key in `VITE_*` variables or commit secrets.

3. Set Edge Function secrets in the Supabase project (Dashboard → Edge Functions → Secrets, or CLI):

   ```bash
   supabase secrets set RDMS_ENCRYPTION_KEY="$(openssl rand -base64 32)"
   supabase secrets set APP_ORIGIN="https://YOUR_DEPLOYED_SITE.example"
   ```

   `RDMS_ENCRYPTION_KEY` must be a base64-encoded random 32-byte key. Back it up in a secure secrets manager. Losing it makes encrypted files unrecoverable. Rotating it requires a controlled re-encryption migration.

4. Link and apply migrations:

   ```bash
   supabase login
   supabase link --project-ref YOUR_PROJECT_REF
   supabase db push
   ```

5. Deploy the Edge Functions:

   ```bash
   supabase functions deploy file-upload
   supabase functions deploy file-download
   supabase functions deploy admin-users
   supabase functions deploy audit-event
   supabase functions deploy auth-failure
   ```

6. In Supabase Authentication → URL Configuration, set the Site URL to your deployment URL and add your local and production callback URLs to the redirect allow list. Enable email confirmation according to your institution's policy. TOTP MFA is used by this app; make sure TOTP is enabled in Authentication → Multi-Factor Authentication.

## 2. Create the first administrator

Self-service signup intentionally cannot select an administrator role. Register the first account, verify its email if required, sign in, and complete TOTP enrolment. Then run the following once in Supabase SQL Editor, replacing the email with the first administrator's verified email:

```sql
update public.profiles
set role = 'admin'
where email = 'admin@your-university.ac.ke';
```

Sign out and sign in again so the updated role is loaded. Thereafter administrators can create users and manage roles from **User management**. Do not leave a publicly shared SQL editor or admin credentials exposed.

## 3. Run locally

```bash
npm install
cp .env.example .env
# Edit .env with your Supabase URL and publishable/anon key
npm run dev
```

Open the local URL printed by Vite (normally `http://localhost:5173`).

## 4. Build and deploy

```bash
npm run typecheck
npm run build
```

Deploy the generated `dist/` directory to Vercel, Netlify, Cloudflare Pages or any static host. Configure the same two `VITE_` environment variables in the hosting provider and redeploy. Supabase hosts the database, authentication, storage and Edge Functions separately. Add a SPA rewrite to `/index.html` if your host requires it.

### GitHub

```bash
git init
git add .
git commit -m "Build Secure RDMS with Supabase"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/secure-rdms.git
git push -u origin main
```

Connect the GitHub repository to your frontend host and set the build command to `npm run build` and output directory to `dist`.

## Security model and important notes

- Browser clients use only the Supabase publishable/anon key. Service-role access exists only in Edge Function runtime secrets.
- RLS is enabled on application tables. Sensitive reads require AAL2, and file operations are routed through Edge Functions that independently verify the bearer token, active profile, role and file ownership/assignment.
- The storage bucket is private and has no direct browser object policies. The browser cannot fetch encrypted objects directly.
- File encryption uses AES-256-GCM with a random 96-bit IV per file. The authentication tag is included in Web Crypto's ciphertext output; tampering causes decryption to fail.
- File size is limited to 4 MB per upload to stay within the Edge Function request payload budget. The accepted MIME list is enforced server-side; MIME declarations alone do not prove file safety. For production, add malware scanning/content-disarm, quotas, key rotation, SIEM forwarding, backup/restore drills and independent penetration testing.
- This is a deployable academic baseline, not a claim of completed third-party penetration testing or production certification. Test in a non-production Supabase project before storing real research data.
- Repeated login and MFA failures are submitted to a service-role-only database RPC by the `auth-failure` Edge Function; five failures for the same account within ten minutes create an alert. Supabase Auth remains responsible for credential verification and its own platform-level throttling.

## Roles

| Role | Capabilities |
|---|---|
| Administrator | All repository metadata and downloads; user management; audit, alerts and reports |
| Researcher | Upload files; access files they uploaded or were assigned |
| Viewer | Read/download only files explicitly assigned to them |

## Repository structure

```text
src/                         React application and styles
supabase/migrations/         PostgreSQL schema, RLS and private bucket
supabase/functions/           Authenticated upload/download/admin/audit APIs
.env.example                 Frontend environment template
```
