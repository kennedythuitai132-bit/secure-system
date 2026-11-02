# Verification checklist

## Checks completed in this build environment

- TypeScript/TSX transpilation syntax checks passed for all frontend source files.
- TypeScript transpilation syntax checks passed for all Supabase Edge Function source files.
- Reviewed the Supabase migrations, RLS policies, private storage bucket configuration and Edge Function authorization paths for consistency.
- Verified no Supabase service-role key or encryption key is present in the repository template.

## Checks requiring project credentials / package installation

The full Vite production build, Supabase migration application and live end-to-end tests must be run after configuring a Supabase project. Dependency installation could not complete in the build environment because the npm registry was unreachable; therefore this package has not been represented as having passed `npm run typecheck` or `npm run build` here.

Run:

```bash
npm install
npm run typecheck
npm run build
```

Then apply migrations and deploy Edge Functions as described in `README.md`. Use a non-production Supabase project to test:

1. Signup, email confirmation, sign-in and TOTP enrolment.
2. Login with a wrong password and five failed attempts; verify a high-severity alert appears.
3. Login with a wrong TOTP code five times; verify an MFA alert appears.
4. Admin upload, user assignment, encrypted storage and authorised download.
5. Researcher upload and owner-only access; assigned researcher/viewer download.
6. Attempt an unassigned download; verify HTTP 403, audit event and high-severity alert.
7. Verify viewers cannot upload and non-admins cannot access admin functions.
8. Create users, change roles and disable accounts; verify disabled users lose access.
9. Resolve alerts, inspect audit events and compare report counts with recorded events.
10. Confirm a browser session without AAL2 cannot read protected file metadata or invoke file/admin Edge Functions.
