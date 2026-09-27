# Google Accounts and Cluster Roles

Cluster Desk uses Supabase Auth for Google sign-in and Supabase Postgres row-level security for shared cluster access. Browser local mode is separate and is not a secure account.

## Configure Supabase

1. Create a Supabase project.
2. In the Supabase SQL Editor, run [`supabase/migrations/20260927000000_cluster_roles.sql`](supabase/migrations/20260927000000_cluster_roles.sql).
3. In Supabase Authentication, enable Google and configure its OAuth client ID and secret. Use the callback URL shown by Supabase in the Google Cloud OAuth client.
4. In Authentication URL Configuration, set the site URL to `https://cluster-desk.vercel.app` and allow that URL and your local development URL as redirect URLs.
5. Copy the project URL and the public anon/publishable key from Supabase into [`auth-config.js`](auth-config.js):

   ```js
   window.CLUSTER_AUTH_CONFIG = {
     supabaseUrl: 'https://YOUR_PROJECT.supabase.co',
     supabaseAnonKey: 'YOUR_PUBLIC_ANON_OR_PUBLISHABLE_KEY'
   };
   ```

   The anon/publishable key is intended for browser use. Never put the Supabase service-role key or Google client secret in this file.
6. Commit and push the configured `auth-config.js` to GitHub so Vercel deploys it. Configure the same Supabase redirect URL for the production deployment.

## Account Workflow

- A Google account that creates a cluster becomes its first LSA manager.
- From Cluster settings, an LSA can create an invitation link for an LSA or individual account.
- Share the link with the invited person. They must sign in with the exact email address the LSA invited. Links expire after 14 days.
- LSA accounts can add and edit cluster information. Individual accounts can view cluster information and generate reports, but cannot change shared data.
- Database row-level security enforces cluster membership and LSA-only writes; client-side control hiding is not the security boundary.
- Each account sees only clusters where it has a membership. Separate clusters remain isolated.

Existing data saved in device-only mode is not uploaded or shared automatically. Export it from Cluster settings and arrange a deliberate migration before using shared accounts.
