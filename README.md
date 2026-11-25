# Dog Day Out — Cloudflare backend foundation

This is a **partial backend implementation**, not a deployable complete customer system. It includes D1 SQL schema, a Worker API with password hashing, session cookies, parent registration/login, dog records, 30-day booking requests, staff approvals, public schedules and updates.

## Setup (computer or GitHub workflow required)
1. In Cloudflare dashboard create a D1 database called `dog-day-out-db`.
2. Replace `REPLACE_WITH_YOUR_D1_DATABASE_ID` in `wrangler.jsonc` with the database ID.
3. Install Node.js and Wrangler (`npm install -g wrangler`) and authenticate (`wrangler login`).
4. From this directory run `wrangler d1 execute dog-day-out-db --remote --file=./schema.sql`.
5. Run `wrangler deploy`. Test `/api/health` at the resulting Worker URL.
6. If the frontend is on a different origin, route `/api/*` through the same domain using Cloudflare routing or Pages Functions. Cookie sessions require same-origin requests; this worker intentionally does not enable cross-origin credentialed requests.

## Important: not ready for public customer use
- **Email verification is not implemented**: registration records are unverified and cannot log in. Configure a transactional email provider and signed, single-use, expiring verification tokens before enabling sign-ins.
- **First staff account is not provisioned**: use a controlled admin onboarding process; never put shared staff passwords or the `9922` code in frontend source.
- **Password reset, login rate limiting, CSRF protection, audit logs, and abuse protection** are required before public launch. Origin checking alone is not complete CSRF protection.
- **Vaccination file uploads and R2 policies, GPS collar integration, destination votes, and frontend integration** are not yet implemented. The schema reserves tables for some of these features.
- The date limit uses America/New_York and should be adapted if the business operates elsewhere.
- The existing Cloudflare preview is **not yet wired** to this API. Do not claim it is fully operational.
- Do not migrate real customers or medical/vaccination records until privacy/security review and end-to-end tests are complete.
- Dog Day Out deployment test
