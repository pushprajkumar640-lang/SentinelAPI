<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://ai.google.dev/static/site-assets/images/share-ais-513315318.png" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/1dd47d85-ff9d-437e-a2be-a25e75e61724

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Running without an external database

The app no longer requires a PostgreSQL server to start. If `SQL_HOST` is not
set, it automatically uses an embedded PostgreSQL database (PGlite) created
from `drizzle/*.sql`, stored in `node_modules/.cache/sentinel-pglite`
(override with `PGLITE_DATA_DIR`).

To use a real PostgreSQL / Cloud SQL instance instead, copy `.env.example` to
`.env` and fill in `SQL_HOST`, `SQL_USER`, `SQL_PASSWORD` and `SQL_DB_NAME`,
then run `npm run db:push`.

`GEMINI_API_KEY` is optional: without it the app works normally and only the
AI Copilot stays disabled. Firebase auth config lives in
`firebase-applet-config.json`.

Scripts: `npm run dev`, `npm run build`, `npm start`, `npm test`,
`npm run db:generate`, `npm run db:push`.
"# SentinelAPI" 
