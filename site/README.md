# enki landing page & waitlist

Static page (`index.html`, `styles.css`, `app.js`) with a hosted-beta waitlist
form. The form posts JSON to the `enki-cloud` endpoint `POST /v1/waitlist`
(CORS enabled; duplicate emails return `200 already subscribed`).

## Configure

Set the API origin in `app.js` (or define it before the script loads):

```html
<script>window.ENKI_WAITLIST_ENDPOINT = "https://cloud.example.com/v1/waitlist";</script>
<script src="app.js"></script>
```

If the site and API share an origin, the default `/v1/waitlist` works.

## Deploy

- **GitHub Pages:** Settings → Pages → deploy from branch, folder `/site`.
- **Netlify / Cloudflare Pages:** publish directory `site`, no build step.
- **Self-host:** serve this directory with any static server. The waitlist API
  is part of `cmd/enki-cloud`.

## Admin

List signups (requires the cloud admin key):

```bash
curl -s https://cloud.example.com/v1/admin/waitlist \
  -H "Authorization: Bearer $ENKI_CLOUD_ADMIN_KEY" | jq
```

Signups are stored by the cloud store (in-memory in the beta). Emails are
lowercased and deduplicated; audit events record only that a signup happened,
never the address. Add proxy-level rate limiting before a public launch.
