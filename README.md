# InvoiceClaw
Tell Claude who to invoice -> a live, trackable invoice appears in this app. No AI inside; Claude (the customer's own plan) does the thinking.

## Deploy (Render, ~10 min)
1. Push this folder to a GitHub repo.
2. Render -> New Web Service -> connect repo. Build: `npm install`  Start: `npm start`
3. Add a Disk mounted at `/data` and env var `DB_PATH=/data/data.db` (otherwise data resets on redeploy).
4. Env var `BASE_URL=https://<your-app>.onrender.com` (no trailing slash).
5. Optional: `RESEND_API_KEY` + `MAIL_FROM` for real overdue-reminder emails (without them reminders are logged only).

## Connect to Claude
1. Open the live app, log in (test login: demo / demo1234).
2. Copy the MCP URL shown on the dashboard.
3. Claude -> Settings -> Connectors -> Add custom connector -> paste URL -> Add.
4. Try: "Invoice Acme Corp 50,000 INR for May design work, due in 15 days."

Tools: create_invoice, list_invoices, update_invoice. Local run: `npm install && npm start`.
