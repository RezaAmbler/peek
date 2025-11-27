# Email Configuration Guide

## Gmail Setup (Recommended for Testing)

### Step 1: Enable 2-Factor Authentication
1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable "2-Step Verification"

### Step 2: Generate App Password
1. Go to [App Passwords](https://myaccount.google.com/apppasswords)
2. Select app: **Mail**
3. Select device: **Other (Custom name)**
4. Enter name: **PEEK Scanner**
5. Click **Generate**
6. Copy the 16-character password (e.g., `abcd efgh ijkl mnop`)

### Step 3: Configure PEEK
Edit `backend/.env`:

```bash
SMTP_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=abcdefghijklmnop  # No spaces
SMTP_FROM_EMAIL=your-email@gmail.com
SMTP_FROM_NAME=PEEK Security Scanner
SMTP_USE_TLS=true
```

### Step 4: Restart Services
```bash
docker-compose restart backend celery celery-beat
```

### Step 5: Test
1. Create a scheduled scan with email notification
2. Add your email in recipients
3. Run the scan
4. Check your inbox (and spam folder)

---

## Other SMTP Providers

### SendGrid
```bash
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=your-sendgrid-api-key
```

### Mailgun
```bash
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USER=postmaster@your-domain.mailgun.org
SMTP_PASSWORD=your-mailgun-password
```

### AWS SES
```bash
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=your-ses-smtp-username
SMTP_PASSWORD=your-ses-smtp-password
```

### Custom SMTP Server
```bash
SMTP_HOST=mail.yourcompany.com
SMTP_PORT=587  # or 465 for SSL
SMTP_USER=noreply@yourcompany.com
SMTP_PASSWORD=your-password
SMTP_USE_TLS=true  # or false for SSL on port 465
```

---

## Testing Email

### Test via Scheduled Scan
1. Go to Scheduled Scans → New
2. Fill in details
3. Enable "Email on completion"
4. Add your email
5. Set cron to `* * * * *` (every minute)
6. Save and wait

### Test via Logs
```bash
docker-compose logs celery | grep -i email
docker-compose logs celery-beat | grep -i email
```

### Expected Output
```
✅ Email sent successfully to ['you@example.com']: [PEEK] ✅ Scan Complete: Test Scan
```

---

## Troubleshooting

### Email not sending
1. Check `SMTP_ENABLED=true` in `.env`
2. Verify credentials are correct
3. Check logs: `docker-compose logs celery`
4. Test SMTP connection manually

### Gmail "Less secure app" error
- Enable 2FA and use App Password (not your regular password)

### Authentication failed
- Double-check SMTP_USER and SMTP_PASSWORD
- Remove any spaces from password
- Try regenerating app password

### Emails in spam
- Set SMTP_FROM_EMAIL to a valid email you control
- Consider SPF/DKIM records (advanced)

### No attachment in email
- Check logs for PDF generation errors
- Verify scan completed successfully
- Ensure reportlab is installed

---

## Email Features

### What's Included in Emails
- ✅ Scan summary (targets, ports, vulnerabilities)
- ✅ HTML formatted with styling
- ✅ Comparison summary (if changes detected)
- ✅ Link to view full report
- ✅ Executive summary PDF attached
- ✅ Mobile-friendly responsive design

### When Emails Are Sent
- Scheduled scan completes (if `email_on_completion=true`)
- Changes detected (if `email_on_changes_only=true`)
- Critical vulnerabilities found (if `alert_on_critical=true`)
- New vulnerabilities detected (if `alert_on_new_vulns=true`)
