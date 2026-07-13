// Emails the 6-digit verification code for an access request.
//
// The code is derived (HMAC) from the issue number + requester's GitHub login,
// so nothing has to be stored: the verify job recomputes it the same way.
// The code is never logged.
//
// Env vars:
//   CODE_KEY                      HMAC key (repo secret)
//   MAIL_USERNAME, MAIL_PASSWORD  Office 365 credentials (app password)
//   TO_EMAIL                      the requester's work email
//   ISSUE_NUMBER, AUTHOR          the access-request issue and its author

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

const ALLOWED_DOMAINS = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'config', 'allowed-domains.json'), 'utf8'),
).domains.map((d) => String(d).toLowerCase());

const env = {};
for (const key of ['CODE_KEY', 'MAIL_USERNAME', 'MAIL_PASSWORD', 'TO_EMAIL', 'ISSUE_NUMBER', 'AUTHOR']) {
  env[key] = process.env[key] || '';
  if (!env[key]) {
    console.error(`${key} is not set — cannot send the verification code.`);
    process.exit(1);
  }
}

const toEmail = env.TO_EMAIL.toLowerCase();
if (!/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(toEmail)
  || !ALLOWED_DOMAINS.some((d) => toEmail.endsWith('@' + d))) {
  console.error('Refusing to send: the recipient is not on an allowed email domain.');
  process.exit(1);
}

const hex = crypto.createHmac('sha256', env.CODE_KEY)
  .update(`${env.ISSUE_NUMBER}:${env.AUTHOR}`)
  .digest('hex');
const code = String(parseInt(hex.slice(0, 12), 16) % 1000000).padStart(6, '0');

const html =
  `<div style="font-family:Calibri,'Segoe UI',sans-serif;font-size:15px;line-height:1.6">` +
  `<p>Hi,</p>` +
  `<p>Your verification code for the CSTP course repository access request ` +
  `(<b>@${env.AUTHOR}</b>, request #${env.ISSUE_NUMBER}) is:</p>` +
  `<p style="font-size:28px;letter-spacing:6px;font-weight:bold">${code}</p>` +
  `<p>Reply to your access request on GitHub with this code and your access is granted automatically.</p>` +
  `<p style="color:#777;font-size:12px">If you did not request access, you can ignore this email — ` +
  `nothing is granted without this code.</p>` +
  `</div>`;

const transporter = nodemailer.createTransport({
  host: 'smtp.office365.com',
  port: 587,
  secure: false,
  requireTLS: true,
  auth: { user: env.MAIL_USERNAME, pass: env.MAIL_PASSWORD },
});

transporter
  .sendMail({
    from: `CSTP Access <${env.MAIL_USERNAME}>`,
    to: env.TO_EMAIL,
    subject: `CSTP repository access — your verification code (request #${env.ISSUE_NUMBER})`,
    html,
  })
  .then((info) => console.log(`Verification code sent (${info.messageId}).`))
  .catch((err) => {
    console.error(`Email failed: ${err.message}`);
    process.exit(1);
  });
