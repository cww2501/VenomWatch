'use strict';

const express = require('express');
const crypto = require('crypto');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken');
const { rateLimit } = require('express-rate-limit');

const router = express.Router();
const resend = new Resend(process.env.RESEND_API_KEY);

// In-memory OTP store: email → { code, expiresAt, attempts, lockedUntil }
const otpStore = new Map();

const OTP_EXPIRY_MS     = 10 * 60 * 1000;   // 10 minutes
const OTP_MAX_ATTEMPTS  = 5;
const OTP_LOCKOUT_MS    = 15 * 60 * 1000;   // 15 minutes
const JWT_EXPIRY        = '60m';

// Rolling send-code rate limit (max 5 per hour, per IP)
const sendCodeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many code requests. Try again in an hour.' },
});

function generateOTP() {
  // 6-digit code using crypto — never Math.random
  const n = crypto.randomBytes(4).readUInt32BE(0) % 1_000_000;
  return String(n).padStart(6, '0');
}

function safeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) {
    // Still run timingSafeEqual on equal-length buffers to avoid timing leak
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

// POST /auth/send-code
router.post('/send-code', sendCodeLimiter, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }

  const existing = otpStore.get(email);
  if (existing?.lockedUntil && Date.now() < existing.lockedUntil) {
    const mins = Math.ceil((existing.lockedUntil - Date.now()) / 60_000);
    return res.status(429).json({ error: `Account locked. Try again in ${mins} minute(s).` });
  }

  const code = generateOTP();
  otpStore.set(email, {
    code,
    expiresAt: Date.now() + OTP_EXPIRY_MS,
    attempts: 0,
    lockedUntil: null,
  });

  try {
    await resend.emails.send({
      from: process.env.RESEND_FROM_EMAIL,
      to: email,
      subject: 'Your VenomWatch Access Code',
      html: `
        <div style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:32px;border-radius:8px;max-width:480px">
          <div style="color:#e53935;font-size:22px;font-weight:bold;letter-spacing:4px;margin-bottom:8px">VENOM WATCH</div>
          <div style="color:#666;font-size:12px;margin-bottom:24px">// AI Security Intake Assessor</div>
          <div style="color:#aaa;margin-bottom:16px">Your one-time access code is:</div>
          <div style="font-size:40px;letter-spacing:12px;color:#fff;background:#111;padding:16px 24px;border-radius:4px;display:inline-block;margin-bottom:24px">${code}</div>
          <div style="color:#666;font-size:12px">Expires in 10 minutes. Do not share this code.</div>
        </div>
      `,
    });
  } catch (err) {
    console.error('Resend error:', err?.message);
    return res.status(502).json({ error: 'Failed to send email. Please try again.' });
  }

  res.json({ ok: true, message: 'Code sent.' });
});

// POST /auth/verify-code
router.post('/verify-code', (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const code  = (req.body.code  || '').trim();

  if (!email || !code) {
    return res.status(400).json({ error: 'Email and code are required.' });
  }

  const record = otpStore.get(email);

  if (!record) {
    return res.status(401).json({ error: 'No active code for this email. Request a new one.' });
  }

  if (record.lockedUntil && Date.now() < record.lockedUntil) {
    const mins = Math.ceil((record.lockedUntil - Date.now()) / 60_000);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${mins} minute(s).` });
  }

  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);
    return res.status(401).json({ error: 'Code expired. Request a new one.' });
  }

  record.attempts += 1;

  if (!safeEqual(record.code, code)) {
    if (record.attempts >= OTP_MAX_ATTEMPTS) {
      record.lockedUntil = Date.now() + OTP_LOCKOUT_MS;
      record.code = '';
      return res.status(429).json({ error: 'Too many failed attempts. Account locked for 15 minutes.' });
    }
    const remaining = OTP_MAX_ATTEMPTS - record.attempts;
    return res.status(401).json({ error: `Invalid code. ${remaining} attempt(s) remaining.` });
  }

  otpStore.delete(email);

  const token = jwt.sign(
    { email, iat: Math.floor(Date.now() / 1000) },
    process.env.JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );

  res.json({ ok: true, token });
});

module.exports = router;
