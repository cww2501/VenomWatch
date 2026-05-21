'use strict';

require('dotenv').config();

const express = require('express');
const helmet  = require('helmet');
const cors    = require('cors');
const { rateLimit } = require('express-rate-limit');

const authRoutes   = require('./routes/auth');
const assessRoutes = require('./routes/assess');

const app = express();

// Security headers
app.use(helmet());

// CORS — locked to GitHub Pages origin
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Body parsing
app.use(express.json({ limit: '16kb' }));

// Global rate limit — coarse ceiling before per-route limits kick in
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests. Slow down.' },
}));

// Routes
app.use('/auth',   authRoutes);
app.use('/assess', assessRoutes);

// Health check
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// 404 catch-all
app.use((_req, res) => res.status(404).json({ error: 'Not found.' }));

const PORT = parseInt(process.env.PORT || '3000', 10);
app.listen(PORT, () => {
  console.log(`VenomWatch backend listening on port ${PORT}`);
  console.log(`CORS origin: ${process.env.ALLOWED_ORIGIN}`);
});
