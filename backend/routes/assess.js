'use strict';

const express = require('express');
const jwt = require('jsonwebtoken');
const Anthropic = require('@anthropic-ai/sdk');
const { rateLimit } = require('express-rate-limit');

const router = express.Router();
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// 10 assessments per hour, per IP
const assessLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Assessment limit reached (10/hr). Try again later.' },
});

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing authorization token.' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired session. Please log in again.' });
  }
}

function sanitizeProduct(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/[<>"'`]/g, '').trim().slice(0, 120);
}

const PHASE_SCHEMAS = {
  1: {
    name: 'Intake & Classification',
    prompt: (product) => `You are a senior AI security assessor performing a structured intake assessment under the NIST AI RMF 1.0 framework.

Product under review: "${product}"

Provide a structured intake assessment with these sections:
1. Product Classification (type, vendor, deployment model)
2. Primary Use Cases (top 3–5 identified)
3. Data Categories Involved (PII, PHI, financial, behavioral, etc.)
4. Integration Points (APIs, third-party services, data flows)
5. Initial Risk Tier (Low/Medium/High/Critical with rationale)

Respond in valid JSON matching this schema:
{
  "classification": { "type": string, "vendor": string, "deployment": string },
  "use_cases": [string],
  "data_categories": [string],
  "integration_points": [string],
  "risk_tier": { "level": "Low"|"Medium"|"High"|"Critical", "rationale": string },
  "summary": string
}`,
  },
  2: {
    name: 'Vulnerability Analysis',
    prompt: (product) => `You are a senior AI security assessor performing a vulnerability analysis under the NIST AI RMF 1.0 framework.

Product under review: "${product}"

Identify the top vulnerabilities and attack vectors for this AI product. For each vulnerability, assess severity and recommend mitigations.

Respond in valid JSON:
{
  "vulnerabilities": [
    {
      "id": string,
      "name": string,
      "severity": "Critical"|"High"|"Medium"|"Low",
      "description": string,
      "attack_vector": string,
      "mitigation": string
    }
  ],
  "overall_exposure": "Critical"|"High"|"Medium"|"Low",
  "priority_actions": [string]
}`,
  },
  3: {
    name: 'Breach & Incident Scenarios',
    prompt: (product) => `You are a senior AI security assessor performing breach scenario analysis under the NIST AI RMF 1.0 framework.

Product under review: "${product}"

Identify the top realistic breach scenarios, their potential business impact, and recommended incident response steps.

Respond in valid JSON:
{
  "breach_scenarios": [
    {
      "scenario": string,
      "likelihood": "High"|"Medium"|"Low",
      "impact": "Critical"|"High"|"Medium"|"Low",
      "affected_assets": [string],
      "response_steps": [string]
    }
  ],
  "estimated_blast_radius": string,
  "detection_gaps": [string]
}`,
  },
  4: {
    name: 'Privacy & Compliance',
    prompt: (product) => `You are a senior AI security assessor performing a privacy and compliance assessment under the NIST AI RMF 1.0 framework.

Product under review: "${product}"

Assess the privacy risks and regulatory compliance considerations for this AI product.

Respond in valid JSON:
{
  "applicable_regulations": [string],
  "privacy_risks": [
    {
      "risk": string,
      "severity": "Critical"|"High"|"Medium"|"Low",
      "regulation": string,
      "recommendation": string
    }
  ],
  "data_retention_concerns": [string],
  "consent_gaps": [string],
  "compliance_score": { "overall": "Pass"|"Conditional"|"Fail", "notes": string }
}`,
  },
  5: {
    name: 'AI-Specific Risk',
    prompt: (product) => `You are a senior AI security assessor performing an AI-specific risk assessment under the NIST AI RMF 1.0 framework (Govern, Map, Measure, Manage functions).

Product under review: "${product}"

Assess AI-specific risks including model integrity, bias, hallucination, adversarial robustness, and explainability.

Respond in valid JSON:
{
  "ai_risks": [
    {
      "category": string,
      "risk": string,
      "nist_function": "GOVERN"|"MAP"|"MEASURE"|"MANAGE",
      "severity": "Critical"|"High"|"Medium"|"Low",
      "mitigation": string
    }
  ],
  "model_integrity_score": "Strong"|"Moderate"|"Weak",
  "explainability_gap": string,
  "bias_exposure": string,
  "adversarial_hardening": string
}`,
  },
  6: {
    name: 'Supply Chain Risk',
    prompt: (product) => `You are a senior AI security assessor performing a supply chain risk assessment under the NIST AI RMF 1.0 framework.

Product under review: "${product}"

Assess supply chain risks including third-party model dependencies, data provenance, and vendor trust.

Respond in valid JSON:
{
  "supply_chain_risks": [
    {
      "component": string,
      "risk": string,
      "severity": "Critical"|"High"|"Medium"|"Low",
      "mitigation": string
    }
  ],
  "vendor_trust_score": "High"|"Medium"|"Low",
  "model_provenance_gaps": [string],
  "recommended_controls": [string]
}`,
  },
  7: {
    name: 'Executive Report',
    prompt: (product) => `You are a senior AI security assessor producing an executive summary report under the NIST AI RMF 1.0 framework.

Product under review: "${product}"

Produce a concise, actionable executive summary suitable for CISO and board-level review.

Respond in valid JSON:
{
  "executive_summary": string,
  "overall_risk_rating": "Critical"|"High"|"Medium"|"Low",
  "top_findings": [{ "finding": string, "severity": "Critical"|"High"|"Medium"|"Low" }],
  "recommended_actions": [{ "action": string, "priority": "Immediate"|"Short-term"|"Long-term", "owner": string }],
  "nist_rmf_alignment": { "govern": string, "map": string, "measure": string, "manage": string },
  "approval_recommendation": "Approve"|"Conditional Approve"|"Do Not Approve",
  "approval_rationale": string
}`,
  },
};

// POST /assess
router.post('/', requireAuth, assessLimiter, async (req, res) => {
  const product = sanitizeProduct(req.body.product);
  const phaseId = parseInt(req.body.phaseId, 10);

  if (!product) {
    return res.status(400).json({ error: 'Product name is required.' });
  }
  if (!PHASE_SCHEMAS[phaseId]) {
    return res.status(400).json({ error: `Unknown phase: ${phaseId}` });
  }

  const phase = PHASE_SCHEMAS[phaseId];

  try {
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 2048,
      output_config: { effort: 'high' },
      messages: [{ role: 'user', content: phase.prompt(product) }],
    });

    const text = message.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('');

    let parsed;
    try {
      const match = text.match(/\{[\s\S]*\}/);
      parsed = JSON.parse(match ? match[0] : text);
    } catch {
      return res.status(502).json({ error: 'Model returned non-JSON response.', raw: text });
    }

    res.json({ ok: true, phase: phaseId, name: phase.name, data: parsed });
  } catch (err) {
    if (err instanceof Anthropic.APIError) {
      console.error(`Anthropic API error ${err.status}:`, err.message);
      return res.status(502).json({ error: `Upstream AI error: ${err.message}` });
    }
    console.error('Assessment error:', err?.message);
    res.status(500).json({ error: 'Assessment failed. Please try again.' });
  }
});

module.exports = router;
