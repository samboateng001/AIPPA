AI-Powered Phishing Investigation Assistant
Purpose

Accelerate triage, analysis, and response for reported and detected phishing. The assistant automates the repetitive extraction-and-enrichment work so the analyst spends time on judgment, not copy-paste.

Scope

Defensive only: intake → parse → enrich → analyze → verdict → respond → document. No content generation, no offensive capability.

Stage 1 — Intake

Sources the assistant pulls from:

A user-report mailbox (e.g. phishing@yourco.com) and the “Report Phish” button feed.
SOAR/SIEM alerts for flagged mail.
Analyst manual submission of a .eml/.msg sample.

Preserve the original message — pull the raw .eml/.msg with full headers, not a forwarded copy. Forwarding strips the headers you need. Store each case with a unique ID and keep the original artifact immutable.

Stage 2 — Parsing & extraction

Deterministic parsing (do this with code, not the LLM — you want reliable IOCs):

Headers: Received chain, Return-Path, Reply-To vs From mismatch, Message-ID, originating IP.
Authentication: SPF, DKIM, DMARC results from Authentication-Results.
Body: URLs (defanged), display-text vs actual href mismatches, embedded images, tracking pixels.
Attachments: filenames, file types, hashes (SHA-256), macro presence.
Indicators (IOCs): sender domains/IPs, URLs, domains, file hashes.

Libraries that do this well: Python mailparser/email, eml_parser, oletools (for Office macros), tldextract.

Stage 3 — Enrichment

For each extracted IOC, query reputation/intel sources (via API, cached to avoid rate limits):

URLs/domains: VirusTotal, urlscan.io, domain age/WHOIS, reputation feeds.
IPs: AbuseIPDB, GreyNoise, geolocation, ASN.
Hashes: VirusTotal, your EDR/sandbox.
Detonation: submit suspicious URLs/attachments to a sandbox (Cuckoo, Joe Sandbox, or your vendor’s) — in an isolated environment, never on a live host.
Internal context: has anyone else received this? Did anyone click? Query mail logs and proxy/DNS logs for the sender, subject, and URLs across the org.
Stage 4 — AI-assisted analysis

This is where the LLM earns its place — on interpretation, with the structured data from Stages 2–3 as input:

Summarize the message and the enrichment findings into a plain-language case brief.
Classify likely type: credential harvesting, BEC, malware delivery, benign/marketing false positive.
Score social-engineering signals: urgency, authority impersonation, lookalike domains, brand spoofing.
Map to MITRE ATT&CK (e.g. T1566 Phishing and sub-techniques) for consistent reporting.
Recommend a verdict and next actions, with its reasoning shown.

Keep the human in the loop: the AI proposes, the analyst decides. Log the model’s rationale so verdicts are auditable. Don’t let the model auto-execute containment.

Stage 5 — Verdict & response

Analyst confirms the verdict, then the assistant helps trigger (with approval) via SOAR:

Containment: quarantine/purge the message org-wide (e.g. Microsoft 365 purge, Google Workspace investigation), block sender/domain/URL at the gateway and proxy.
Credential risk: if anyone clicked and submitted, force password reset and session revocation for affected users; check for inbox rules/forwarding added by an attacker.
Notify: affected users and, per policy, broader awareness if it’s a campaign.

Every automated action should be gated behind analyst approval and fully logged.

Stage 6 — Documentation & learning
Auto-generate the case report: timeline, IOCs, verdict, actions taken, analyst notes.
Push confirmed IOCs to your threat-intel platform (MISP/TIP) and detection rules.
Track metrics: time-to-triage, time-to-containment, false-positive rate, repeat-sender campaigns.
Feed confirmed phish into user-awareness training.
Reference architecture
Report mailbox / SIEM / manual
            │
       [Intake service]  → case store (immutable original)
            │
    [Parser]  ── deterministic IOC extraction
            │
   [Enrichment]  ── VT, urlscan, AbuseIPDB, sandbox, internal logs  (cached)
            │
  [AI analysis layer]  ── LLM: summarize, classify, score, ATT&CK map
            │
   [Analyst review]  ← human-in-the-loop verdict
            │
    [SOAR response]  ── quarantine, block, reset (approval-gated)
            │
  [Reporting + TIP + metrics]
Suggested stack
Orchestration: Python service or n8n/Tines/Shuffle; SOAR (Splunk SOAR, Cortex XSOAR, or open-source Shuffle).
Parsing: eml_parser, oletools, tldextract.
Enrichment: VirusTotal, urlscan.io, AbuseIPDB, GreyNoise APIs; a sandbox.
LLM layer: an API model or a locally hosted one if mail content can’t leave your environment (often the deciding factor for IR data).
Case management: TheHive + Cortex is a strong open-source pairing (TheHive for cases, Cortex for enrichment analyzers); or your existing ticketing/SOAR.
Key design principles
Deterministic for IOCs, AI for interpretation. Don’t ask the LLM to extract hashes; do ask it to explain what they mean.
Human-in-the-loop for anything destructive. Purge, block, and reset stay approval-gated.
Data handling: mail content is sensitive. Decide early whether it can go to an external API or must stay in a local model. Redact PII where you can.
Auditability: log every enrichment call, model output, and action taken.
Guard against prompt injection: phishing bodies are attacker-controlled text. Treat message content as untrusted data in your prompts, not as instructions — wrap it clearly and never let it drive tool execution.
