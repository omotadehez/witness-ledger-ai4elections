# Distributed Witness Ledger

**#AI4Elections Hackathon 2026 | Track: Electoral Cybersecurity and Resilience**
Team: Quantum Pioneers 

Members: Omotade Hezekiah Adeniyi, Bolajoko Aliyat Morenikeji, Osigbemhe Nathan Oluwaseyi

> **Synthetic data only.** This prototype is not connected to any electoral system, never uses real election data, and never declares or validates election results. Every mismatch is referred to human review.

## The problem

After a result is published, citizens and independent parties cannot easily check it without trusting a single institution. When uploads stall or are disputed, trust suffers, and there is no simple public way to confirm that a published result was not changed after upload.

## What this does

A witness-based verification layer that **complements** the signed paper result sheet (Form EC8A) and electronic upload. It does not replace them.

1. **Public integrity ledger.** Each published polling-unit result is hashed into a Merkle tree. Anyone can check a single result against the published root.
2. **Witness quorum.** Independent witnesses (the design assumes party agents who lawfully receive copies of the result sheet) each submit their own hash of the transcribed figures. A result is shown as matching only when a quorum, drawn from several different groups, agrees.
3. **Offline-first.** Late submissions catch up round by round. Outages cause delay and human review, never a false pass.
4. **AI layer.** An anomaly-detection model learns normal witness behaviour from a trusted rehearsal and flags copy-like or unusual witnesses, who can then be revoked pending human review. Its outputs are advisory.
5. **Sealed submissions.** Witnesses commit their hash before the published result is visible, so there is nothing to copy.
6. **Public verifier page.** A browser page where anyone can look up a polling unit, see witness agreement and the proof check. Available in English, Hausa, Yorùbá, Igbo and Nigerian Pidgin, with high-contrast and larger-text options.

## Files

| File | Purpose |
|---|---|
| `witness_ledger_v4.py` | Simulator, ledger, quorum logic, AI layer, and adversarial tests |
| `result_verifier_i18n.html` | Public verifier page (self-contained, runs in the browser) |

## How to run

**Python prototype (easiest: Google Colab)**
1. Open colab.research.google.com and create a new notebook.
2. Paste the contents of `witness_ledger_v4.py` into a cell and press play.
3. Results print below the cell. Sections A to E are the adversarial tests.

To change settings, put this at the top of the cell:
```python
import sys; sys.argv = ["x", "--pus", "1000", "--witnesses", "9", "--k", "5"]
```

**Verifier page:** open `result_verifier_i18n.html` in any browser, or visit the live page: [LIVE PAGE LINK]

## What the tests show (reproduce by running the script)

- **Collusion:** tampering is caught unless an attacker controls a quorum of witnesses. With a 4-of-7 quorum, the plain rule breaks at 4 colluders. Requiring agreement across at least 3 groups raises that bar.
- **Outages:** a regional outage leaves units pending and sends them to manual review. Tampered units are never marked as matching.
- **Forgery:** a forged signature without the key is rejected.
- **AI layer:** copy-style colluders are flagged and revoked, and units then go to human review instead of passing silently.
- **Sealed submissions:** an attacker must pre-agree every alteration with colluders before the commit deadline.

## Known limits

- It shows whether a published result changed after upload and whether independent witnesses agree. It **cannot prove the figures were right at the polling unit**.
- Attackers who control a quorum of witnesses across several independent groups defeat the quorum.
- Attackers who imitate honest witness behaviour evade the AI layer. Sealed submissions and richer real-world behaviour data are the intended defences.
- The AI layer is validated on simulated behaviour only and needs real rehearsal data.
- Signature checks run in the Python prototype, not in the browser page.
- Translations on the page are drafts and need native-speaker review.

## Legal and data assumptions

- Party agents lawfully receive copies of the signed result sheet. Whether accredited observers may hold or photograph a copy is **unconfirmed** and is not assumed.
- Witnesses submit only a hash of the figures, never images or personal data.
- Only synthetic data is used. No access to INEC systems or restricted data is needed or attempted.
- This is not legal advice. These assumptions should be confirmed with INEC or a legal expert.

## Responsible AI

Human oversight on every decision. No automated action. The system never decides election outcomes, electoral validity or legal matters.

## AI assistance disclosure

This project was developed with the assistance of Claude (Anthropic), an AI model, for code, design and drafting. The team reviewed and takes responsibility for the submission.

## Eligibility statement

This is an original working prototype built for this hackathon. It has not received any grant, award or recognition in any other competition.
