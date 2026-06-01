# Phishing Awareness Guide for Employees

> **A practical, no-nonsense guide to recognizing and responding to phishing emails.**  
> No jargon. No condescension. Just clear signals and clear actions.

---

## What Is Phishing?

Phishing is when someone sends you a fake email (or text, or call) pretending to be someone you trust — your bank, your IT department, your boss — to trick you into:
- Giving away your password
- Downloading malware
- Sending money or gift cards
- Revealing confidential information

It is the #1 way attackers break into organizations. The good news: phishing emails almost always have **tells** — red flags that give them away.

---

## The Red Flags Checklist

Use this checklist every time an email feels "off." You don't need to check every box — even **one or two** strong red flags means you should pause.

### 🔴 Sender Red Flags

| Signal | What to Look For |
|--------|-----------------|
| **Wrong domain** | The email claims to be from `yourcompany.com` but the actual address is `yourc0mpany.com` or `yourcompany-security.net` |
| **Display name spoof** | The sender name says "CEO James Whitfield" but the email address is `james.whitfield@gmail.com` |
| **Generic greeting** | "Dear Valued Customer" instead of your actual name |
| **Reply-to mismatch** | The "From" address looks right, but "Reply-To" goes somewhere else |

### 🔴 Content Red Flags

| Signal | What to Look For |
|--------|-----------------|
| **Urgency and threats** | "Your account will be locked in 2 hours," "Legal action will be taken," "Your personnel file will be flagged" |
| **Too good to be true** | "You won a gift card," "Unexpected refund" |
| **Confidentiality pressure** | "Do not tell your manager," "This is between us," "Handle this quietly" |
| **Grammatical errors** | Unusual phrasing, awkward sentences, misspellings (attackers often work in non-native languages) |
| **Vague references** | "Your recent order" without saying what you ordered, "Invoice #4421" without context |

### 🔴 Link & Attachment Red Flags

| Signal | What to Look For |
|--------|-----------------|
| **Hover before clicking** | Hover over any link. Does the URL match what the text says? `https://bankofamerica.com` vs. `https://b4nkofamerica.secure-login.io` |
| **Shortened URLs** | `bit.ly`, `t.co`, `tinyurl` — legitimate companies rarely use these in security emails |
| **IP-based URLs** | `http://192.168.1.105/login` — real companies use domain names, not raw IP addresses |
| **Suspicious attachments** | `.exe`, `.zip`, `.js`, `.scr`, or a PDF that asks you to "Enable Macros" |
| **Double extensions** | `invoice.pdf.exe` — Windows hides the real extension |

### 🔴 Request Red Flags

| Signal | What to Look For |
|--------|-----------------|
| **Asks for your password** | **No legitimate company will ever email you a link and ask for your password.** This is the golden rule. |
| **Requests money or gift cards** | Especially with urgency: "Buy $500 in gift cards for a client meeting" |
| **Asks you to bypass process** | "Don't go through Finance," "Skip the normal approval" |
| **Unexpected wire transfer** | A CEO asking you to wire money to a new account — verify by voice |

---

## What to Do If You Suspect Phishing

### Step 1: Stop. Do Not Click.

Your first instinct may be to panic and act fast. **Phishing relies on this.** Take a breath. The real IT department will not penalize you for taking 5 minutes to verify.

### Step 2: Verify Through a Different Channel

| If the email claims to be from... | Verify by... |
|-----------------------------------|-------------|
| Your IT department | Calling the IT help desk (use the number from your employee directory, NOT from the email) |
| Your bank | Logging into your bank account directly by typing the URL (don't use the email link) or calling the number on your card |
| Your CEO / manager | Calling them, messaging them on Teams/Slack, or walking to their office |
| A vendor | Logging into the vendor portal directly or calling your known contact |

**Never use contact information from a suspicious email.**

### Step 3: Report It

Forward the suspicious email to your security team:
- **Your organization's phishing inbox** (usually `phishing@yourcompany.com` or `security@yourcompany.com`)
- If you don't know the address, ask IT once — then you'll know forever

Reporting helps your security team:
- Block the attack for others
- Update filters to catch similar emails
- Investigate whether anyone else fell for it

**You will not get in trouble for reporting a phishing email — even if you already clicked.** Security teams need to know ASAP so they can contain any damage.

### Step 4: If You Already Clicked

1. **Disconnect from the internet** (unplug ethernet or turn off Wi-Fi) — this stops malware from spreading
2. **Call IT/Security immediately** — speed matters
3. **Do not enter credentials** if a fake login page opened
4. **Change your password** from a known-clean device
5. **Monitor your accounts** for unusual activity

---

## Special Scenarios

### The "CEO Fraud" Email

You get an email from your CEO asking you to wire money or buy gift cards urgently. The tone is casual — "I'm in a meeting, can't talk."

**Reality check:** Real CEOs do not send wire instructions over email. A 30-second phone call or Slack message will verify this instantly. The scammer is counting on your reluctance to question authority.

### The "IT Security Alert" Email

An email says there's a critical vulnerability and you must click a link to patch your computer immediately.

**Reality check:** Real IT departments push patches through management tools (Intune, Jamf, SCCM) — they do not ask you to click a link and run an installer. If you're unsure, call IT. They will thank you.

### The "HIPAA / Compliance" Email

An email threatens compliance action if you don't click a link to verify your credentials.

**Reality check:** Compliance teams send official notices through your HR portal or registered mail — not urgent emails with countdown timers. The urgency is manufactured to bypass your judgment.

---

## Remember: You Are the First Line of Defense

Attackers can bypass firewalls, antivirus, and email filters. But they cannot bypass **you** — the person reading the email. One paused moment, one verification call, one report to security — that is often the difference between a blocked attack and a breach.

Phishing is not about intelligence. It is about **timing, pressure, and trust**. Attackers study human psychology. Your awareness is their biggest obstacle.

**When in doubt: Stop. Verify. Report.**

---

## Quick Reference Card

```
┌─────────────────────────────────────────┐
│  BEFORE YOU CLICK                       │
│                                         │
│  □ Is the sender's address suspicious?  │
│  □ Is there unnatural urgency?          │
│  □ Are there threats or penalties?      │
│  □ Does it ask for my password?         │
│  □ Does the link URL look wrong?        │
│  □ Is there an unexpected attachment?   │
│                                         │
│  IF ANY BOX IS CHECKED:                 │
│  → STOP. Do not click.                  │
│  → VERIFY via a different channel.      │
│  → REPORT to security@yourcompany.com   │
└─────────────────────────────────────────┘
```

---

*This guide is part of an authorized security awareness training program. If you received this as part of a phishing simulation exercise, thank you for your participation — your vigilance protects the entire organization.*
