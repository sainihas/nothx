<img width="2218" height="1440" alt="38 copy" src="https://github.com/user-attachments/assets/8f24f539-2382-4931-8ff6-9a9237380843" />





# nothx

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Status: Beta](https://img.shields.io/badge/status-beta-yellow.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)
![Privacy](https://img.shields.io/badge/privacy-local%20mailbox%20processing-success.svg)

nothx (no thanks) separates legitimate subscriptions from spam and phishing, then takes the safe action: unsubscribe from authenticated lists or suppress dangerous mail in Junk without contacting its sender. Mailbox access and body inspection stay on your machine. If you enable a cloud AI provider, only a bounded summary of locally selected marketing/spam headers is sent for preference classification—never message bodies or unrelated personal mail.

Your inbox, uncrowded.

---

## Quick Start

```bash
pipx install nothx
nothx init
```

That's it. The wizard handles everything else.

> Don't have pipx? `brew install pipx` (macOS) or `sudo apt install pipx` (Linux).
>
> Run `nothx` anytime for the interactive menu.

---

## Why nothx?

| The Problem | How nothx fixes it |
|-------------|-------------------|
| Mailbox-cleanup services require inbox access | IMAP scanning and state remain on your machine |
| Most tools treat all unwanted mail alike | Safe subscriptions are unsubscribed; spam/phishing is never contacted |
| Manual unsubscribing is tedious | AI classifies hundreds of senders in seconds |
| One-size-fits-all rules | **Learns your preferences** over time |
| Yet another app to run | Uses native OS scheduling (launchd/systemd) |
| What if AI gets it wrong? | Correct future local policy and teach the classifier |

---

## Features

### Core
- **AI-Powered** — Claude, GPT, Gemini, or local models via Ollama
- **Authenticated Unsubscribe** — strict RFC 8058 one-click, vetted HTTPS GET, or constrained mailto
- **Real Spam Suppression** — consumes provider Junk/phishing verdicts and safely moves exact IMAP UIDs to the discovered Junk mailbox
- **Privacy First** — header-only by default; the optional footer scanner is local, bounded, and never sends footer content to AI

### Smart
- **Learns From You** — Gets smarter every time you disagree with a decision
- **5-Layer Classification** — Rules → Patterns → AI → Heuristics → Manual review
- **Guarded Automation** — unknown authentication, conflicting verdicts, and protected identities go to review

### Practical
- **Multi-Account** — Scan Gmail + Outlook simultaneously
- **Native Scheduling** — No daemon needed. Uses launchd (macOS) or systemd (Linux).
- **Future Policy Corrections** — `nothx undo domain.com` changes nothx's future decision; it cannot externally resubscribe you

### Beautiful
- **Rich CLI** — Animated banner, progress bars, colored output
- **Interactive Mode** — Just run `nothx` for menu-driven operation

---

## The Learning System

nothx gets smarter the more you use it. Every decision trains your personal preference model.

**What it learns:**
- **Keywords** — Keep emails with "receipt"? Future receipt-related senders score safer.
- **Open rates** — If you keep emails you never open, it stops penalizing low engagement.
- **Volume tolerance** — Keep high-volume senders? It raises the threshold before flagging.

**Corrections teach it too.** When you run `nothx undo`, it doesn't just restore — it learns that this type of email matters to you.

```bash
nothx status --learning   # See your learned preferences
```

---

## How It Works

```
Email arrives in Inbox or Junk
      ↓
┌─────────────────┐
│ PROVIDER POLICY │  Junk, phishing, authentication, mailbox flags
└────────┬────────┘
         ↓
┌─────────────────┐
│  USER RULES     │  Your exact keep, unsubscribe, and block choices
└────────┬────────┘
         ↓
┌─────────────────┐
│ LOCAL CANDIDATE │  List/bulk, engagement, and cold-outreach evidence
└────────┬────────┘
         ↓
┌─────────────────┐
│ AI / HEURISTICS │  Preference classification for selected candidates
└────────┬────────┘
         ↓
┌─────────────────┐
│ SAFE DISPOSITION│  Keep, review, unsubscribe, or move to Junk
└─────────────────┘
```

Provider threat evidence and explicit block rules are resolved before AI. Bulk mail is not automatically spam, and an unsubscribe link is not automatically safe.

---

## Commands

### Essentials

| Command | What it does |
|---------|--------------|
| `nothx` | Interactive menu |
| `nothx init` | Setup wizard — accounts, API key, first scan |
| `nothx run` | Scan and process emails |
| `nothx status` | Stats, accounts, schedule at a glance |
| `nothx review` | Decide on uncertain senders |

### Day-to-Day

| Command | What it does |
|---------|--------------|
| `nothx senders` | List all tracked senders |
| `nothx search <pattern>` | Find a specific sender |
| `nothx undo [domain]` | Change future local policy (does not resubscribe) |
| `nothx history` | View grouped, redacted operation history |
| `nothx export` | Export data to CSV |

### Configuration

| Command | What it does |
|---------|--------------|
| `nothx rule "pattern" keep/unsub/block` | Add a classification rule |
| `nothx rules` | List all classification rules |
| `nothx schedule --daily` | Set the recommended automatic run frequency |
| `nothx account add/remove` | Manage email accounts |
| `nothx config --show` | View current config |
| `nothx consent` | Explicitly grant or revoke versioned network/mailbox automation consent |
| `nothx run --full-history` | Explicitly scan all UIDs instead of the incremental cursor |
| `nothx run --rescan` | Repeat the configured lookback without rewinding the cursor |
| `nothx update` | Check for and install updates |
| `nothx completion` | Generate shell completion |

**Aliases:** `r` (run), `s` (status), `rv` (review), `h` (history)

---

## Setup

### Requirements
- Python 3.11+
- Gmail, Outlook, Yahoo, or iCloud account
- AI provider *(optional — works without AI too)*

### Installation

[pipx](https://pipx.pypa.io) is the recommended way to install nothx. It handles virtual environments automatically.

```bash
# Base install (heuristics only, or Ollama)
pipx install nothx

# With your preferred AI provider
pipx install "nothx[anthropic]"  # Claude (recommended)
pipx install "nothx[openai]"     # GPT-4
pipx install "nothx[gemini]"     # Google Gemini
pipx install "nothx[all-ai]"     # All providers
```

<details>
<summary><strong>Don't have pipx?</strong></summary>

**macOS:**
```bash
brew install pipx
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt install pipx

# Fedora
sudo dnf install pipx
```

pipx requires Python 3.11+. After installing, verify with `python3 --version`.
</details>

<details>
<summary><strong>Using pip instead</strong></summary>

If you prefer pip, use a virtual environment to avoid system conflicts:

```bash
python3 -m venv ~/.nothx-venv
source ~/.nothx-venv/bin/activate
pip install nothx
```

</details>

<details>
<summary><strong>Gmail App Password</strong></summary>

1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Generate a new password for "nothx"
3. Copy the 16-character code

*Requires 2FA enabled on your account.*
</details>

<details>
<summary><strong>Outlook / Live / Hotmail OAuth</strong></summary>

Microsoft personal accounts no longer accept basic authentication or app
passwords for IMAP. nothx uses OAuth2 device sign-in instead; it never needs
your Microsoft password.

1. In [Azure App registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade), create a public-client app that supports **Personal Microsoft accounts only**.
2. Under **Authentication**, enable **Allow public client flows**. No client secret or redirect URI is needed.
3. Copy the **Application (client) ID** and provide it when `nothx init` or `nothx account add` asks for it.
4. Open the displayed Microsoft device-login URL, enter its short code, and approve IMAP and SMTP access.

The access and refresh tokens are stored separately in
`~/.nothx/tokens.json` with owner-only permissions. If an older token granted
IMAP but not SMTP, nothx asks you to sign in once more before it sends an
unsubscribe email.
</details>

<details>
<summary><strong>AI Provider Setup</strong></summary>

**Anthropic (Claude)** — Best for email classification. [Get API key](https://console.anthropic.com)

**OpenAI (GPT)** — GPT-4o models. [Get API key](https://platform.openai.com/api-keys)

**Google (Gemini)** — Free tier available. [Get API key](https://aistudio.google.com/apikey)

**Ollama (Local)** — Run models locally. No API key needed. [Install Ollama](https://ollama.ai)

*Without AI, nothx uses heuristic scoring. Still works, just less smart.*
</details>

### Safety and privacy defaults

- Inbox and the unambiguously advertised IMAP `\Junk` mailbox are scanned. nothx does not guess localized Junk folder names; configure an override if your server advertises none or several.
- Initial runs use the configured lookback. Later runs use `(account, mailbox, UIDVALIDITY, UID)` cursors. Full history is always explicit.
- Body fetching is disabled by default. The optional footer scanner examines at most two inline text tails (64 KiB each, 128 KiB total) for authenticated list/bulk candidates. It skips attachments, nested messages, images, scripts, and forms.
- One-click POST requires compliant headers plus `$canunsubscribe` or a correlated passing DKIM signature that covers both unsubscribe headers. All outbound unsubscribe contact—including an explicitly opened browser page—and mailbox actions require separate, versioned consent.
- HTTP requests are HTTPS-only, proxy/cookie/auth/referrer-free, redirect constrained, SSRF checked, and connected to an already validated public IP while preserving TLS hostname verification.
- Stored targets are fingerprints and hashed destination labels. Complete hosts, paths, queries, mailto recipients/bodies, and HTTP response bodies are excluded from normal history and exports.

### What an outcome means

- `requested`: the endpoint accepted a one-click/GET request, or SMTP accepted the mail for delivery. It does **not** guarantee mail will stop.
- `needs_user`: safe automation reached a login, form, JavaScript flow, preference center, CAPTCHA, or another manual boundary.
- `verified_quiet`: a complete post-grace scan found no later matching delivery.
- `ineffective`: matching mail arrived after the 48-hour grace period. One fresh-token or alternate-method retry is allowed; another post-grace delivery is blocked.
- `blocked`: nothx sent no unsubscribe traffic and applied its local spam path. Portable IMAP Junk movement is best effort; provider-side spam training is not guaranteed.

---

## Troubleshooting

<details>
<summary><strong>Connection failed</strong></summary>

- Verify your App Password (not your regular password)
- Ensure IMAP is enabled in your email settings
- For Gmail: Check that 2FA is enabled (required for App Passwords)
- For Outlook/Live/Hotmail: re-add the account to renew OAuth consent; app passwords do not work
- Run `nothx test` to diagnose
</details>

<details>
<summary><strong>AI classification not working</strong></summary>

- Check your API key: `nothx config --show`
- Verify you have credits/quota with your chosen provider (Anthropic, OpenAI, or Google)
- nothx falls back to heuristics if AI fails — it still works
</details>

<details>
<summary><strong>Still getting emails after unsubscribe</strong></summary>

- Some senders ignore unsubscribe requests (bad actors)
- Daily runs verify accepted requests after 48 hours and escalate repeat offenders to Junk
- Add manually: `nothx rule "domain.com" block`
</details>

<details>
<summary><strong>Start fresh</strong></summary>

```bash
nothx reset              # Delete everything
nothx reset --keep-config # Keep accounts, clear history
```
</details>

---

## Comparison

| Feature | Unroll.me | SaneBox | Leave Me Alone | **nothx** |
|---------|-----------|---------|----------------|-----------|
| Price | Free | $84-432/yr | $48/yr | **Free** |
| Mailbox processing | Cloud | Cloud | Cloud | **Local** |
| Actually unsubscribes | No | Yes | Yes | **Yes** |
| AI classification | No | Yes | Basic | **Yes (multi-provider)** |
| Learns your preferences | No | Limited | No | **Yes** |
| Local AI option | No | No | No | **Yes (Ollama)** |
| Open source | No | No | No | **Yes** |

---

## Philosophy

We built nothx because:

1. **Your email is yours.** Not a product to sell.
2. **AI should adapt to you.** Not the other way around.
3. **Automation should be invisible.** Set once, forget forever.
4. **Words matter.** A request is not verified cessation, and changing local policy cannot externally resubscribe an address.

---

## Contributing

```bash
git clone https://github.com/sainihas/nothx.git
cd nothx
pip install -e ".[dev]"
pytest
```

---

## License

MIT — see [LICENSE](LICENSE)

---

**nothx** — Because your inbox should work for you, not against you.

*Made with mass frustration at marketing emails.*
