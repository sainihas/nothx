<img width="2218" height="1440" alt="nothx" src="https://github.com/user-attachments/assets/36c92fe2-94f6-4a35-80ba-e283f54be78a" />



# nothx

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Status: Beta](https://img.shields.io/badge/status-beta-yellow.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)
![Privacy](https://img.shields.io/badge/privacy-100%25%20local-success.svg)

nothx (no thanks) hunts down marketing emails, uses AI to sort the noise from the signal, and actually clicks unsubscribe for you. It runs on your machine, learns your preferences, and never touches your data.

Inbox zero, effort zero.

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
| Unroll.me sells your data | 100% local — your data never leaves home |
| Most tools just filter emails | Actually clicks unsubscribe links |
| Manual unsubscribing is tedious | AI classifies hundreds of senders in seconds |
| One-size-fits-all rules | **Learns your preferences** over time |
| Yet another app to run | Uses native OS scheduling (launchd/systemd) |
| What if AI gets it wrong? | Undo anything — and it learns from the correction |

---

## Features

### Core
- **AI-Powered** — Claude, GPT, Gemini, or local models via Ollama
- **Actually Unsubscribes** — RFC 8058 one-click, GET requests, or mailto
- **Privacy First** — Never reads email bodies. Only headers. All data stays local.

### Smart
- **Learns From You** — Gets smarter every time you disagree with a decision
- **5-Layer Classification** — Rules → Patterns → AI → Heuristics → Manual review
- **Protected Categories** — Banks, government, healthcare never auto-unsubscribed

### Practical
- **Multi-Account** — Scan Gmail + Outlook simultaneously
- **Native Scheduling** — No daemon needed. Uses launchd (macOS) or systemd (Linux).
- **Undo Anything** — Changed your mind? `nothx undo domain.com`

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
Email arrives
      ↓
┌─────────────────┐
│  USER RULES     │  Your explicit keep/unsub patterns
└────────┬────────┘
         ↓
┌─────────────────┐
│  PATTERNS       │  Known marketing domains, safe categories
└────────┬────────┘
         ↓
┌─────────────────┐
│  AI ANALYSIS    │  AI examines headers (never bodies)
└────────┬────────┘
         ↓
┌─────────────────┐
│  HEURISTICS     │  Open rates, frequency, spam patterns
└────────┬────────┘
         ↓
┌─────────────────┐
│  REVIEW QUEUE   │  Uncertain? You decide.
└─────────────────┘
```

Each layer can make a final call or pass to the next. Your rules always win.

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
| `nothx undo [domain]` | Undo an unsubscribe |
| `nothx history` | View activity log |
| `nothx export` | Export data to CSV |

### Configuration

| Command | What it does |
|---------|--------------|
| `nothx rule "pattern" keep/unsub` | Add a classification rule |
| `nothx rules` | List all classification rules |
| `nothx schedule --monthly` | Set automatic run frequency |
| `nothx account add/remove` | Manage email accounts |
| `nothx config --show` | View current config |
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
<summary><strong>Outlook App Password</strong></summary>

1. Go to [account.live.com/proofs/AppPassword](https://account.live.com/proofs/AppPassword)
2. Enable 2FA if not already
3. Generate and copy the app password
</details>

<details>
<summary><strong>AI Provider Setup</strong></summary>

**Anthropic (Claude)** — Best for email classification. [Get API key](https://console.anthropic.com)

**OpenAI (GPT)** — GPT-4o models. [Get API key](https://platform.openai.com/api-keys)

**Google (Gemini)** — Free tier available. [Get API key](https://aistudio.google.com/apikey)

**Ollama (Local)** — Run models locally. No API key needed. [Install Ollama](https://ollama.ai)

*Without AI, nothx uses heuristic scoring. Still works, just less smart.*
</details>

---

## Troubleshooting

<details>
<summary><strong>Connection failed</strong></summary>

- Verify your App Password (not your regular password)
- Ensure IMAP is enabled in your email settings
- For Gmail: Check that 2FA is enabled (required for App Passwords)
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
- Run `nothx run` again — it escalates repeat offenders to blocking
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
| Privacy | Sells data | Cloud | Cloud | **100% local** |
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
4. **You can always change your mind.** Every action is reversible.

---

## Contributing

```bash
git clone https://github.com/nothx/nothx.git
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
