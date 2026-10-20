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

The wizard configures accounts and AI. Outlook/Live/Hotmail also requires the
one-time Microsoft application setup described below.

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

Provider threat evidence and explicit block rules are resolved before AI. Mixed clean/threat or pass/fail evidence requires review; one flagged message never authorizes suppressing the whole sender group. Bulk mail is not automatically spam, and an unsubscribe link is not automatically safe.

---

## Commands

### Essentials

| Command | What it does |
|---------|--------------|
| `nothx` | Interactive menu |
| `nothx init` | Setup wizard — accounts, API key, first scan |
| `nothx run` | Recheck the recent lookback with configured AI and process eligible mail |
| `nothx cleanup` | Scan the full Inbox once, review the plan, and apply approved actions |
| `nothx cleanup --preview` | Explicit read-only preview; no mail actions |
| `nothx status` | Stats, accounts, schedule at a glance |
| `nothx review` | Decide on uncertain senders |
| `nothx test --ai` | Test mailbox connections and the configured AI provider, including disabled-provider recovery |

Cleanup review focuses on marketing/newsletters and spam. Promotional evidence is checked
across every header in the scan, including mail older than the five recent subject samples.
Personal conversations and service-only senders stay outside the cleanup picker. Mixed
service/promotional senders appear for inspection with promotional examples, while their
receipts and security notices continue to prevent group-wide suppression.
Search by full sender address,
account, mailing list, or subject; pages contain at most 20 sender groups and you can
finish review at any time. Accounts and separate mailing lists are never merged by domain.
Use `nothx cleanup --details` for candidate tables before review.


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
| `nothx config --engaged-marketing review/allow` | Review or permit automatic actions on engaged marketing |
| `nothx config --unwanted-mail keep/junk` | Keep mail in Inbox or move approved mail to Junk after request acceptance |
| `nothx consent` | Explicitly grant or revoke versioned network/mailbox automation consent |
| `nothx run --preview` | Preview recent mail with configured AI; no mail actions or saved decisions |
| `nothx run --dry-run` | Preview recent mail with local rules; no cloud AI or mail actions |
| `nothx run --new-only` | Only scan new UIDs, skipping earlier undecided messages |
| `nothx resolve ID --dry-run` | Refresh a saved subscription and preview usable sources |
| `nothx resolve ID` | Finish a selected subscription; supports simple confirmation forms |
| `nothx browser-setup` | Install the isolated browser runtime and enable JavaScript page completion |
| `nothx config --browser-fallback off` | Disable browser page completion |
| `nothx resolve ID --retry` | Explicitly allow one bounded retry of a failed/manual case |
| `nothx resolve ID --completed` | Record provider confirmation you saw in the browser |
| `nothx run --full-history` | Scan all history in Inbox and configured folders |
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

The operator must register a nothx application once. This release does not ship a
shared Microsoft application ID. After setup, accounts reuse that ID and users
only complete Microsoft sign-in. App IDs are public identifiers; no client secret
is used.

1. In [Azure App registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade), create a public-client app that supports **Personal Microsoft accounts only**.
2. Under **Authentication**, enable **Allow public client flows**. No client secret or redirect URI is needed. If you already created an organizational single-tenant app, [change its supported account types](https://learn.microsoft.com/en-us/entra/identity-platform/howto-modify-supported-accounts) to include personal Microsoft accounts; single-tenant organizational registrations cannot sign in Live/Hotmail accounts.
3. Set `NOTHX_MICROSOFT_CLIENT_ID` to the **Application (client) ID**, or provide it once when `nothx init` or `nothx account add` asks. nothx saves it for later accounts.
4. Open the displayed Microsoft device-login URL, enter its short code, and approve IMAP and SMTP access using the same personal email address entered in nothx.
5. In [Outlook web](https://outlook.live.com/mail/), open **Settings → Mail → Forwarding and IMAP**, enable **Let devices and apps use IMAP**, and save. Microsoft disables IMAP by default. If sign-in succeeds but Inbox access fails, nothx preserves the sign-in; run `nothx test` after enabling IMAP.

[Microsoft connection settings](https://support.microsoft.com/en-us/outlook/pop-imap-and-smtp-settings-for-outlook-com) document the OAuth2 requirement and IMAP switch.

The access and refresh tokens are stored separately in
`~/.nothx/tokens.json` with owner-only permissions. If an older token granted
IMAP but not SMTP, nothx asks you to sign in once more before it sends an
unsubscribe email.
</details>

<details>
<summary><strong>AI Provider Setup</strong></summary>

**Anthropic (Claude)** — Best for email classification. [Get API key](https://console.anthropic.com)

**OpenAI (GPT)** — GPT-6 models. [Get API key](https://platform.openai.com/api-keys)

**Google (Gemini)** — Free tier available. [Get API key](https://aistudio.google.com/apikey)

**Ollama (Local)** — Run models locally. No API key needed. [Install Ollama](https://ollama.ai)

*Without AI, nothx uses heuristic scoring. Still works, just less smart.*
</details>

### Safety and privacy defaults

- Inbox and the unambiguously advertised IMAP `\Junk` mailbox are scanned. nothx does not guess localized Junk folder names; configure an override if your server advertises none or several.
- Ordinary runs repeat the configured lookback (30 days by default), so earlier undecided mail is reclassified after AI or policy changes. `--new-only` explicitly uses `(account, mailbox, UIDVALIDITY, UID)` cursors. Full history is explicit: `cleanup` includes only Inbox, while `run --full-history` also includes configured folders.
- Marketing/newsletters with at least 25% of messages marked read require review by default. Engaged cold outreach also requires review. Read flags are imperfect evidence of preference, so they never force KEEP. Choose `nothx config --engaged-marketing allow` to permit automatic actions on clear promotions even when read; explicit keep/block choices still win.
- Every scan reports mailbox size, selected headers, headers read, and scope. A small incremental result describes new mail, not a clean Inbox. Junk messages already outside Inbox are reported separately from Inbox messages to move.
- Cleanup previews show summary counts; add `--details` for each unsubscribe/block candidate’s account/list identity and recent subjects. Unsubscribe requests stop future deliveries when honored; existing marketing messages remain in Inbox unless you enable `nothx config --unwanted-mail junk`. Run `nothx cleanup` after enabling it to include the full Inbox backlog. Block actions move matching messages to Junk. Preview uses configured AI only when enabled; `--dry-run` remains local.
- Inbox cleanup is optional: `nothx config --unwanted-mail junk` moves approved, non-protected messages after the unsubscribe request is accepted. It also clears subsequent matching deliveries while verification is pending. Requests needing a manual step keep their source messages available. Mailbox consent is still required, failures remain visible, and moving to Junk does not prove the sender stopped mailing.
- Body fetching is disabled by default. The optional footer scanner examines at most two inline text tails (64 KiB each, 128 KiB total) for authenticated list/bulk candidates or explicit commercial offers. It skips attachments, nested messages, images, scripts, and forms.
- One-click POST requires compliant headers plus `$canunsubscribe` or a correlated passing DKIM signature that covers both unsubscribe headers. All outbound unsubscribe contact—including an explicitly opened browser page—and mailbox actions require separate, versioned consent.
- HTTP requests are HTTPS-only, proxy/auth/referrer-free, redirect constrained, SSRF checked, and connected to an already validated public IP while preserving TLS hostname verification. Ordinary requests carry no cookies; optional browser completion permits temporary cookies only on the unsubscribe page's origin.
- Stored targets are fingerprints and hashed destination labels. Complete hosts, paths, queries, mailto recipients/bodies, and HTTP response bodies are excluded from normal history and exports.

### What an outcome means

- `requested`: the endpoint accepted a one-click/GET request, or SMTP accepted the mail for delivery. It does **not** guarantee mail will stop.
- `needs_user`: automation reached a login, JavaScript flow, preference center, CAPTCHA, or an ambiguous submission. Nothx can submit one same-origin, unambiguous unsubscribe confirmation form; it does not choose preferences or enter credentials.
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
- For Outlook/Live/Hotmail: use Microsoft sign-in, enable IMAP in Outlook web, and retry `nothx test`. Re-add the account only when OAuth consent needs renewal; app passwords do not work
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

### Sonnet model (September 29, 2026)

The optional Sonnet choice uses `claude-sonnet-5-5`; the Haiku default is unchanged. Short Sonnet completion paths request
`between_tools` to preserve the output budget; explicit adaptive reasoning
remains available. Existing model environment overrides still take precedence.

### Finishing saved unsubscribe decisions

`nothx review` includes failed requests and offers **Resolve unsubscribe in Nothx**.
The equivalent `nothx resolve ID` refreshes up to 50 stored Inbox sources, prioritizing
promotional messages and advertised unsubscribe methods across the full saved history.
An explicit `--source-uid UID` can select an older stored source outside that shortlist. It checks UIDVALIDITY, UID, Message-ID,
From and list identity before using a source. If the mailbox changed or the messages
are gone, run `nothx cleanup` to refresh the full Inbox history.

Use `nothx resolve ID --dry-run` to see usable source UIDs without contacting a sender
or saving decisions. Mixed From-address groups require a source selection; scripts
can pass `--source-uid UID --yes`. This source-level choice does not set a blanket
unsubscribe policy for the sender, and unrelated service deliveries cannot mark that
source-level request ineffective. Whole-list resolution uses matching List-ID messages;
aliased From-only messages require an explicit source selection. Optional `nothx config --footer-scan on` also lets
resolution inspect at most three bounded, authenticated footer sources for alternatives
to failed header links. It stays off by default. Full scans spend their 100-message-per-account footer budget
on the newest eligible message from distinct subscriptions, so a single prolific
newsletter cannot consume the entire budget.

An explicit `--retry` permits one additional contacting attempt. Consent or authentication
boundaries that sent nothing do not spend this retry. Accepted requests, ambiguous
submissions and exhausted retries are not replayed. Ordinary scans preserve these
boundaries. For a provider requiring login or preference choices, use
`nothx open-unsubscribe ID` (which refreshes only saved sources for this identity),
complete the provider step, then
`nothx resolve ID --completed` after seeing confirmation. The latter records **your
reported confirmation**, not independent proof of delivery stopping. Nothx waits
48 hours and a complete subsequent Inbox scan before reporting verified quietness
for whole-list requests. A source-level opt-out stays requested: Nothx cannot distinguish
that stream from other mail sharing the address. Browser acknowledgements are atomic
with execution claims, and they resolve prior ambiguity without permitting a replay
to that ambiguous endpoint.

### JavaScript unsubscribe pages

Optional browser support can finish simple JavaScript confirmation pages through
Nothx. With pipx, run `pipx inject nothx playwright`, then `nothx browser-setup`.
New scans use the fallback automatically; use `nothx resolve ID --retry` for a
previously pending page. A failed or uncertain submission is never silently replayed.

The browser uses a fresh isolated context without your saved login. Temporary
page cookies stay within the unsubscribe origin and are discarded afterward. Downloads,
service workers, WebSockets, cross-origin submissions, and private-network requests
are blocked. All page traffic uses the same pinned-address HTTPS fetcher as ordinary
unsubscribe requests. Login, CAPTCHA, account deletion, broad opt-out choices and
forms needing personal input remain manual. An accepted unsubscribe request and
visible confirmation are both required; delivery still needs the normal post-grace scan.
