# nothx

**AI-powered email unsubscribe tool. Set it up once, AI handles your inbox forever.**

nothx scans your inbox for marketing emails, uses AI to intelligently classify them, and automatically unsubscribes you from the ones you don't want. It runs on your machine, uses your API key, and never sells your data.

## Features

- **AI-Powered Classification** - Uses Claude to distinguish marketing from important transactional emails
- **Truly Hands-Off** - Set it and forget it. Runs monthly via system scheduler
- **Privacy First** - Runs 100% locally. Only email headers sent to AI, never bodies
- **Hybrid Classification** - User rules → Preset patterns → AI → Heuristics → Manual review
- **Actually Unsubscribes** - Doesn't just filter. Clicks unsubscribe links via RFC 8058, GET, or mailto
- **Learns From You** - AI improves based on your corrections

## Quick Start

```bash
# Install
pip install nothx

# Set up (guided wizard)
nothx init

# That's it! nothx will run monthly automatically.
```

## Requirements

- Python 3.11+
- Gmail account with App Password (or Outlook)
- Anthropic API key (optional, for AI classification)

## Installation

### From PyPI (recommended)
```bash
pip install nothx
```

### From Source
```bash
git clone https://github.com/nothx/nothx.git
cd nothx
pip install -e .
```

## Setup

### 1. Run the Setup Wizard

```bash
nothx init
```

This will:
1. Ask for your email provider (Gmail/Outlook)
2. Guide you through creating an App Password
3. Test your connection
4. Set up AI classification (optional)
5. Run your first scan
6. Schedule automatic monthly runs

### 2. Gmail App Password

For Gmail, you need an App Password:
1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Generate a new password for "nothx"
3. Copy the 16-character code

### 3. Anthropic API Key (Optional)

For AI-powered classification:
1. Get an API key from [console.anthropic.com](https://console.anthropic.com)
2. Enter it during setup

Without an API key, nothx uses heuristic scoring (still works, just less smart).

## Usage

### Manual Run

```bash
# Scan and process emails
nothx run

# Preview without making changes
nothx run --dry-run

# Show detailed output
nothx run --verbose
```

### Check Status

```bash
nothx status
```

### Review Uncertain Senders

```bash
nothx review
```

### Undo an Unsubscribe

```bash
# Show recent unsubscribes
nothx undo

# Undo specific domain
nothx undo linkedin.com
```

### Manage Schedule

```bash
# Show current schedule
nothx schedule --status

# Set monthly runs
nothx schedule --monthly

# Set weekly runs
nothx schedule --weekly

# Disable automatic runs
nothx schedule --off
```

### Add Custom Rules

```bash
# Always keep emails from a domain
nothx rule "github.com" keep

# Always unsubscribe from a domain
nothx rule "*.spam.com" unsub

# List all rules
nothx rules
```

### Configuration

```bash
# Show current config
nothx config --show

# Disable AI (use heuristics only)
nothx config --ai off

# Set operation mode
nothx config --mode hands_off    # Silent auto-action (default)
nothx config --mode notify       # Auto-action + summary
nothx config --mode confirm      # Manual confirmation required
```

## How It Works

### 5-Layer Classification System

```
Email arrives
     ↓
┌─────────────────────────────────────┐
│ Layer 1: USER RULES                 │  ← Your manual keep/unsub lists
└─────────────────────────────────────┘
     ↓
┌─────────────────────────────────────┐
│ Layer 2: PRESET PATTERNS            │  ← marketing@*, *.gov, etc.
└─────────────────────────────────────┘
     ↓
┌─────────────────────────────────────┐
│ Layer 3: AI CLASSIFICATION          │  ← Claude analyzes headers
└─────────────────────────────────────┘
     ↓
┌─────────────────────────────────────┐
│ Layer 4: HEURISTIC SCORING          │  ← Open rate, frequency, patterns
└─────────────────────────────────────┘
     ↓
┌─────────────────────────────────────┐
│ Layer 5: REVIEW QUEUE               │  ← Manual decision needed
└─────────────────────────────────────┘
```

### Privacy Model

- **Email bodies are NEVER read** - Only headers (From, Subject, Date, List-Unsubscribe)
- **Your machine, your data** - All data stored locally in `~/.nothx/`
- **Your API key** - Direct relationship with Anthropic, not through us
- **Open source** - Audit the code yourself

### Unsubscribe Methods

nothx tries these methods in order:
1. **RFC 8058 One-Click** - POST request to List-Unsubscribe-Post URL
2. **GET Request** - Simple GET to List-Unsubscribe URL
3. **Mailto** - Sends unsubscribe email (requires SMTP)

## Configuration File

Config is stored in `~/.nothx/config.json`:

```json
{
  "accounts": {
    "default": {
      "provider": "gmail",
      "email": "you@gmail.com",
      "password": "xxxx-xxxx-xxxx-xxxx"
    }
  },
  "ai": {
    "enabled": true,
    "provider": "anthropic",
    "api_key": "sk-ant-...",
    "confidence_threshold": 0.80
  },
  "operation_mode": "hands_off",
  "scan_days": 30
}
```

## Comparison with Alternatives

| Tool | Price | Privacy | AI | Actually Unsubscribes | Local |
|------|-------|---------|-----|----------------------|-------|
| Unroll.me | Free | Sells data | No | No (filters only) | No |
| Clean Email | $30/yr | Headers only | No | Yes | No |
| SaneBox | $84-432/yr | Headers only | Yes | Yes | No |
| Leave Me Alone | $48/yr | Yes | Basic | Yes | No |
| **nothx** | **Free** | **100% local** | **Yes (Claude)** | **Yes** | **Yes** |

## Troubleshooting

### "Connection failed"
- Check your App Password is correct
- Make sure IMAP is enabled in Gmail settings
- Try regenerating the App Password

### "AI test failed"
- Verify your Anthropic API key
- Check you have API credits
- nothx will fall back to heuristics mode

### Emails still coming after unsubscribe
- Some senders ignore unsubscribe requests
- Run `nothx run` again - it will create email filters for repeat offenders
- Add the domain to your block list: `nothx rule "domain.com" block`

## Contributing

Contributions welcome! Please read our contributing guidelines first.

```bash
# Development install
git clone https://github.com/nothx/nothx.git
cd nothx
pip install -e ".[dev]"

# Run tests
pytest
```

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**nothx** - Because your inbox should work for you, not against you.
