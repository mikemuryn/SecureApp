# Secure API Key Management Guide

## Overview

This guide explains how to securely add and use API keys in SecureApp without committing them to git.

## Never Commit API Keys

**Important:** Never commit API keys, passwords, or secrets to git. They will be detected and blocked by GitHub Push Protection.

## Method 1: Using .env File (Recommended)

### Setup (Works in Virtual Environments Too)

The `.env` file works the same whether you're using a virtual environment or not. It's located in your project root and is automatically loaded.

1. **Create your `.env` file in project root:**

    ```bash
    # Navigate to project root (if not already there)
    cd /path/to/SecureApp

    # Activate your virtual environment (if using one)
    conda activate secureapp
    # or
    source .venv/bin/activate  # for venv/virtualenv

    # Copy the example template
    cp .env.example .env
    ```

2. **Edit `.env` with your actual keys:**

    ```bash
    # Edit .env (this file is gitignored)
    nano .env
    # or
    code .env
    ```

    Add your keys:

    ```bash
    OPENAI_API_KEY=sk-proj-your-actual-key-here
    ANTHROPIC_API_KEY=sk-ant-your-actual-key-here
    CURSOR_API_KEY=your-cursor-key-here
    ```

3. **Verify `.env` is gitignored:**

    ```bash
    git status
    # .env should NOT appear in the list
    ```

### Virtual Environment Notes

- `.env` file location: Project root (not inside `.venv/` folder)
- Works with: `conda`, `venv`, `virtualenv`, `pipenv`
- Auto-loads: When scripts run, `python-dotenv` loads `.env` from project root
- Scope: Same `.env` file works for all virtual environments on this project

### Loading Environment Variables

The commit message scripts automatically check environment variables:

```bash
# .env is loaded automatically by python-dotenv if available
# Or set manually:
export OPENAI_API_KEY="your-key"
export ANTHROPIC_API_KEY="your-key"
```

### Using in Scripts

The scripts check for API keys in this order:

1. Environment variables (from `.env` or system)
2. Falls back to heuristics if no keys found

**Example usage:**

```bash
# With .env file (automatically loaded)
python3 generate_commit_msg_with_llm.py

# Or export manually
export OPENAI_API_KEY="your-key"
python3 generate_commit_msg_with_llm.py
```

## Method 2: Virtual Environment Activation Script (Project-Specific)

If you want the keys to be available only when your virtual environment is active:

1. **Create activation script:**

    ```bash
    # For conda
    mkdir -p $CONDA_PREFIX/etc/conda/activate.d
    echo 'export OPENAI_API_KEY="your-key"' > $CONDA_PREFIX/etc/conda/activate.d/env_vars.sh

    # For venv/virtualenv
    echo 'export OPENAI_API_KEY="your-key"' >> .venv/bin/activate
    ```

2. **Or create a local activate script:**

    ```bash
    # Create activate_with_keys.sh in project root
    cat > activate_with_keys.sh << 'EOF'
    #!/bin/bash
    source .venv/bin/activate  # or: conda activate secureapp
    export OPENAI_API_KEY="your-key"
    export ANTHROPIC_API_KEY="your-key"
    echo "Virtual environment activated with API keys"
    EOF

    chmod +x activate_with_keys.sh
    source activate_with_keys.sh
    ```

## Method 3: Shell Profile (System-Wide)

Add to your shell profile for persistent access across all environments:

```bash
# Add to ~/.bashrc or ~/.zshrc
export OPENAI_API_KEY="your-openai-key"
export ANTHROPIC_API_KEY="your-anthropic-key"
```

Then reload:

```bash
source ~/.bashrc
# or
source ~/.zshrc
```

**Note:** This makes keys available system-wide, even outside virtual environments.

## Method 4: OS Keyring (Most Secure)

For maximum security on Linux, use the system keyring:

```bash
# Install keyring (if not already installed)
pip install keyring

# Store key securely
keyring set secureapp openai_api_key
# Enter your key when prompted

# Retrieve in code
import keyring
api_key = keyring.get_password("secureapp", "openai_api_key")
```

## Verification

### Check if keys are loaded:

```bash
# Check environment variables
echo $OPENAI_API_KEY

# Or in Python
python3 -c "import os; print('OPENAI_API_KEY' in os.environ)"
```

### Test commit message generation:

```bash
# Should use LLM if key is set, otherwise falls back to heuristics
git cr
```

## Security Best Practices

1. **Never commit `.env`** - Already in `.gitignore`
2. **Never hardcode keys** - Always use environment variables
3. **Rotate keys regularly** - Especially if exposed
4. **Use different keys for dev/prod** - Separate environments
5. **Restrict key permissions** - Limit what each key can do
6. **Monitor usage** - Check API usage logs regularly

## Troubleshooting

### Key not found?

```bash
# Verify .env exists
ls -la .env

# Check if variables are loaded
python3 -c "import os; print(os.getenv('OPENAI_API_KEY'))"

# Test with explicit export
export OPENAI_API_KEY="test-key"
python3 -c "import os; print(os.getenv('OPENAI_API_KEY'))"
```

### Scripts still using heuristics?

- Check if API key is actually set: `echo $OPENAI_API_KEY`
- Verify the script checks environment: `grep OPENAI_API_KEY generate_commit_msg_with_llm.py`
- Check for typos in variable names

## Example .env File

```bash
# SecureApp Environment Variables
# DO NOT COMMIT THIS FILE

# LLM API Keys
OPENAI_API_KEY=sk-proj-abc123...
ANTHROPIC_API_KEY=sk-ant-xyz789...

# Application settings (optional)
LOG_LEVEL=INFO
```

## Next Steps

1. Copy `.env.example` to `.env`
2. Add your actual API keys to `.env`
3. Verify `.env` is in `.gitignore`
4. Test commit message generation: `git cr`
