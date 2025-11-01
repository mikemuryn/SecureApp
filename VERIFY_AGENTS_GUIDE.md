# System-Wide AI Agent/CLI Verification Guide

This guide helps you verify all AI-related CLI tools and agents installed on your machine across all environments.

## Quick Verification Scripts

Two scripts are provided:

- **Linux/WSL**: `verify_system_agents.sh`
- **Windows PowerShell**: `verify_system_agents.ps1`

### Run the Scripts

**Linux/WSL:**

```bash
chmod +x verify_system_agents.sh
./verify_system_agents.sh
```

**Windows PowerShell:**

```powershell
.\verify_system_agents.ps1
```

---

## Manual Verification Steps

### 1. Check PATH for AI CLI Tools

**Linux/WSL:**

```bash
which -a hf huggingface-cli openai anthropic claude xai grok qwen deepseek mistral ollama langchain aws gcloud azure
```

**Windows:**

```powershell
Get-Command hf, huggingface-cli, openai, anthropic, claude, xai, grok, qwen, deepseek, mistral, ollama -ErrorAction SilentlyContinue
```

### 2. Check Python Environments

**List all Python installations:**

```bash
# Linux/WSL
which -a python python3 py

# Windows
where.exe python python3 py
```

**Check packages in default Python:**

```bash
python3 -m pip list | grep -iE "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral|ollama|langchain|transformers"
```

**Windows:**

```powershell
python -m pip list | Select-String -Pattern "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral"
```

### 3. Check All Conda Environments

```bash
# List all environments
conda env list

# Check each environment
for env in $(conda env list | awk 'NR>2 {print $1}'); do
    echo "=== Environment: $env ==="
    conda run -n "$env" pip list | grep -iE "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral|ollama|transformers"
done
```

**Windows:**

```powershell
conda env list
# Then manually check each:
conda run -n <env_name> pip list | Select-String -Pattern "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral"
```

### 4. Check Global npm Packages

```bash
npm list -g --depth=0 | grep -iE "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral"
```

**Windows:**

```powershell
npm list -g --depth=0 | Select-String -Pattern "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral"
```

### 5. Check pipx Packages

```bash
pipx list
```

**Windows:**

```powershell
pipx list
```

### 6. Check Local Installation Directories

**Linux/WSL:**

```bash
# User local bin
ls -la ~/.local/bin/ | grep -iE "hf|huggingface|openai|claude|xai|grok|qwen|deepseek|mistral"

# System directories
ls -la /usr/local/bin/ | grep -iE "hf|huggingface|openai|claude|xai|grok|qwen|deepseek|mistral"
```

**Windows:**

```powershell
# Check AppData
Get-ChildItem "$env:LOCALAPPDATA\Programs" -Recurse -Directory | Where-Object { $_.Name -match "huggingface|openai|anthropic|xai|grok|qwen|deepseek|mistral" }
```

### 7. Check Environment Variables

**Linux/WSL:**

```bash
env | grep -iE "HUGGINGFACE|OPENAI|ANTHROPIC|CLAUDE|XAI|GROK|QWEN|DEEPSEEK|MISTRAL|HF_|XAI_|MISTRAL_"
```

**Windows:**

```powershell
Get-ChildItem Env: | Where-Object { $_.Name -match "HUGGINGFACE|OPENAI|ANTHROPIC|CLAUDE|XAI|GROK|QWEN|DEEPSEEK|MISTRAL|HF_|XAI_|MISTRAL_" }
```

### 8. Check Configuration Files

**Linux/WSL:**

```bash
# HuggingFace cache/config
ls -la ~/.cache/huggingface/ 2>/dev/null
ls -la ~/.huggingface/ 2>/dev/null

# OpenAI config
ls -la ~/.openai/ 2>/dev/null

# General config
find ~/.config -name "*huggingface*" -o -name "*openai*" -o -name "*anthropic*" -o -name "*xai*" -o -name "*grok*" -o -name "*qwen*" -o -name "*deepseek*" -o -name "*mistral*" 2>/dev/null

# Windows paths (from WSL)
ls -la /mnt/c/Users/*/AppData/Roaming/Cursor/ 2>/dev/null
ls -la /mnt/c/Users/*/AppData/Local/Cursor/ 2>/dev/null
```

**Windows:**

```powershell
# Check common config locations
Test-Path "$env:USERPROFILE\.cache\huggingface"
Test-Path "$env:USERPROFILE\.huggingface"
Test-Path "$env:USERPROFILE\.openai"
Get-ChildItem "$env:APPDATA" -Recurse -Filter "*huggingface*" -ErrorAction SilentlyContinue
Get-ChildItem "$env:APPDATA" -Recurse -Directory | Where-Object { $_.Name -match "xai|grok|qwen|deepseek|mistral" }

# Check Cursor installation locations
$cursorPaths = @(
    "$env:LOCALAPPDATA\Programs\cursor",
    "$env:APPDATA\Cursor",
    "$env:LOCALAPPDATA\Cursor",
    "$env:USERPROFILE\.cursor",
    "C:\Program Files\Cursor",
    "C:\Program Files (x86)\Cursor"
)
foreach ($path in $cursorPaths) {
    if (Test-Path $path) {
        Write-Host "Cursor found at: $path"
    }
}
```

### 9. Check VS Code/Cursor Extensions

**Linux/WSL:**

```bash
# VS Code
code --list-extensions | grep -iE "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral|ai"

# Or check directories
ls ~/.vscode/extensions/ | grep -iE "huggingface|openai|anthropic|xai|grok|qwen|deepseek|mistral"
ls ~/.cursor/extensions/ 2>/dev/null | grep -iE "huggingface|openai|anthropic|xai|grok|qwen|deepseek|mistral"
```

**Windows:**

```powershell
# VS Code
code --list-extensions | Select-String -Pattern "huggingface|openai|anthropic|xai|grok|qwen|deepseek|mistral"

# Or check directories
Get-ChildItem "$env:USERPROFILE\.vscode\extensions" | Where-Object { $_.Name -match "huggingface|openai|anthropic|xai|grok|qwen|deepseek|mistral" }
Get-ChildItem "$env:USERPROFILE\.cursor\extensions" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "huggingface|openai|anthropic|xai|grok|qwen|deepseek|mistral" }
```

---

## What to Look For

### AI/ML CLI Tools:

- `hf` or `huggingface-cli` - HuggingFace CLI
- `openai` - OpenAI CLI
- `anthropic` or `claude` - Anthropic/Claude CLI
- `xai` or `grok` - xAI/Grok CLI
- `qwen` - Alibaba Qwen CLI
- `deepseek` - DeepSeek CLI
- `mistral` - Mistral AI CLI
- `ollama` - Ollama CLI
- `langchain-cli` - LangChain CLI

### AI/ML Python Packages:

- `huggingface_hub` - HuggingFace Hub client
- `transformers` - HuggingFace Transformers
- `openai` - OpenAI Python client
- `anthropic` - Anthropic Python client
- `xai` - xAI/Grok Python client
- `qwen` / `qwen-api` - Alibaba Qwen client
- `deepseek` / `deepseek-api` - DeepSeek client
- `mistralai` - Mistral AI client
- `ollama` - Ollama Python client
- `langchain` - LangChain framework
- `llama-index` - LlamaIndex
- `cohere` - Cohere client

### Environment Variables:

- `HUGGINGFACE_TOKEN` / `HF_TOKEN`
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `XAI_API_KEY` / `GROK_API_KEY`
- `QWEN_API_KEY`
- `DEEPSEEK_API_KEY`
- `MISTRAL_API_KEY`
- `HF_HOME` / `HF_CACHE`
- `XAI_API_BASE` / `MISTRAL_API_BASE`

---

## Expected Results for SecureApp

Since SecureApp only uses:

- **Cursor Agent** (primary)
- **Codex** (verification)

You should see:

- ✅ No HuggingFace CLI (`hf`, `huggingface-cli`)
- ✅ No OpenAI CLI (`openai`)
- ✅ No Anthropic CLI (`anthropic`, `claude`)
- ✅ No AI-related npm packages
- ✅ No AI-related Python packages (unless installed for other projects)
- ✅ No AI-related environment variables (unless for other projects)

---

## Next Steps

If you find unwanted AI CLI tools:

1. **Python packages**: `pip uninstall <package-name>`
2. **Conda packages**: `conda remove -n <env> <package-name>`
3. **npm packages**: `npm uninstall -g <package-name>`
4. **pipx packages**: `pipx uninstall <package-name>`
5. **System binaries**: Remove from PATH or uninstall the application
