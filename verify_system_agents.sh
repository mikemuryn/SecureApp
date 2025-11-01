#!/bin/bash
# System-wide AI Agent/CLI Verification Script
# This script checks for all AI-related CLI tools and agents across your system

echo "=========================================="
echo "System-Wide AI Agent/CLI Verification"
echo "=========================================="
echo ""

# 1. Check for common AI CLI tools in PATH
echo "1. Checking for AI CLI tools in PATH..."
echo "----------------------------------------"
which -a hf huggingface-cli openai anthropic claude xai grok qwen deepseek mistral ollama langchain aws gcloud azure 2>/dev/null || echo "   ✅ No system-wide AI CLI tools found in PATH"
echo ""

# 2. Check default Python packages
echo "2. Checking default Python packages..."
echo "----------------------------------------"
if command -v python3 >/dev/null 2>&1; then
    python3 -m pip list 2>/dev/null | grep -iE "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral|ollama|langchain|llama|cohere|tiktoken|transformers|diffusers" || echo "   ✅ No AI-related packages in default Python"
else
    echo "   ⚠️  Python3 not found"
fi
echo ""

# 3. Check all conda environments
echo "3. Checking Conda environments..."
echo "----------------------------------------"
if command -v conda >/dev/null 2>&1; then
    echo "   Conda environments:"
    conda env list 2>/dev/null
    echo ""
    echo "   Checking each environment for AI packages..."
    for env in $(conda env list | awk 'NR>2 {print $1}' | grep -v "^#"); do
        echo "   - Environment: $env"
        conda run -n "$env" pip list 2>/dev/null | grep -iE "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral|ollama|langchain|llama|cohere|tiktoken|transformers|diffusers" || echo "      ✅ No AI packages in $env"
    done
else
    echo "   ✅ Conda not installed"
fi
echo ""

# 4. Check global npm packages
echo "4. Checking global npm packages..."
echo "----------------------------------------"
if command -v npm >/dev/null 2>&1; then
    npm list -g --depth=0 2>/dev/null | grep -iE "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral|@huggingface|@openai|@xai|@mistral" || echo "   ✅ No AI-related npm packages found globally"
else
    echo "   ✅ npm not installed"
fi
echo ""

# 5. Check pipx packages
echo "5. Checking pipx packages..."
echo "----------------------------------------"
if command -v pipx >/dev/null 2>&1; then
    pipx list 2>/dev/null || echo "   ✅ No pipx packages installed"
else
    echo "   ✅ pipx not installed"
fi
echo ""

# 6. Check ~/.local/bin
echo "6. Checking ~/.local/bin for AI tools..."
echo "----------------------------------------"
if [ -d ~/.local/bin ]; then
    ls -la ~/.local/bin/ 2>/dev/null | grep -iE "hf|huggingface|openai|claude|anthropic|xai|grok|qwen|deepseek|mistral" || echo "   ✅ No AI tools in ~/.local/bin/"
else
    echo "   ✅ ~/.local/bin/ does not exist"
fi
echo ""

# 7. Check environment variables
echo "7. Checking AI-related environment variables..."
echo "----------------------------------------"
env | grep -iE "HUGGINGFACE|OPENAI|ANTHROPIC|CLAUDE|XAI|GROK|QWEN|DEEPSEEK|MISTRAL|HF_|XAI_|MISTRAL_" || echo "   ✅ No AI-related environment variables set"
echo ""

# 8. Check common installation directories
echo "8. Checking common installation directories..."
echo "----------------------------------------"
echo "   /usr/local/bin:"
ls -la /usr/local/bin/ 2>/dev/null | grep -iE "hf|huggingface|openai|claude|anthropic|xai|grok|qwen|deepseek|mistral" || echo "      ✅ No AI tools found"
echo ""
echo "   ~/.config:"
find ~/.config -maxdepth 2 -type f \( -name "*huggingface*" -o -name "*openai*" -o -name "*anthropic*" -o -name "*xai*" -o -name "*grok*" -o -name "*qwen*" -o -name "*deepseek*" -o -name "*mistral*" \) 2>/dev/null || echo "      ✅ No AI config files found"
echo ""

# 9. Check Cursor-specific configuration
echo "9. Checking Cursor IDE configuration..."
echo "----------------------------------------"
cursor_found=0

# Linux/WSL paths
if [ -d ~/.cursor ] || [ -d ~/.config/Cursor ]; then
    echo "   ✅ Cursor configuration found (Linux/WSL)"
    find ~/.cursor ~/.config/Cursor -type f -name "*.json" 2>/dev/null | head -5
    cursor_found=1
fi

# Windows paths (accessible from WSL)
if [ -d /mnt/c/Users ]; then
    for user_dir in /mnt/c/Users/*/; do
        username=$(basename "$user_dir")
        # Check Windows AppData paths
        if [ -d "/mnt/c/Users/$username/AppData/Roaming/Cursor" ] || \
           [ -d "/mnt/c/Users/$username/AppData/Local/Cursor" ] || \
           [ -d "/mnt/c/Users/$username/.cursor" ]; then
            echo "   ✅ Cursor configuration found (Windows: $username)"
            find "/mnt/c/Users/$username/AppData/Roaming/Cursor" \
                 "/mnt/c/Users/$username/AppData/Local/Cursor" \
                 "/mnt/c/Users/$username/.cursor" \
                 -type f -name "*.json" 2>/dev/null | head -5
            cursor_found=1
        fi
        # Check Windows Program Files
        if [ -d "/mnt/c/Program Files/Cursor" ] || [ -d "/mnt/c/Program Files (x86)/Cursor" ]; then
            echo "   ✅ Cursor installation found (Windows Program Files)"
            cursor_found=1
        fi
    done
fi

if [ $cursor_found -eq 0 ]; then
    echo "   ⚠️  Cursor configuration not found in expected locations"
fi
echo ""

# 10. Check VS Code extensions (might have AI-related)
echo "10. Checking VS Code/Cursor extensions..."
echo "----------------------------------------"
if command -v code >/dev/null 2>&1; then
    code --list-extensions 2>/dev/null | grep -iE "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral|ai" || echo "   ✅ No AI-related VS Code extensions"
elif [ -d ~/.vscode/extensions ] || [ -d ~/.cursor/extensions ]; then
    echo "   Checking extension directories..."
    find ~/.vscode/extensions ~/.cursor/extensions -maxdepth 1 -type d 2>/dev/null | grep -iE "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral" || echo "   ✅ No AI-related extensions found"
else
    echo "   ✅ VS Code/Cursor not installed or no extensions"
fi
echo ""

echo "=========================================="
echo "Verification Complete"
echo "=========================================="
