# System-wide AI Agent/CLI Verification Script for Windows/PowerShell
# This script checks for all AI-related CLI tools and agents across your system

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "System-Wide AI Agent/CLI Verification" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check for common AI CLI tools in PATH
Write-Host "1. Checking for AI CLI tools in PATH..." -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Gray
$aiTools = @("hf", "huggingface-cli", "openai", "anthropic", "claude", "xai", "grok", "qwen", "deepseek", "mistral", "ollama", "langchain", "aws", "gcloud", "az")
$found = $false
foreach ($tool in $aiTools) {
    $path = Get-Command $tool -ErrorAction SilentlyContinue
    if ($path) {
        Write-Host "   [WARNING] Found: $tool at $($path.Source)" -ForegroundColor Yellow
        $found = $true
    }
}
if (-not $found) {
    Write-Host "   [OK] No system-wide AI CLI tools found in PATH" -ForegroundColor Green
}
Write-Host ""

# 2. Check Python packages (default and in PATH)
Write-Host "2. Checking Python packages..." -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Gray
$pythonVersions = @("python", "python3", "py")
$aiPackages = @("huggingface", "openai", "anthropic", "claude", "xai", "grok", "qwen", "deepseek", "mistral", "ollama", "langchain", "llama", "cohere", "transformers", "diffusers")

foreach ($py in $pythonVersions) {
    $pyCmd = Get-Command $py -ErrorAction SilentlyContinue
    if ($pyCmd) {
        Write-Host "   Checking $py..." -ForegroundColor Gray
        $packages = & $py -m pip list 2>$null | Select-String -Pattern ($aiPackages -join "|") -CaseSensitive:$false
        if ($packages) {
            Write-Host "   [WARNING] Found AI packages:" -ForegroundColor Yellow
            $packages | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
        } else {
            Write-Host "      [OK] No AI-related packages" -ForegroundColor Green
        }
    }
}
Write-Host ""

# 3. Check Conda environments
Write-Host "3. Checking Conda environments..." -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Gray
$condaCmd = Get-Command conda -ErrorAction SilentlyContinue
if ($condaCmd) {
    Write-Host "   Conda environments:" -ForegroundColor Gray
    & conda env list 2>$null
    Write-Host ""
    Write-Host "   Checking each environment for AI packages..." -ForegroundColor Gray
    $envs = & conda env list 2>$null | Select-String -Pattern "^\w+" | ForEach-Object { ($_ -split "\s+")[0] }
    foreach ($env in $envs) {
        Write-Host "   - Environment: $env" -ForegroundColor Gray
        $packages = & conda run -n $env pip list 2>$null | Select-String -Pattern ($aiPackages -join "|") -CaseSensitive:$false
        if ($packages) {
            Write-Host "      [WARNING] Found AI packages" -ForegroundColor Yellow
        } else {
            Write-Host "      [OK] No AI packages" -ForegroundColor Green
        }
    }
} else {
    Write-Host "   [OK] Conda not installed" -ForegroundColor Green
}
Write-Host ""

# 4. Check npm packages
Write-Host "4. Checking global npm packages..." -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Gray
$npmCmd = Get-Command npm -ErrorAction SilentlyContinue
if ($npmCmd) {
    $packages = & npm list -g --depth=0 2>$null | Select-String -Pattern "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral" -CaseSensitive:$false
    if ($packages) {
        Write-Host "   [WARNING] Found AI-related npm packages:" -ForegroundColor Yellow
        $packages | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
    } else {
        Write-Host "   [OK] No AI-related npm packages found globally" -ForegroundColor Green
    }
} else {
    Write-Host "   [OK] npm not installed" -ForegroundColor Green
}
Write-Host ""

# 5. Check environment variables
Write-Host "5. Checking AI-related environment variables..." -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Gray
$envVars = Get-ChildItem Env: | Where-Object { $_.Name -match "HUGGINGFACE|OPENAI|ANTHROPIC|CLAUDE|XAI|GROK|QWEN|DEEPSEEK|MISTRAL|HF_|XAI_|MISTRAL_" }
if ($envVars) {
    Write-Host "   [WARNING] Found environment variables:" -ForegroundColor Yellow
    $envVars | ForEach-Object { Write-Host "      $($_.Name)=$($_.Value)" -ForegroundColor Yellow }
} else {
    Write-Host "   [OK] No AI-related environment variables set" -ForegroundColor Green
}
Write-Host ""

# 6. Check AppData for AI tools (Windows)
Write-Host "6. Checking Windows AppData for AI tools..." -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Gray
$appDataPaths = @("$env:LOCALAPPDATA\Programs", "$env:APPDATA")
foreach ($path in $appDataPaths) {
    if (Test-Path $path) {
        $tools = Get-ChildItem -Path $path -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral" }
        if ($tools) {
            Write-Host ("   [WARNING] Found in " + $path + ":") -ForegroundColor Yellow
            $tools | ForEach-Object { Write-Host "      $($_.FullName)" -ForegroundColor Yellow }
        }
    }
}
Write-Host ""

# 6b. Check Cursor installation (Windows-specific)
Write-Host "6b. Checking Cursor IDE installation (Windows)..." -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Gray
$cursorPaths = @(
    "$env:LOCALAPPDATA\Programs\cursor",
    "$env:APPDATA\Cursor",
    "$env:LOCALAPPDATA\Cursor",
    "$env:USERPROFILE\.cursor",
    "C:\Program Files\Cursor",
    "C:\Program Files (x86)\Cursor"
)
$cursorFound = $false
foreach ($cursorPath in $cursorPaths) {
    if (Test-Path $cursorPath) {
        Write-Host "   [OK] Cursor found at: $cursorPath" -ForegroundColor Green
        $cursorFound = $true
        # Check for extensions
        $extPath = Join-Path $cursorPath "extensions"
        if (Test-Path $extPath) {
            $aiExtensions = Get-ChildItem -Path $extPath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral|ai" }
            if ($aiExtensions) {
                Write-Host "      [WARNING] Found AI-related extensions:" -ForegroundColor Yellow
                $aiExtensions | ForEach-Object { Write-Host "         $($_.Name)" -ForegroundColor Yellow }
            }
        }
        # Check for settings
        $settingsPath = Join-Path $cursorPath "User\settings.json"
        if (Test-Path $settingsPath) {
            Write-Host "      Settings file found: $settingsPath" -ForegroundColor Gray
        }
    }
}
if (-not $cursorFound) {
    Write-Host "   [WARNING] Cursor not found in standard Windows locations" -ForegroundColor Yellow
}
Write-Host ""

# 7. Check Cursor/VS Code extensions (user-specific)
Write-Host "7. Checking Cursor/VS Code extensions (user-specific)..." -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Gray
$extPaths = @(
    "$env:USERPROFILE\.vscode\extensions",
    "$env:USERPROFILE\.cursor\extensions",
    "$env:APPDATA\Cursor\User\extensions",
    "$env:LOCALAPPDATA\Cursor\User\extensions"
)
foreach ($extPath in $extPaths) {
    if (Test-Path $extPath) {
        $extensions = Get-ChildItem -Path $extPath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "huggingface|openai|anthropic|claude|xai|grok|qwen|deepseek|mistral|ai" }
        if ($extensions) {
            Write-Host ("   [WARNING] Found extensions in " + $extPath + ":") -ForegroundColor Yellow
            $extensions | ForEach-Object { Write-Host "      $($_.Name)" -ForegroundColor Yellow }
        }
    }
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Verification Complete" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
