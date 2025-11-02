# Show git changes summary for the current project
# Automatically detects which project (SecureApp or QuantFramework) and shows changes
# Works with symlinked configuration files - git tracks changes normally

$ProjectDir = Split-Path -Leaf (Get-Location)
$ProjectRoot = Get-Location

# Check if we're in a git repository
try {
    $null = git rev-parse --git-dir 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Not in a git repository" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Error: Not in a git repository" -ForegroundColor Red
    exit 1
}

# Detect if config files are symlinks (for informational purposes)
$ConfigSymlinkInfo = @()
if (Test-Path ".cursorrules") {
    $item = Get-Item ".cursorrules"
    if ($item.LinkType -eq "SymbolicLink") {
        $target = $item.Target
        $ConfigSymlinkInfo += "  • .cursorrules → $target"
    }
}
if (Test-Path ".vscode/settings.json") {
    $item = Get-Item ".vscode/settings.json"
    if ($item.LinkType -eq "SymbolicLink") {
        $target = $item.Target
        $ConfigSymlinkInfo += "  • .vscode/settings.json → $target"
    }
}

$ProjectName = $ProjectDir

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Changes Summary: $ProjectName" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Project Directory: $ProjectRoot" -ForegroundColor Gray
if ($ConfigSymlinkInfo.Count -gt 0) {
    Write-Host ""
    Write-Host "Shared configuration files (symlinks):" -ForegroundColor DarkGray
    foreach ($info in $ConfigSymlinkInfo) {
        Write-Host $info -ForegroundColor DarkGray
    }
}
Write-Host ""

# Check for changes
$Modified = git diff --name-only 2>$null
$Untracked = git ls-files --others --exclude-standard 2>$null

if ([string]::IsNullOrEmpty($Modified) -and [string]::IsNullOrEmpty($Untracked)) {
    Write-Host "No changes since last commit" -ForegroundColor Green
    Write-Host ""
    exit 0
}

# Modified files
if (-not [string]::IsNullOrEmpty($Modified)) {
    Write-Host "## Modified Files" -ForegroundColor Yellow
    Write-Host ""
    git diff --stat
    Write-Host ""
}

# New untracked files
if (-not [string]::IsNullOrEmpty($Untracked)) {
    Write-Host "## New Files" -ForegroundColor Yellow
    Write-Host ""
    $Untracked | ForEach-Object {
        Write-Host "  + $_" -ForegroundColor Green
    }
    Write-Host ""
}

# File count summary
$ModifiedCount = if ($Modified) { ($Modified -split "`n").Count } else { 0 }
$UntrackedCount = if ($Untracked) { ($Untracked -split "`n").Count } else { 0 }
$TotalCount = $ModifiedCount + $UntrackedCount

Write-Host "## Automatic Summary" -ForegroundColor Yellow
Write-Host ""
Write-Host "**Total Changes:** $TotalCount files ($ModifiedCount modified, $UntrackedCount new)" -ForegroundColor White
Write-Host ""

# Combine all files for analysis
$AllFiles = @()
if ($Modified) { $AllFiles += $Modified -split "`n" | Where-Object { $_ -ne "" } }
if ($Untracked) { $AllFiles += $Untracked -split "`n" | Where-Object { $_ -ne "" } }

if ($AllFiles.Count -gt 0) {
    # Count by file type
    $PythonFiles = ($AllFiles | Where-Object { $_ -match '\.py$' }).Count
    $ConfigFiles = ($AllFiles | Where-Object { $_ -match '\.(toml|yaml|yml|json|ini|cfg)$' }).Count
    $DocFiles = ($AllFiles | Where-Object { $_ -match '\.(md|txt|rst)$' }).Count
    $ScriptFiles = ($AllFiles | Where-Object { $_ -match '\.(sh|ps1|bat)$' }).Count
    $TestFiles = ($AllFiles | Where-Object { $_ -match '(test_|/test)' }).Count
    $ConfigDirFiles = ($AllFiles | Where-Object { $_ -match '(^\.|config/|\.cursor)' }).Count

    $Categories = @()
    if ($PythonFiles -gt 0) { $Categories += "  • Python files: $PythonFiles" }
    if ($TestFiles -gt 0) { $Categories += "  • Test files: $TestFiles" }
    if ($ConfigFiles -gt 0) { $Categories += "  • Config files: $ConfigFiles" }
    if ($ConfigDirFiles -gt 0) { $Categories += "  • Configuration/root files: $ConfigDirFiles" }
    if ($DocFiles -gt 0) { $Categories += "  • Documentation: $DocFiles" }
    if ($ScriptFiles -gt 0) { $Categories += "  • Scripts: $ScriptFiles" }

    if ($Categories.Count -gt 0) {
        Write-Host "**By Category:**" -ForegroundColor White
        foreach ($cat in $Categories) {
            Write-Host $cat
        }
        Write-Host ""
    }

    # Analyze code changes (lines added/removed) - for commit message
    $LinesAdded = 0
    $LinesRemoved = 0
    $NetChanges = 0

    if ($ModifiedCount -gt 0) {
        $NumStat = git diff --numstat 2>$null

        if ($NumStat) {
            $NumStat -split "`n" | ForEach-Object {
                if ($_ -match '^(\d+)\s+(\d+)') {
                    $LinesAdded += [int]$matches[1]
                    $LinesRemoved += [int]$matches[2]
                }
            }
        }

        $NetChanges = $LinesAdded - $LinesRemoved

        Write-Host "**Code Changes:**" -ForegroundColor White
        Write-Host "  • Lines added: $LinesAdded"
        Write-Host "  • Lines removed: $LinesRemoved"
        if ($NetChanges -gt 0) {
            Write-Host "  • Net change: +$NetChanges lines" -ForegroundColor Green
        } elseif ($NetChanges -lt 0) {
            Write-Host "  • Net change: $NetChanges lines" -ForegroundColor Yellow
        } else {
            Write-Host "  • Net change: 0 lines"
        }
        Write-Host ""
    }

    # Generate commit message summary
    Write-Host "## Suggested Commit Message" -ForegroundColor Yellow
    Write-Host ""

    $ChangeTypes = @()
    $CommitBodyParts = @()

    # Detect config file changes (works with symlinks)
    if ($AllFiles | Where-Object { $_ -match '\.cursorrules|\.editorconfig|\.vscode/settings\.json' }) {
        $ChangeTypes += "config"
        $ConfigChanged = @()
        if ($AllFiles | Where-Object { $_ -match '\.cursorrules' }) {
            $ConfigChanged += "Cursor rules"
        }
        if ($AllFiles | Where-Object { $_ -match '\.editorconfig' }) {
            $ConfigChanged += "Editor config"
        }
        if ($AllFiles | Where-Object { $_ -match '\.vscode/settings\.json' }) {
            $ConfigChanged += "VS Code settings"
        }
        if ($ConfigChanged.Count -gt 0) {
            $CommitBodyParts += "- Update shared configuration: $($ConfigChanged -join ', ')"
            $CommitBodyParts += "  (Note: Changes apply to all projects using master config)"
        }
    }
    if ($AllFiles | Where-Object { $_ -match '(verify_|guide)' }) {
        $ChangeTypes += "docs"
        $CommitBodyParts += "- Add verification scripts and documentation"
    }
    if ($AllFiles | Where-Object { $_ -match '(test_|/test)' }) {
        $ChangeTypes += "test"
        $CommitBodyParts += "- Update test suite"
    }
    if ($AllFiles | Where-Object { $_ -match '\.py$' -and ($_ -match '(app/|src/|trading/)') }) {
        $ChangeTypes += "feat"
        $CommitBodyParts += "- Update application code"
    }
    if ($AllFiles | Where-Object { $_ -match '(requirements|pyproject|setup\.py)' }) {
        $ChangeTypes += "build"
        $CommitBodyParts += "- Update dependencies/package configuration"
    }
    if ($AllFiles | Where-Object { $_ -match '\.(sh|ps1|py)$' -and $_ -notmatch 'test' }) {
        $ChangeTypes += "chore"
        $CommitBodyParts += "- Add utility scripts"
    }

    # Determine primary type (prioritize feat > fix > docs > test > build > chore)
    $TypePriority = @{"feat" = 1; "fix" = 2; "docs" = 3; "test" = 4; "build" = 5; "chore" = 6}
    $CommitType = "chore"
    foreach ($ct in $ChangeTypes) {
        if ($TypePriority.ContainsKey($ct) -and $TypePriority[$ct] -lt $TypePriority[$CommitType]) {
            $CommitType = $ct
        }
    }

    # Build subject line
    if ($TotalCount -eq 1) {
        if ($UntrackedCount -eq 1) {
            $FileName = Split-Path -Leaf $AllFiles[0]
            $CommitSubject = "add $FileName"
        } else {
            $FileName = Split-Path -Leaf $AllFiles[0]
            $CommitSubject = "update $FileName"
        }
    } elseif ($PythonFiles -gt 0 -and $PythonFiles -eq $TotalCount) {
        $CommitSubject = "update Python code"
    } elseif ($ScriptFiles -gt 0) {
        $CommitSubject = "add utility scripts"
    } elseif ($DocFiles -gt 0 -and $DocFiles -eq $TotalCount) {
        $CommitSubject = "update documentation"
    } elseif ($ConfigFiles -gt 0) {
        $CommitSubject = "update configuration"
    } else {
        $CommitSubject = "update project files"
    }

    # Output commit message format
    Write-Host "```" -ForegroundColor Gray
    Write-Host "$CommitType`: $CommitSubject" -ForegroundColor White
    Write-Host ""

    if ($CommitBodyParts.Count -gt 0) {
        foreach ($part in $CommitBodyParts) {
            Write-Host $part
        }
        Write-Host ""
    }

    Write-Host "Files changed: $TotalCount ($ModifiedCount modified, $UntrackedCount new)"

    if ($ModifiedCount -gt 0) {
        Write-Host "Lines: +$LinesAdded/-$LinesRemoved (net: $NetChanges)"
    }

    Write-Host "```" -ForegroundColor Gray
    Write-Host ""
}

# Option to show detailed diff (skip if non-interactive)
$IsInteractive = [Environment]::UserInteractive -and $Host.UI.RawUI.KeyAvailable
if (-not [string]::IsNullOrEmpty($Modified) -and $IsInteractive) {
    $ShowDiff = Read-Host "Show detailed diff? (y/n)"
    if ($ShowDiff -eq "y" -or $ShowDiff -eq "Y") {
        git diff
    }
} elseif (-not [string]::IsNullOrEmpty($Modified) -and -not $IsInteractive) {
    # Non-interactive mode - provide hint
    Write-Host ""
    Write-Host "Run 'git diff' to see detailed changes" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
