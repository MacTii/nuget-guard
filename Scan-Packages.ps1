# Scan-Packages.ps1
#
# .\Scan-Packages.ps1
# .\Scan-Packages.ps1 -Export CSV
# .\Scan-Packages.ps1 -Export HTML
# .\Scan-Packages.ps1 -Export HTML -OutputFile "C:\reports\my-project"

param(
    [string]$SolutionPath = ".",
    [ValidateSet("None", "CSV", "HTML")]
    [string]$Export = "None",
    [string]$OutputFile = "nuget-report"
)

# ──────────────────────────────────────────────────────────────
# Infrastructure helpers
# ──────────────────────────────────────────────────────────────

function Get-NuGetExe {
    $existing = Get-Command nuget -ErrorAction SilentlyContinue
    if ($existing) { return $existing.Source }

    $cached = Join-Path $env:TEMP "nuget.exe"
    if (-not (Test-Path $cached)) {
        Write-Host "⬇️  Downloading nuget.exe..." -ForegroundColor Cyan
        Invoke-WebRequest `
            -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" `
            -OutFile $cached
    }
    return $cached
}

function Get-SeverityOrder {
    param([string]$Severity)
    switch -Regex ($Severity) {
        "Critical" { 0 }
        "High"     { 1 }
        "Moderate" { 2 }
        "Low"      { 3 }
        default    { 4 }
    }
}

function Get-CategoryOrder {
    param([string]$Category)
    switch ($Category) {
        "Vulnerable" { 0 }
        "Deprecated" { 1 }
        "Outdated"   { 2 }
        default      { 3 }
    }
}

function Get-MaxSeverityForPackage {
    param([object[]]$Results, [string]$Category, [string]$Package)

    ($Results |
        Where-Object { $_.Category -eq $Category -and $_.Package -eq $Package } |
        ForEach-Object { Get-SeverityOrder $_.Severity } |
        Measure-Object -Minimum).Minimum
}

function ConvertTo-TitleCase {
    param([string]$Value)
    if (-not $Value) { return $Value }
    (Get-Culture).TextInfo.ToTitleCase($Value.ToLower())
}

function Get-SeverityLabel {
    param([int]$Value)
    switch ($Value) {
        0 { "Low" }
        1 { "Moderate" }
        2 { "High" }
        3 { "Critical" }
        default { "Unknown" }
    }
}

# Runs `dotnet ... --format json` and returns parsed object or $null.
# Filters out leading "error:" lines from stderr.
function Invoke-DotNetJson {
    param([string[]]$Arguments)

    $raw = & dotnet @Arguments 2>&1

    $errorLines = $raw | Where-Object { $_ -match "^error\s*:" }
    $jsonLines  = $raw | Where-Object { $_ -notmatch "^error\s*:" }

    if ($errorLines -and -not $jsonLines) {
        return [PSCustomObject]@{ Json = $null; HasError = $true }
    }

    $jsonString = ($jsonLines | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($jsonString)) {
        return [PSCustomObject]@{ Json = $null; HasError = $false }
    }

    try {
        return [PSCustomObject]@{
            Json     = ($jsonString | ConvertFrom-Json)
            HasError = $false
        }
    } catch {
        return [PSCustomObject]@{ Json = $null; HasError = $true }
    }
}

# ──────────────────────────────────────────────────────────────
# Package collection helpers
# ──────────────────────────────────────────────────────────────

function Add-PackageReference {
    param(
        [hashtable]$Bag,
        [string]$Id,
        [string]$Version,
        [string]$ProjectName
    )

    if (-not $Id -or -not $Version) { return }

    $key = "$Id|$Version"

    if (-not $Bag.ContainsKey($key)) {
        $Bag[$key] = @{ Id = $Id; Version = $Version; Projects = @() }
    }

    if ($Bag[$key].Projects -notcontains $ProjectName) {
        $Bag[$key].Projects += $ProjectName
    }
}

function Read-ProjectPackages {
    param([System.IO.FileInfo]$Project, [hashtable]$Bag)

    # SDK-style: <PackageReference Include="..." Version="..." />
    [xml]$xml = Get-Content $Project.FullName
    foreach ($ref in $xml.SelectNodes("//PackageReference")) {
        $version = $ref.GetAttribute("Version")
        if ($version -match '\*') { continue }
        Add-PackageReference -Bag $Bag `
            -Id          $ref.GetAttribute("Include") `
            -Version     $version `
            -ProjectName $Project.BaseName
    }

    # Legacy: packages.config
    $cfgPath = Join-Path $Project.DirectoryName "packages.config"
    if (-not (Test-Path $cfgPath)) { return }

    [xml]$cfg = Get-Content $cfgPath
    foreach ($pkg in $cfg.SelectNodes("//package")) {
        Add-PackageReference -Bag $Bag `
            -Id          $pkg.GetAttribute("id") `
            -Version     $pkg.GetAttribute("version") `
            -ProjectName $Project.BaseName
    }
}

function Add-LegacyTransitivePackages {
    param(
        [System.IO.FileInfo[]]$LegacyProjects,
        [string]$PackagesRoot,
        [hashtable]$Bag
    )

    $resolved = Get-ChildItem -Path $PackagesRoot -Directory

    foreach ($legacy in $LegacyProjects) {
        foreach ($folder in $resolved) {
            if ($folder.Name -match '^(?<id>.+?)\.(?<ver>\d+(\.\d+){1,3}(-[\w\.]+)?)$') {
                Add-PackageReference -Bag $Bag `
                    -Id          $Matches.id `
                    -Version     $Matches.ver `
                    -ProjectName $legacy.BaseName
            }
        }
    }
}

# ──────────────────────────────────────────────────────────────
# Result aggregation helpers
# ──────────────────────────────────────────────────────────────

function New-ResultEntry {
    param(
        [string]$Category,
        [string]$Package,
        [string]$Version,
        [string]$Severity,
        [string]$Advisory,
        [string]$Message,
        [string]$Alternative
    )

    [PSCustomObject]@{
        Category    = $Category
        Package     = $Package
        Version     = $Version
        Severity    = $Severity
        Advisory    = $Advisory
        Message     = $Message
        Alternative = $Alternative
        Projects    = [System.Collections.Generic.List[string]]::new()
    }
}

function Add-ProjectToEntry {
    param([PSCustomObject]$Entry, [string[]]$ProjectNames)

    foreach ($p in $ProjectNames) {
        if ($p -and -not $Entry.Projects.Contains($p)) {
            $Entry.Projects.Add($p)
        }
    }
}

function ConvertTo-ResultList {
    param([hashtable]$Map)

    $Map.Values |
        Sort-Object { Get-SeverityOrder $_.Severity } |
        ForEach-Object {
            $_ | Select-Object Category, Package, Version, Severity, Advisory, Message, Alternative,
                @{Name="Projects"; Expression={ $_.Projects -join ", " }}
        }
}

# ──────────────────────────────────────────────────────────────
# Console output helpers
# ──────────────────────────────────────────────────────────────

function Write-ReportItem {
    param(
        [PSCustomObject]$Item,
        [string]$HeaderColor,
        [hashtable]$Fields
    )

    Write-Host "  📦 $($Item.Package) $($Item.Version)" -ForegroundColor $HeaderColor

    foreach ($label in $Fields.Keys) {
        $f = $Fields[$label]
        if ($null -ne $f.Value -and $f.Value -ne "") {
            Write-Host "     $label : $($f.Value)" -ForegroundColor $f.Color
        }
    }
    Write-Host ""
}

# ──────────────────────────────────────────────────────────────
# Find solution
# ──────────────────────────────────────────────────────────────
$solutionFile = Get-ChildItem -Path $SolutionPath -Filter "*.sln" -Recurse |
                Select-Object -First 1

if (-not $solutionFile) {
    Write-Error "No .sln file found."
    exit 1
}

Write-Host "`n🔍 Scanning solution: $($solutionFile.Name)`n" -ForegroundColor Cyan

# ──────────────────────────────────────────────────────────────
# Collect all packages
# ──────────────────────────────────────────────────────────────
$projectFiles = Get-ChildItem -Path $SolutionPath -Filter "*.csproj" -Recurse
$allPackages  = @{}

foreach ($project in $projectFiles) {
    Read-ProjectPackages -Project $project -Bag $allPackages
}

$nugetExe       = Get-NuGetExe
$legacyProjects = $projectFiles | Where-Object {
    Test-Path (Join-Path $_.DirectoryName "packages.config")
}

if ($legacyProjects -and $nugetExe) {

    Write-Host "🔄 Restoring legacy projects via nuget.exe..." -ForegroundColor Cyan
    & $nugetExe restore $solutionFile.FullName -NonInteractive -Verbosity quiet 2>&1 | Out-Null

    $packagesRoot = Join-Path $solutionFile.DirectoryName "packages"

    if (Test-Path $packagesRoot) {
        Add-LegacyTransitivePackages `
            -LegacyProjects $legacyProjects `
            -PackagesRoot   $packagesRoot `
            -Bag            $allPackages
        Write-Host "✅ Added transitive packages from legacy restore`n" -ForegroundColor Green
    } else {
        Write-Host "⚠️  No packages/ folder produced by nuget restore`n" -ForegroundColor Yellow
    }

} elseif ($legacyProjects -and -not $nugetExe) {
    Write-Host "⚠️  Legacy projects detected but nuget.exe not on PATH — transitive deps will be missed.`n" -ForegroundColor Yellow
}

# ──────────────────────────────────────────────────────────────
# NuGet API: deprecation + vulnerability metadata
# ──────────────────────────────────────────────────────────────
Write-Host "🔄 Fetching NuGet metadata..." -ForegroundColor Cyan

$packageList  = $allPackages.Values | ForEach-Object { [PSCustomObject]$_ }
$totalCount   = $packageList.Count
$nugetResults = @()
$seq = 0

foreach ($pkg in $packageList) {

    $seq++
    Write-Progress -Activity "Fetching NuGet metadata" `
        -Status "$($pkg.Id) $($pkg.Version)" `
        -PercentComplete (($seq / $totalCount) * 100)

    $result = [PSCustomObject]@{
        Id                 = $pkg.Id
        Version            = $pkg.Version
        Projects           = $pkg.Projects
        IsDeprecated       = $false
        DeprecatedSeverity = $null
        DeprecationMessage = $null
        AltId              = $null
        AltRange           = $null
        Vulnerabilities    = @()
    }

    try {
        $url = "https://api.nuget.org/v3/registration5-gz-semver2/$($pkg.Id.ToLower())/index.json"
        $reg = Invoke-RestMethod -Uri $url -ErrorAction Stop

        foreach ($page in $reg.items) {
            $items = $page.items
            if (-not $items) {
                $pd    = Invoke-RestMethod -Uri $page.'@id' -ErrorAction SilentlyContinue
                $items = $pd.items
            }
            foreach ($item in $items) {
                if ($item.catalogEntry.version -ne $pkg.Version) { continue }

                $entry = $item.catalogEntry

                if ($null -ne $entry.deprecation) {
                    $result.IsDeprecated       = $true
                    $result.DeprecatedSeverity = ($entry.deprecation.reasons -join ", ")
                    $result.DeprecationMessage = $entry.deprecation.message
                    $result.AltId              = $entry.deprecation.alternatePackage.id
                    $result.AltRange           = $entry.deprecation.alternatePackage.range
                }

                if ($entry.vulnerabilities -and $entry.vulnerabilities.Count -gt 0) {
                    $result.Vulnerabilities = foreach ($v in $entry.vulnerabilities) {
                        [PSCustomObject]@{
                            Severity    = (Get-SeverityLabel -Value ([int]$v.severity))
                            AdvisoryUrl = $v.advisoryUrl
                        }
                    }
                }
                break
            }
        }
    } catch {}

    $nugetResults += $result
}

Write-Progress -Completed -Activity "Fetching NuGet metadata"
Write-Host "✅ Metadata fetched for $totalCount packages`n" -ForegroundColor Green

# ──────────────────────────────────────────────────────────────
# 1. Vulnerable Packages
# ──────────────────────────────────────────────────────────────
Write-Host "━━━ 🚨 VULNERABLE PACKAGES ━━━" -ForegroundColor Red

$vulnerableMap   = @{}
$skippedProjects = @()

# Single solution-level call — much faster than per-project loop.
# Invoke-DotNetJson strips "error:" lines so legacy project failures
# don't break parsing for the rest.
$parsed = Invoke-DotNetJson -Arguments @(
    "list", $solutionFile.FullName, "package",
    "--vulnerable", "--include-transitive", "--format", "json"
)

if ($parsed.HasError -and -not $parsed.Json) {

    Write-Host "ℹ️  Solution-level vulnerable scan failed, falling back to per-project..." -ForegroundColor DarkGray

    foreach ($project in $projectFiles) {

        $perProj = Invoke-DotNetJson -Arguments @(
            "list", $project.FullName, "package",
            "--vulnerable", "--include-transitive", "--format", "json"
        )

        if ($perProj.HasError) { $skippedProjects += $project.BaseName; continue }
        if (-not $perProj.Json) { continue }

        if (-not $parsed.Json) {
            $parsed = [PSCustomObject]@{ Json = $perProj.Json; HasError = $false }
        } else {
            $parsed.Json.projects += $perProj.Json.projects
        }
    }
}

if ($parsed.Json) {
    foreach ($proj in $parsed.Json.projects) {

        $projectName = [System.IO.Path]::GetFileNameWithoutExtension($proj.path)

        foreach ($framework in $proj.frameworks) {

            $allPkgs = @($framework.topLevelPackages) + @($framework.transitivePackages)

            foreach ($pkg in $allPkgs) {
                if (-not $pkg.vulnerabilities) { continue }

                foreach ($v in $pkg.vulnerabilities) {

                    $severity = ConvertTo-TitleCase $v.severity
                    $key      = "$($pkg.id)|$($pkg.resolvedVersion)|$severity"

                    if (-not $vulnerableMap.ContainsKey($key)) {
                        $vulnerableMap[$key] = New-ResultEntry `
                            -Category "Vulnerable" `
                            -Package  $pkg.id `
                            -Version  $pkg.resolvedVersion `
                            -Severity $severity `
                            -Advisory $v.advisoryUrl
                    }
                    Add-ProjectToEntry -Entry $vulnerableMap[$key] -ProjectNames @($projectName)
                }
            }
        }
    }
}

if ($skippedProjects.Count -gt 0) {
    Write-Host "⚠️  Skipped (build/restore failed): $($skippedProjects -join ', ')" -ForegroundColor Yellow
}

foreach ($r in $nugetResults) {
    foreach ($vuln in $r.Vulnerabilities) {

        $severity = ConvertTo-TitleCase $vuln.Severity
        $key      = "$($r.Id)|$($r.Version)|$severity"

        if (-not $vulnerableMap.ContainsKey($key)) {
            $vulnerableMap[$key] = New-ResultEntry `
                -Category "Vulnerable" `
                -Package  $r.Id `
                -Version  $r.Version `
                -Severity $severity `
                -Advisory $vuln.AdvisoryUrl
        }
        Add-ProjectToEntry -Entry $vulnerableMap[$key] -ProjectNames $r.Projects
    }
}

$vulnerableList = ConvertTo-ResultList -Map $vulnerableMap

if ($vulnerableList) {
    foreach ($item in $vulnerableList) {
        $color = switch ($item.Severity) {
            "Critical" { "Red" }
            "High"     { "DarkRed" }
            "Moderate" { "Yellow" }
            default    { "White" }
        }
        Write-ReportItem -Item $item -HeaderColor $color -Fields ([ordered]@{
            "Severity" = @{ Value = $item.Severity; Color = $color }
            "Advisory" = @{ Value = $item.Advisory; Color = "Gray" }
            "Projects" = @{ Value = $item.Projects; Color = "DarkGray" }
        })
    }
} else {
    Write-Host "✅ No vulnerable packages found." -ForegroundColor Green
}

# ──────────────────────────────────────────────────────────────
# 2. Deprecated Packages
# ──────────────────────────────────────────────────────────────
Write-Host "`n━━━ ⚠️ DEPRECATED PACKAGES ━━━" -ForegroundColor Yellow

$deprecatedList = $nugetResults |
    Where-Object { $_.IsDeprecated } |
    ForEach-Object {
        [PSCustomObject]@{
            Category    = "Deprecated"
            Package     = $_.Id
            Version     = $_.Version
            Severity    = $_.DeprecatedSeverity
            Advisory    = $null
            Message     = $_.DeprecationMessage
            Alternative = if ($_.AltId) { "$($_.AltId) $($_.AltRange)" } else { $null }
            Projects    = ($_.Projects | Select-Object -Unique) -join ", "
        }
    } |
    Sort-Object { Get-SeverityOrder $_.Severity }

if ($deprecatedList.Count -eq 0) {
    Write-Host "✅ No deprecated packages found." -ForegroundColor Green
} else {
    foreach ($item in $deprecatedList) {
        Write-ReportItem -Item $item -HeaderColor "Red" -Fields ([ordered]@{
            "Severity   " = @{ Value = $item.Severity;    Color = "Yellow"   }
            "Message    " = @{ Value = $item.Message;     Color = "Gray"     }
            "Alternative" = @{ Value = $item.Alternative; Color = "Cyan"     }
            "Projects   " = @{ Value = $item.Projects;    Color = "DarkGray" }
        })
    }
}

# ──────────────────────────────────────────────────────────────
# 3. Outdated Packages
# ──────────────────────────────────────────────────────────────
Write-Host "`n━━━ 📦 OUTDATED PACKAGES ━━━" -ForegroundColor Blue

$outdatedList   = @()
$outdatedErrors = $null

$parsed = Invoke-DotNetJson -Arguments @("package", "list", "--outdated", "--format", "json")

if ($parsed.HasError) {
    $outdatedErrors = $true
}
elseif ($parsed.Json) {

    $outdatedMap = @{}

    foreach ($proj in $parsed.Json.projects) {

        $projectName = [System.IO.Path]::GetFileNameWithoutExtension($proj.path)

        foreach ($framework in $proj.frameworks) {
            foreach ($pkg in $framework.topLevelPackages) {

                if (-not $pkg.latestVersion -or $pkg.resolvedVersion -eq $pkg.latestVersion) { continue }

                $key = "$($pkg.id)|$($pkg.resolvedVersion)"

                if (-not $outdatedMap.ContainsKey($key)) {
                    $outdatedMap[$key] = New-ResultEntry `
                        -Category "Outdated" `
                        -Package  $pkg.id `
                        -Version  $pkg.resolvedVersion `
                        -Severity "Latest: $($pkg.latestVersion)"
                }
                Add-ProjectToEntry -Entry $outdatedMap[$key] -ProjectNames @($projectName)
            }
        }
    }

    $outdatedList = ConvertTo-ResultList -Map $outdatedMap
}

if ($outdatedErrors) {
    Write-Host "⚠️ Outdated scan failed." -ForegroundColor Yellow
}
elseif ($outdatedList.Count -gt 0) {
    foreach ($item in $outdatedList) {
        Write-ReportItem -Item $item -HeaderColor "DarkCyan" -Fields ([ordered]@{
            ""         = @{ Value = $item.Severity; Color = "Cyan"     }
            "Projects" = @{ Value = $item.Projects; Color = "DarkGray" }
        })
    }
} else {
    Write-Host "✅ All packages are up to date." -ForegroundColor Green
}

# ──────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────
Write-Host "`n━━━ 📊 SUMMARY ━━━" -ForegroundColor Cyan

Write-Host "  Vulnerable : $(if ($vulnerableList) { '🚨 ' + @($vulnerableList).Count } else { '✅ 0' })"
Write-Host "  Deprecated : $(if (@($deprecatedList).Count -gt 0) { '⚠️ ' + @($deprecatedList).Count } else { '✅ 0' })"

if ($outdatedErrors) {
    Write-Host "  Outdated   : ⚠️  scan failed (build errors)" -ForegroundColor Yellow
} else {
    Write-Host "  Outdated   : $(if ($outdatedList) { '📦 ' + @($outdatedList).Count } else { '✅ 0' })"
}

# ──────────────────────────────────────────────────────────────
# Export
# ──────────────────────────────────────────────────────────────
if ($Export -eq "None") { exit 0 }

if ($Export -eq "CSV") {
    $csvFlat = @($vulnerableList) + @($deprecatedList) + @($outdatedList)
    $csvAll  = $csvFlat |
        Sort-Object `
            @{ Expression = { Get-CategoryOrder $_.Category } },
            @{ Expression = { Get-MaxSeverityForPackage -Results $csvFlat -Category $_.Category -Package $_.Package } },
            Package,
            @{ Expression = { Get-SeverityOrder $_.Severity } }

    $csvPath = "$OutputFile.csv"
    $csvAll | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n💾 CSV saved: $csvPath" -ForegroundColor Green
    exit 0
}

# ── HTML export ───────────────────────────────────────────────
function Format-Cell {
    param($Value, [bool]$IsLink = $false)
    if (-not $Value) { return "—" }
    if ($IsLink)     { return "<a href='$Value' target='_blank'>Open</a>" }
    [System.Web.HttpUtility]::HtmlEncode($Value)
}

function Get-CategoryColor {
    param([string]$Category)
    switch ($Category) {
        "Vulnerable" { "#e74c3c" }
        "Deprecated" { "#e67e22" }
        "Outdated"   { "#3498db" }
    }
}

function Get-SeverityColor {
    param([string]$Severity)
    switch -Regex ($Severity) {
        "Critical" { "#e74c3c" }
        "High"     { "#c0392b" }
        "Moderate" { "#e67e22" }
        default    { "#555" }
    }
}

$htmlPath    = "$OutputFile.html"
$generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm"

# Sort: Category → MaxSeverityInPackage → Package name → Severity within package
$flatResults = @($vulnerableList) + @($deprecatedList) + @($outdatedList)

$allResults = $flatResults |
    Sort-Object `
        @{ Expression = { Get-CategoryOrder $_.Category } },
        @{ Expression = { Get-MaxSeverityForPackage -Results $flatResults -Category $_.Category -Package $_.Package } },
        Package,
        @{ Expression = { Get-SeverityOrder $_.Severity } }

# Group consecutive rows by (Category, Package) using rowspan
$groupCounts = @{}
foreach ($r in $allResults) {
    $gk = "$($r.Category)|$($r.Package)"
    if (-not $groupCounts.ContainsKey($gk)) { $groupCounts[$gk] = 0 }
    $groupCounts[$gk]++
}

$seenGroups = @{}

$rows = $allResults | ForEach-Object {

    $badgeColor    = Get-CategoryColor $_.Category
    $severityColor = Get-SeverityColor $_.Severity
    $groupKey      = "$($_.Category)|$($_.Package)"

    if (-not $seenGroups.ContainsKey($groupKey)) {
        $seenGroups[$groupKey] = $true
        $rowspan     = $groupCounts[$groupKey]
        $badgeCell   = "<td rowspan='$rowspan' class='pkg-cell'><span class='badge' style='background:$badgeColor'>$($_.Category)</span></td>"
        $packageCell = "<td rowspan='$rowspan' class='pkg-cell'><strong>$($_.Package)</strong></td>"
        $rowClass    = "group-start"
    } else {
        $badgeCell   = ""
        $packageCell = ""
        $rowClass    = "group-cont"
    }

@"
<tr class='$rowClass'>
$badgeCell
$packageCell
<td><code>$($_.Version)</code></td>
<td style='color:$severityColor;font-weight:600'>$($_.Severity)</td>
<td>$(Format-Cell $_.Advisory -IsLink $true)</td>
<td>$(Format-Cell $_.Message)</td>
<td>$(Format-Cell $_.Alternative)</td>
<td class='projects'>$($_.Projects)</td>
</tr>
"@
}

$outdatedNote = if ($outdatedErrors) {
    "<div class='build-error'>⚠️ Outdated scan incomplete — fix build errors and re-run.</div>"
} else { "" }

$outdatedNum = if ($outdatedErrors) { "?" } else { @($outdatedList).Count }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NuGet Package Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Segoe UI,sans-serif;background:#f0f2f5;padding:2rem;color:#333}
h1{font-size:1.7rem;margin-bottom:.25rem}
.sub{color:#888;margin-bottom:1.5rem}
.summary{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}
.card{background:#fff;border-radius:10px;padding:1rem 1.5rem;box-shadow:0 1px 4px rgba(0,0,0,.08);flex:1;min-width:140px;text-align:center}
.num{font-size:2.2rem;font-weight:700}
.lbl{font-size:.8rem;color:#888;margin-top:.25rem}
.build-error{background:#fff8e1;border:1px solid #ffe082;border-radius:8px;padding:.75rem 1rem;margin-bottom:1rem;color:#7a5f00;font-size:.88rem}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)}
th{background:#2c3e50;color:#fff;padding:.75rem 1rem;text-align:left;font-size:.8rem;text-transform:uppercase}
td{padding:.65rem 1rem;border-bottom:1px solid #f0f0f0;font-size:.88rem;vertical-align:top}
tr:hover td:not(.pkg-cell){background:#fafafa}
.group-start td{border-top:2px solid #d0d7de}
.pkg-cell{background:#fafbfc;border-right:1px solid #eaecef}
.badge{display:inline-block;padding:.2rem .65rem;border-radius:20px;color:#fff;font-size:.72rem;font-weight:600}
.projects{color:#999;font-size:.78rem}
code{background:#f4f4f4;padding:.1rem .4rem;border-radius:4px}
a{text-decoration:none;color:#3498db}
</style>
</head>
<body>

<h1>📦 NuGet Package Report</h1>
<p class="sub">Solution: <strong>$($solutionFile.Name)</strong> &nbsp;|&nbsp; Generated: $generatedAt</p>

<div class="summary">
<div class="card"><div class="num" style="color:#e74c3c">$(@($vulnerableList).Count)</div><div class="lbl">Vulnerable</div></div>
<div class="card"><div class="num" style="color:#e67e22">$(@($deprecatedList).Count)</div><div class="lbl">Deprecated</div></div>
<div class="card"><div class="num" style="color:#3498db">$outdatedNum</div><div class="lbl">Outdated</div></div>
</div>

$outdatedNote

<table>
<thead>
<tr><th>Category</th><th>Package</th><th>Version</th><th>Severity</th><th>Advisory</th><th>Message</th><th>Alternative</th><th>Projects</th></tr>
</thead>
<tbody>
$($rows -join "`n")
</tbody>
</table>

</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "`n💾 HTML saved: $htmlPath" -ForegroundColor Green
Start-Process $htmlPath