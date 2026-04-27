# Scan-Packages.ps1

# Console only (default)
#.\Scan-Packages.ps1

# Export to CSV
#.\Scan-Packages.ps1 -Export CSV

# Export to HTML (opens automatically in browser)
#.\Scan-Packages.ps1 -Export HTML

# Custom file name
#.\Scan-Packages.ps1 -Export HTML -OutputFile "C:\reports\my-project"

param(
    [string]$SolutionPath = ".",
    [ValidateSet("None", "CSV", "HTML")]
    [string]$Export = "None",
    [string]$OutputFile = "nuget-report"
)

# ── Severity helpers ───────────────────────────────────────────
function Get-SeverityOrder {
    param([string]$Severity)
    switch -Regex ($Severity) {
        "Critical" { return 0 }
        "High"     { return 1 }
        "Moderate" { return 2 }
        "Low"      { return 3 }
        default    { return 4 }
    }
}

function ConvertTo-TitleCase {
    param([string]$Value)
    if (-not $Value) { return $Value }
    return (Get-Culture).TextInfo.ToTitleCase($Value.ToLower())
}

function Get-SeverityLabel {
    param([int]$Value)
    switch ($Value) {
        0 { return "Low" }
        1 { return "Moderate" }
        2 { return "High" }
        3 { return "Critical" }
        default { return "Unknown" }
    }
}

# ── Find solution ──────────────────────────────────────────────
$solutionFile = Get-ChildItem -Path $SolutionPath -Filter "*.sln" -Recurse | Select-Object -First 1

if (-not $solutionFile) {
    Write-Error "No .sln file found."
    exit 1
}

Write-Host "`n🔍 Scanning solution: $($solutionFile.Name)`n" -ForegroundColor Cyan

# ──────────────────────────────────────────────────────────────
# Collect all packages — PackageReference + packages.config
# ──────────────────────────────────────────────────────────────
$projectFiles = Get-ChildItem -Path $SolutionPath -Filter "*.csproj" -Recurse
$allPackages  = @{}

foreach ($project in $projectFiles) {

    # ── SDK-style: <PackageReference> ──
    [xml]$xml = Get-Content $project.FullName

    foreach ($reference in $xml.SelectNodes("//PackageReference")) {

        $packageId = $reference.GetAttribute("Include")
        $version   = $reference.GetAttribute("Version")

        if ($packageId -and $version -and $version -notmatch '\*') {

            $key = "$packageId|$version"

            if (-not $allPackages.ContainsKey($key)) {
                $allPackages[$key] = @{ Id = $packageId; Version = $version; Projects = @() }
            }

            if ($allPackages[$key].Projects -notcontains $project.BaseName) {
                $allPackages[$key].Projects += $project.BaseName
            }
        }
    }

    # ── Legacy: packages.config ──
    $packagesConfig = Join-Path $project.DirectoryName "packages.config"

    if (Test-Path $packagesConfig) {

        [xml]$cfg = Get-Content $packagesConfig

        foreach ($pkg in $cfg.SelectNodes("//package")) {

            $packageId = $pkg.GetAttribute("id")
            $version   = $pkg.GetAttribute("version")

            if ($packageId -and $version) {

                $key = "$packageId|$version"

                if (-not $allPackages.ContainsKey($key)) {
                    $allPackages[$key] = @{ Id = $packageId; Version = $version; Projects = @() }
                }

                if ($allPackages[$key].Projects -notcontains $project.BaseName) {
                    $allPackages[$key].Projects += $project.BaseName
                }
            }
        }
    }
}

# ──────────────────────────────────────────────────────────────
# Single NuGet API pass — fetch vulnerability + deprecation
# for all packages in parallel
# ──────────────────────────────────────────────────────────────
Write-Host "🔄 Fetching NuGet metadata..." -ForegroundColor Cyan

$packageList  = $allPackages.Values | ForEach-Object { [PSCustomObject]$_ }
$totalCount   = $packageList.Count

# ForEach-Object -Parallel requires PowerShell 7+
# Falls back to sequential on PS 5.x
$psVersion = $PSVersionTable.PSVersion.Major

if ($psVersion -ge 7) {

    $nugetResults = $packageList | ForEach-Object -Parallel {

        $pkg = $_

        function Get-SeverityLabel-Inner {
            param([int]$v)
            switch ($v) { 0{"Low"} 1{"Moderate"} 2{"High"} 3{"Critical"} default{"Unknown"} }
        }

        $result = [PSCustomObject]@{
            Id               = $pkg.Id
            Version          = $pkg.Version
            Projects         = $pkg.Projects
            IsDeprecated     = $false
            DeprecatedSeverity = $null
            DeprecationMessage = $null
            AltId            = $null
            AltRange         = $null
            Vulnerabilities  = @()
        }

        try {
            $url  = "https://api.nuget.org/v3/registration5-gz-semver2/$($pkg.Id.ToLower())/index.json"
            $reg  = Invoke-RestMethod -Uri $url -ErrorAction Stop

            foreach ($page in $reg.items) {
                $items = $page.items
                if (-not $items) {
                    $pd = Invoke-RestMethod -Uri $page.'@id' -ErrorAction SilentlyContinue
                    $items = $pd.items
                }
                foreach ($item in $items) {
                    if ($item.catalogEntry.version -eq $pkg.Version) {
                        $entry = $item.catalogEntry

                        if ($null -ne $entry.deprecation) {
                            $result.IsDeprecated       = $true
                            $result.DeprecatedSeverity = ($entry.deprecation.reasons -join ", ")
                            $result.DeprecationMessage = $entry.deprecation.message
                            $result.AltId              = $entry.deprecation.alternatePackage.id
                            $result.AltRange           = $entry.deprecation.alternatePackage.range
                        }

                        if ($null -ne $entry.vulnerabilities -and $entry.vulnerabilities.Count -gt 0) {
                            $vulns = @()
                            foreach ($v in $entry.vulnerabilities) {
                                $vulns += [PSCustomObject]@{
                                    Severity    = (Get-SeverityLabel-Inner -v ([int]$v.severity))
                                    AdvisoryUrl = $v.advisoryUrl
                                }
                            }
                            $result.Vulnerabilities = $vulns
                        }

                        break
                    }
                }
            }
        } catch {}

        $result

    } -ThrottleLimit 20

} else {

    # Sequential fallback for PS 5.x
    $nugetResults = @()
    $seq = 0

    foreach ($pkg in $packageList) {

        $seq++
        Write-Progress `
            -Activity "Fetching NuGet metadata" `
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
                    if ($item.catalogEntry.version -eq $pkg.Version) {
                        $entry = $item.catalogEntry

                        if ($null -ne $entry.deprecation) {
                            $result.IsDeprecated       = $true
                            $result.DeprecatedSeverity = ($entry.deprecation.reasons -join ", ")
                            $result.DeprecationMessage = $entry.deprecation.message
                            $result.AltId              = $entry.deprecation.alternatePackage.id
                            $result.AltRange           = $entry.deprecation.alternatePackage.range
                        }

                        if ($null -ne $entry.vulnerabilities -and $entry.vulnerabilities.Count -gt 0) {
                            $vulns = @()
                            foreach ($v in $entry.vulnerabilities) {
                                $vulns += [PSCustomObject]@{
                                    Severity    = (Get-SeverityLabel -Value ([int]$v.severity))
                                    AdvisoryUrl = $v.advisoryUrl
                                }
                            }
                            $result.Vulnerabilities = $vulns
                        }

                        break
                    }
                }
            }
        } catch {}

        $nugetResults += $result
    }

    Write-Progress -Completed -Activity "Fetching NuGet metadata"
}

Write-Host "✅ Metadata fetched for $totalCount packages`n" -ForegroundColor Green

# ──────────────────────────────────────────────────────────────
# 1. Vulnerable Packages
# ──────────────────────────────────────────────────────────────
Write-Host "━━━ 🚨 VULNERABLE PACKAGES ━━━" -ForegroundColor Red

# SDK-style: dotnet CLI (for PackageReference projects)
$vulnerableMap = @{}

try {
    $jsonRaw = dotnet list $solutionFile.FullName package --vulnerable --format json 2>&1
    $json = $jsonRaw | Out-String | ConvertFrom-Json

    foreach ($proj in $json.projects) {

        $projectName = [System.IO.Path]::GetFileNameWithoutExtension($proj.path)

        foreach ($framework in $proj.frameworks) {
            foreach ($pkg in $framework.topLevelPackages) {

                if ($pkg.vulnerabilities -and $pkg.vulnerabilities.Count -gt 0) {

                    foreach ($v in $pkg.vulnerabilities) {

                        $severity = ConvertTo-TitleCase $v.severity
                        $key = "$($pkg.id)|$($pkg.resolvedVersion)|$severity"

                        if (-not $vulnerableMap.ContainsKey($key)) {
                            $vulnerableMap[$key] = [PSCustomObject]@{
                                Category    = "Vulnerable"
                                Package     = $pkg.id
                                Version     = $pkg.resolvedVersion
                                Severity    = $severity
                                Advisory    = $v.advisoryUrl
                                Message     = $null
                                Alternative = $null
                                Projects    = [System.Collections.Generic.List[string]]::new()
                            }
                        }

                        if (-not $vulnerableMap[$key].Projects.Contains($projectName)) {
                            $vulnerableMap[$key].Projects.Add($projectName)
                        }
                    }
                }
            }
        }
    }

} catch {
    Write-Host "⚠️ Failed to parse vulnerable JSON output" -ForegroundColor Yellow
}

# Legacy + any missed: NuGet API results
foreach ($r in $nugetResults) {
    foreach ($vuln in $r.Vulnerabilities) {

        $severity = ConvertTo-TitleCase $vuln.Severity
        $key      = "$($r.Id)|$($r.Version)|$severity"

        if (-not $vulnerableMap.ContainsKey($key)) {
            $vulnerableMap[$key] = [PSCustomObject]@{
                Category    = "Vulnerable"
                Package     = $r.Id
                Version     = $r.Version
                Severity    = $severity
                Advisory    = $vuln.AdvisoryUrl
                Message     = $null
                Alternative = $null
                Projects    = [System.Collections.Generic.List[string]]::new()
            }
        }

        foreach ($proj in $r.Projects) {
            if (-not $vulnerableMap[$key].Projects.Contains($proj)) {
                $vulnerableMap[$key].Projects.Add($proj)
            }
        }
    }
}

$vulnerableList = $vulnerableMap.Values |
    Sort-Object { Get-SeverityOrder $_.Severity } |
    ForEach-Object {
        $_ | Select-Object Category, Package, Version, Severity, Advisory, Message, Alternative,
            @{Name="Projects"; Expression={ $_.Projects -join ", " }}
    }

if ($vulnerableList) {

    foreach ($item in $vulnerableList) {

        $color = switch ($item.Severity) {
            "Critical" { "Red" }
            "High"     { "DarkRed" }
            "Moderate" { "Yellow" }
            default    { "White" }
        }

        Write-Host "  📦 $($item.Package) $($item.Version)" -ForegroundColor $color
        Write-Host "     Severity : $($item.Severity)" -ForegroundColor $color
        Write-Host "     Advisory : $($item.Advisory)" -ForegroundColor Gray
        Write-Host "     Projects : $($item.Projects)" -ForegroundColor DarkGray
        Write-Host ""
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

        Write-Host "  📦 $($item.Package) $($item.Version)" -ForegroundColor Red
        Write-Host "     Severity    : $($item.Severity)" -ForegroundColor Yellow

        if ($item.Message) {
            Write-Host "     Message     : $($item.Message)" -ForegroundColor Gray
        }

        if ($item.Alternative) {
            Write-Host "     Alternative : $($item.Alternative)" -ForegroundColor Cyan
        }

        Write-Host "     Projects    : $($item.Projects)" -ForegroundColor DarkGray
        Write-Host ""
    }
}

# ──────────────────────────────────────────────────────────────
# 3. Outdated Packages
# ──────────────────────────────────────────────────────────────
Write-Host "`n━━━ 📦 OUTDATED PACKAGES ━━━" -ForegroundColor Blue

$outdatedList   = @()
$outdatedErrors = $null

try {
    $jsonRaw = dotnet package list --outdated --format json 2>&1

    # jeśli dotnet zwróci error tekstowy
    if (($jsonRaw -join "`n") -match "^error") {
        $outdatedErrors = $jsonRaw
    }
    else {
        $json = $jsonRaw | Out-String | ConvertFrom-Json

        $outdatedMap = @{}

        foreach ($proj in $json.projects) {

            $projectName = [System.IO.Path]::GetFileNameWithoutExtension($proj.path)

            foreach ($framework in $proj.frameworks) {

                foreach ($pkg in $framework.topLevelPackages) {

                    if ($pkg.latestVersion -and $pkg.resolvedVersion -ne $pkg.latestVersion) {

                        $key = "$($pkg.id)|$($pkg.resolvedVersion)"

                        if (-not $outdatedMap.ContainsKey($key)) {
                            $outdatedMap[$key] = [PSCustomObject]@{
                                Category    = "Outdated"
                                Package     = $pkg.id
                                Version     = $pkg.resolvedVersion
                                Severity    = "Latest: $($pkg.latestVersion)"
                                Advisory    = $null
                                Message     = $null
                                Alternative = $null
                                Projects    = [System.Collections.Generic.List[string]]::new()
                            }
                        }

                        if (-not $outdatedMap[$key].Projects.Contains($projectName)) {
                            $outdatedMap[$key].Projects.Add($projectName)
                        }
                    }
                }
            }
        }

        $outdatedList = $outdatedMap.Values | ForEach-Object {
            $_ | Select-Object Category, Package, Version, Severity, Advisory, Message, Alternative,
            @{Name="Projects"; Expression={ $_.Projects -join ", " }}
        }
    }
}
catch {
    $outdatedErrors = $_
}

if ($outdatedErrors) {

    Write-Host "⚠️ Outdated scan failed." -ForegroundColor Yellow

}
elseif ($outdatedList.Count -gt 0) {

    foreach ($item in $outdatedList) {

        Write-Host "  📦 $($item.Package) $($item.Version)" -ForegroundColor DarkCyan
        Write-Host "     $($item.Severity)" -ForegroundColor Cyan
        Write-Host "     Projects: $($item.Projects)" -ForegroundColor DarkGray
        Write-Host ""
    }

}
else {

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
if ($Export -eq "None") {
    exit 0
}

$allResults = @($vulnerableList) + @($deprecatedList) + @($outdatedList) |
    Sort-Object { Get-SeverityOrder $_.Severity }

if ($Export -eq "CSV") {

    $csvPath = "$OutputFile.csv"
    $allResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n💾 CSV saved: $csvPath" -ForegroundColor Green
}

if ($Export -eq "HTML") {

    $htmlPath    = "$OutputFile.html"
    $generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm"

    function Format-Cell {
        param($Value, [bool]$IsLink = $false)
        if (-not $Value) { return "—" }
        if ($IsLink)     { return "<a href='$Value' target='_blank'>Open</a>" }
        return [System.Web.HttpUtility]::HtmlEncode($Value)
    }

    $rows = $allResults | ForEach-Object {

        $badgeColor = switch ($_.Category) {
            "Vulnerable" { "#e74c3c" }
            "Deprecated" { "#e67e22" }
            "Outdated"   { "#3498db" }
        }

        $severityColor = switch ($_.Severity) {
            { $_ -match "Critical" } { "#e74c3c" }
            { $_ -match "High" }     { "#c0392b" }
            { $_ -match "Moderate" } { "#e67e22" }
            default                  { "#555" }
        }

@"
<tr>
<td><span class='badge' style='background:$badgeColor'>$($_.Category)</span></td>
<td><strong>$($_.Package)</strong></td>
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
td{padding:.65rem 1rem;border-bottom:1px solid #f0f0f0;font-size:.88rem}
tr:hover td{background:#fafafa}
.badge{display:inline-block;padding:.2rem .65rem;border-radius:20px;color:#fff;font-size:.72rem;font-weight:600}
.projects{color:#999;font-size:.78rem}
code{background:#f4f4f4;padding:.1rem .4rem;border-radius:4px}
a{text-decoration:none;color:#3498db}
</style>
</head>
<body>

<h1>📦 NuGet Package Report</h1>
<p class="sub">
Solution: <strong>$($solutionFile.Name)</strong>
&nbsp;|&nbsp;
Generated: $generatedAt
</p>

<div class="summary">
<div class="card">
<div class="num" style="color:#e74c3c">$(@($vulnerableList).Count)</div>
<div class="lbl">Vulnerable</div>
</div>

<div class="card">
<div class="num" style="color:#e67e22">$(@($deprecatedList).Count)</div>
<div class="lbl">Deprecated</div>
</div>

<div class="card">
<div class="num" style="color:#3498db">$(if ($outdatedErrors) { "?" } else { @($outdatedList).Count })</div>
<div class="lbl">Outdated</div>
</div>
</div>

$outdatedNote

<table>
<thead>
<tr>
<th>Category</th>
<th>Package</th>
<th>Version</th>
<th>Severity</th>
<th>Advisory</th>
<th>Message</th>
<th>Alternative</th>
<th>Projects</th>
</tr>
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
}