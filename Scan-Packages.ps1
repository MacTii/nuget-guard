param(
    [string]$SolutionPath = ".",
    [ValidateSet("None", "CSV", "HTML")]
    [string]$Export = "None",
    [string]$OutputFile = "nuget-report"
)

# ── Find solution ──────────────────────────────────────────────
$solutionFile = Get-ChildItem -Path $SolutionPath -Filter "*.sln" -Recurse | Select-Object -First 1

if (-not $solutionFile) {
    Write-Error "No .sln file found."
    exit 1
}

Write-Host "`n🔍 Scanning solution: $($solutionFile.Name)`n" -ForegroundColor Cyan

# ──────────────────────────────────────────────────────────────
# 1. Vulnerable Packages
# ──────────────────────────────────────────────────────────────
Write-Host "━━━ 🚨 VULNERABLE PACKAGES ━━━" -ForegroundColor Red

$vulnerableOutput = dotnet list $solutionFile.FullName package --vulnerable 2>&1
$vulnerableMap = @{}

foreach ($line in $vulnerableOutput) {

    if ($line -match "^(.+\.csproj)\s*:\s*warning NU190\d: Package '(.+?)' (.+?) has a known (\w+) severity vulnerability,\s*(https://\S+)") {

        $projectName = [System.IO.Path]::GetFileNameWithoutExtension($matches[1])
        $packageId   = $matches[2]
        $version     = $matches[3]
        $severity    = $matches[4]
        $advisoryUrl = $matches[5]

        $key = "$packageId|$version|$severity"

        if (-not $vulnerableMap.ContainsKey($key)) {

            $vulnerableMap[$key] = [PSCustomObject]@{
                Category   = "Vulnerable"
                Package    = $packageId
                Version    = $version
                Reason     = $severity
                Message    = $advisoryUrl
                Alternative= "—"
                Projects   = [System.Collections.Generic.List[string]]::new()
            }
        }

        if ($projectName -and -not $vulnerableMap[$key].Projects.Contains($projectName)) {
            $vulnerableMap[$key].Projects.Add($projectName)
        }
    }
}

$vulnerableList = $vulnerableMap.Values | ForEach-Object {
    $_ | Select-Object Category, Package, Version, Reason, Message, Alternative,
        @{Name="Projects"; Expression={ $_.Projects -join ", " }}
}

if ($vulnerableList) {

    foreach ($item in $vulnerableList) {

        $color = switch ($item.Reason) {
            "Critical" { "Red" }
            "High"     { "DarkRed" }
            "Moderate" { "Yellow" }
            default    { "White" }
        }

        Write-Host "  📦 $($item.Package) $($item.Version)" -ForegroundColor $color
        Write-Host "     Severity : $($item.Reason)" -ForegroundColor $color
        Write-Host "     Advisory : $($item.Message)" -ForegroundColor Gray
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

function Get-PackageDeprecationInfo {

    param(
        [string]$PackageId,
        [string]$Version
    )

    try {

        $registrationUrl = "https://api.nuget.org/v3/registration5-gz-semver2/$($PackageId.ToLower())/index.json"
        $registration = Invoke-RestMethod -Uri $registrationUrl -ErrorAction Stop

        foreach ($page in $registration.items) {

            $items = $page.items

            if (-not $items) {
                $pageData = Invoke-RestMethod -Uri $page.'@id' -ErrorAction SilentlyContinue
                $items = $pageData.items
            }

            foreach ($item in $items) {

                if ($item.catalogEntry.version -eq $Version) {

                    $entry = $item.catalogEntry

                    if ($null -ne $entry.deprecation) {

                        return @{
                            IsDeprecated = $true
                            Reason       = ($entry.deprecation.reasons -join ", ")
                            Message      = $entry.deprecation.message
                            AltId        = $entry.deprecation.alternatePackage.id
                            AltRange     = $entry.deprecation.alternatePackage.range
                        }
                    }

                    return @{ IsDeprecated = $false }
                }
            }
        }

    } catch {
        return @{ IsDeprecated = $false }
    }

    return @{ IsDeprecated = $false }
}

$projectFiles = Get-ChildItem -Path $SolutionPath -Filter "*.csproj" -Recurse
$allPackages = @{}

foreach ($project in $projectFiles) {

    [xml]$xml = Get-Content $project.FullName

    foreach ($reference in $xml.SelectNodes("//PackageReference")) {

        $packageId = $reference.GetAttribute("Include")
        $version   = $reference.GetAttribute("Version")

        if ($packageId -and $version -and $version -notmatch '\*') {

            $key = "$packageId|$version"

            if (-not $allPackages.ContainsKey($key)) {

                $allPackages[$key] = @{
                    Id       = $packageId
                    Version  = $version
                    Projects = @()
                }
            }

            $allPackages[$key].Projects += $project.Name
        }
    }
}

$deprecatedList = @()
$counter = 0

foreach ($package in $allPackages.Values) {

    $counter++

    Write-Progress `
        -Activity "Checking NuGet API" `
        -Status "$($package.Id) $($package.Version)" `
        -PercentComplete (($counter / $allPackages.Count) * 100)

    $info = Get-PackageDeprecationInfo -PackageId $package.Id -Version $package.Version

    if ($info.IsDeprecated) {

        $deprecatedList += [PSCustomObject]@{
            Category    = "Deprecated"
            Package     = $package.Id
            Version     = $package.Version
            Reason      = $info.Reason
            Message     = $info.Message
            Alternative = if ($info.AltId) { "$($info.AltId) $($info.AltRange)" } else { "—" }
            Projects    = ($package.Projects | Select-Object -Unique) -join ", "
        }
    }
}

Write-Progress -Completed -Activity "Completed"

if ($deprecatedList.Count -eq 0) {

    Write-Host "✅ No deprecated packages found." -ForegroundColor Green

} else {

    foreach ($item in $deprecatedList) {

        Write-Host "  📦 $($item.Package) $($item.Version)" -ForegroundColor Red
        Write-Host "     Reason      : $($item.Reason)" -ForegroundColor Yellow

        if ($item.Message) {
            Write-Host "     Message     : $($item.Message)" -ForegroundColor Gray
        }

        Write-Host "     Alternative : $($item.Alternative)" -ForegroundColor Cyan
        Write-Host "     Projects    : $($item.Projects)" -ForegroundColor DarkGray
        Write-Host ""
    }
}

# ──────────────────────────────────────────────────────────────
# 3. Outdated Packages
# ──────────────────────────────────────────────────────────────
Write-Host "`n━━━ 📦 OUTDATED PACKAGES ━━━" -ForegroundColor Blue

$outdatedOutput = dotnet list $solutionFile.FullName package --outdated 2>&1
$outdatedMap = @{}
$currentProject = ""

foreach ($line in $outdatedOutput) {

    if ($line -match "Project '(.+)'") {
        $currentProject = [System.IO.Path]::GetFileNameWithoutExtension($matches[1])
    }

    if ($line -match "^\s+>\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)") {

        $packageId = $matches[1]
        $resolved  = $matches[2]
        $latest    = $matches[4]

        $key = "$packageId|$resolved"

        if (-not $outdatedMap.ContainsKey($key)) {

            $outdatedMap[$key] = [PSCustomObject]@{
                Category    = "Outdated"
                Package     = $packageId
                Version     = $resolved
                Reason      = "Latest: $latest"
                Message     = ""
                Alternative = "—"
                Projects    = [System.Collections.Generic.List[string]]::new()
            }
        }

        if ($currentProject -and -not $outdatedMap[$key].Projects.Contains($currentProject)) {
            $outdatedMap[$key].Projects.Add($currentProject)
        }
    }
}

$outdatedList = $outdatedMap.Values | ForEach-Object {
    $_ | Select-Object Category, Package, Version, Reason, Message, Alternative,
        @{Name="Projects"; Expression={ $_.Projects -join ", " }}
}

if ($outdatedList) {

    foreach ($item in $outdatedList) {

        Write-Host "  📦 $($item.Package) $($item.Version)" -ForegroundColor DarkCyan
        Write-Host "     $($item.Reason)" -ForegroundColor Cyan
        Write-Host "     Projects: $($item.Projects)" -ForegroundColor DarkGray
        Write-Host ""
    }

} else {
    Write-Host "✅ All packages are up to date." -ForegroundColor Green
}

# ──────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────
Write-Host "`n━━━ 📊 SUMMARY ━━━" -ForegroundColor Cyan

Write-Host "  Vulnerable : $(if ($vulnerableList) { '🚨 ' + @($vulnerableList).Count } else { '✅ 0' })"
Write-Host "  Deprecated : $(if ($deprecatedList) { '⚠️ ' + $deprecatedList.Count } else { '✅ 0' })"
Write-Host "  Outdated   : $(if ($outdatedList) { '📦 ' + @($outdatedList).Count } else { '✅ 0' })"

# ──────────────────────────────────────────────────────────────
# Export
# ──────────────────────────────────────────────────────────────
if ($Export -eq "None") {
    exit 0
}

$allResults = @($vulnerableList) + @($deprecatedList) + @($outdatedList)

if ($Export -eq "CSV") {

    $csvPath = "$OutputFile.csv"
    $allResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n💾 CSV saved: $csvPath" -ForegroundColor Green
}

if ($Export -eq "HTML") {

    $htmlPath = "$OutputFile.html"
    $generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm"

    $rows = $allResults | ForEach-Object {

        $badgeColor = switch ($_.Category) {
            "Vulnerable" { "#e74c3c" }
            "Deprecated" { "#e67e22" }
            "Outdated"   { "#3498db" }
        }

        $reasonColor = switch ($_.Reason) {
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
<td style='color:$reasonColor;font-weight:600'>$($_.Reason)</td>
<td>$(if ($_.Message) { "<a href='$($_.Message)' target='_blank'>Open</a>" } else { "—" })</td>
<td>$($_.Alternative)</td>
<td class='projects'>$($_.Projects)</td>
</tr>
"@
    }

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
<div class="num" style="color:#e67e22">$($deprecatedList.Count)</div>
<div class="lbl">Deprecated</div>
</div>

<div class="card">
<div class="num" style="color:#3498db">$(@($outdatedList).Count)</div>
<div class="lbl">Outdated</div>
</div>
</div>

<table>
<thead>
<tr>
<th>Category</th>
<th>Package</th>
<th>Version</th>
<th>Reason</th>
<th>Advisory</th>
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
