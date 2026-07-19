# Scan-Packages.ps1
#
# LEGACY: this script has been superseded by the NuGetGuard .NET tool (see /src)
# and is no longer actively developed. It still works, but lacks newer features:
# Central Package Management, .slnx solutions, outdated detection for
# packages.config projects, CI exit codes (--fail-on) and parallel metadata fetch.
# Prefer: dotnet tool install -g NuGetGuard
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
# License helpers
# ──────────────────────────────────────────────────────────────

# ── Well-known package → SPDX license database ───────────────
# Covers packages that ship no licenseExpression and have opaque URLs.
# Key is lowercase package ID for case-insensitive lookup.
$script:KnownPackageLicenses = @{
    # ── Microsoft / ASP.NET / .NET ────────────────────────────
    "microsoft.aspnet.mvc"                              = "Apache-2.0"
    "microsoft.aspnet.razor"                            = "Apache-2.0"
    "microsoft.aspnet.webpages"                         = "Apache-2.0"
    "microsoft.aspnet.webpages.data"                    = "Apache-2.0"
    "microsoft.aspnet.webpages.oauth"                   = "Apache-2.0"
    "microsoft.aspnet.webapi"                           = "Apache-2.0"
    "microsoft.aspnet.webapi.client"                    = "Apache-2.0"
    "microsoft.aspnet.webapi.core"                      = "Apache-2.0"
    "microsoft.aspnet.webapi.owin"                      = "Apache-2.0"
    "microsoft.aspnet.webapi.tracing"                   = "Apache-2.0"
    "microsoft.aspnet.webapi.webhost"                   = "Apache-2.0"
    "microsoft.aspnet.web.optimization"                 = "Apache-2.0"
    "microsoft.aspnet.identity.core"                    = "Apache-2.0"
    "microsoft.aspnet.identity.entityframework"         = "Apache-2.0"
    "microsoft.aspnet.identity.owin"                    = "Apache-2.0"
    "microsoft.aspnet.signalr"                          = "Apache-2.0"
    "microsoft.aspnet.signalr.core"                     = "Apache-2.0"
    "microsoft.aspnet.signalr.js"                       = "Apache-2.0"
    "microsoft.aspnet.signalr.systemweb"                = "Apache-2.0"
    "microsoft.owin"                                    = "Apache-2.0"
    "microsoft.owin.cors"                               = "Apache-2.0"
    "microsoft.owin.host.systemweb"                     = "Apache-2.0"
    "microsoft.owin.security"                           = "Apache-2.0"
    "microsoft.owin.security.cookies"                   = "Apache-2.0"
    "microsoft.owin.security.facebook"                  = "Apache-2.0"
    "microsoft.owin.security.google"                    = "Apache-2.0"
    "microsoft.owin.security.jwt"                       = "Apache-2.0"
    "microsoft.owin.security.microsoftaccount"          = "Apache-2.0"
    "microsoft.owin.security.oauth"                     = "Apache-2.0"
    "microsoft.owin.security.twitter"                   = "Apache-2.0"
    "microsoft.owin.testing"                            = "Apache-2.0"
    "owin"                                              = "Apache-2.0"
    # ── Microsoft general packages ────────────────────────────
    "microsoft.net.http"                                = "MIT"
    "microsoft.bcl"                                     = "MIT"
    "microsoft.bcl.build"                               = "MIT"
    "microsoft.bcl.async"                               = "MIT"
    "microsoft.bcl.asyncinterfaces"                     = "MIT"
    "microsoft.csharp"                                  = "MIT"
    "microsoft.extensions.caching.abstractions"         = "MIT"
    "microsoft.extensions.caching.memory"               = "MIT"
    "microsoft.extensions.configuration"                = "MIT"
    "microsoft.extensions.configuration.abstractions"   = "MIT"
    "microsoft.extensions.configuration.binder"         = "MIT"
    "microsoft.extensions.configuration.commandline"    = "MIT"
    "microsoft.extensions.configuration.environmentvariables" = "MIT"
    "microsoft.extensions.configuration.json"           = "MIT"
    "microsoft.extensions.configuration.xml"            = "MIT"
    "microsoft.extensions.dependencyinjection"          = "MIT"
    "microsoft.extensions.dependencyinjection.abstractions" = "MIT"
    "microsoft.extensions.diagnostics.abstractions"     = "MIT"
    "microsoft.extensions.fileproviders.abstractions"   = "MIT"
    "microsoft.extensions.fileproviders.composite"      = "MIT"
    "microsoft.extensions.fileproviders.physical"       = "MIT"
    "microsoft.extensions.filesystemglobbing"           = "MIT"
    "microsoft.extensions.hosting"                      = "MIT"
    "microsoft.extensions.hosting.abstractions"         = "MIT"
    "microsoft.extensions.http"                         = "MIT"
    "microsoft.extensions.logging"                      = "MIT"
    "microsoft.extensions.logging.abstractions"         = "MIT"
    "microsoft.extensions.logging.configuration"        = "MIT"
    "microsoft.extensions.logging.console"              = "MIT"
    "microsoft.extensions.logging.debug"                = "MIT"
    "microsoft.extensions.logging.eventlog"             = "MIT"
    "microsoft.extensions.logging.eventsource"          = "MIT"
    "microsoft.extensions.options"                      = "MIT"
    "microsoft.extensions.options.configurationextensions" = "MIT"
    "microsoft.extensions.primitives"                   = "MIT"
    "microsoft.extensions.objectpool"                   = "MIT"
    "microsoft.extensions.webencoding"                  = "MIT"
    "microsoft.entityframeworkcore"                     = "MIT"
    "microsoft.entityframeworkcore.abstractions"        = "MIT"
    "microsoft.entityframeworkcore.analyzers"           = "MIT"
    "microsoft.entityframeworkcore.design"              = "MIT"
    "microsoft.entityframeworkcore.inmemory"            = "MIT"
    "microsoft.entityframeworkcore.relational"          = "MIT"
    "microsoft.entityframeworkcore.sqlserver"           = "MIT"
    "microsoft.entityframeworkcore.sqlite"              = "MIT"
    "microsoft.entityframeworkcore.tools"               = "MIT"
    "system.buffers"                                    = "MIT"
    "system.collections"                                = "MIT"
    "system.collections.concurrent"                     = "MIT"
    "system.collections.immutable"                      = "MIT"
    "system.componentmodel.annotations"                 = "MIT"
    "system.componentmodel.composition"                 = "MIT"
    "system.data.common"                                = "MIT"
    "system.diagnostics.debug"                          = "MIT"
    "system.diagnostics.diagnosticsource"               = "MIT"
    "system.diagnostics.tracing"                        = "MIT"
    "system.dynamic.runtime"                            = "MIT"
    "system.globalization"                              = "MIT"
    "system.io"                                         = "MIT"
    "system.io.filesystem"                              = "MIT"
    "system.io.pipelines"                               = "MIT"
    "system.linq"                                       = "MIT"
    "system.linq.expressions"                           = "MIT"
    "system.linq.queryable"                             = "MIT"
    "system.memory"                                     = "MIT"
    "system.net.http"                                   = "MIT"
    "system.net.primitives"                             = "MIT"
    "system.numerics.vectors"                           = "MIT"
    "system.objectmodel"                                = "MIT"
    "system.reflection"                                 = "MIT"
    "system.reflection.emit"                            = "MIT"
    "system.reflection.extensions"                      = "MIT"
    "system.reflection.metadata"                        = "MIT"
    "system.reflection.primitives"                      = "MIT"
    "system.resources.resourcemanager"                  = "MIT"
    "system.runtime"                                    = "MIT"
    "system.runtime.caching"                            = "MIT"
    "system.runtime.compilerservices.unsafe"            = "MIT"
    "system.runtime.extensions"                         = "MIT"
    "system.runtime.handles"                            = "MIT"
    "system.runtime.interopservices"                    = "MIT"
    "system.runtime.interopservices.runtimeinformation" = "MIT"
    "system.runtime.numerics"                           = "MIT"
    "system.security.claims"                            = "MIT"
    "system.security.cryptography.algorithms"           = "MIT"
    "system.security.cryptography.encoding"             = "MIT"
    "system.security.cryptography.primitives"           = "MIT"
    "system.security.cryptography.x509certificates"     = "MIT"
    "system.security.permissions"                       = "MIT"
    "system.servicemodel.primitives"                    = "MIT"
    "system.text.encoding"                              = "MIT"
    "system.text.encoding.codepages"                    = "MIT"
    "system.text.encoding.extensions"                   = "MIT"
    "system.text.encodings.web"                         = "MIT"
    "system.text.regularexpressions"                    = "MIT"
    "system.threading"                                  = "MIT"
    "system.threading.channels"                         = "MIT"
    "system.threading.tasks"                            = "MIT"
    "system.threading.tasks.dataflow"                   = "MIT"
    "system.threading.tasks.extensions"                 = "MIT"
    "system.threading.timer"                            = "MIT"
    "system.valuetuple"                                 = "MIT"
    "system.xml.readerwriter"                           = "MIT"
    "system.xml.xdocument"                              = "MIT"
    "microsoft.identity.client"                         = "MIT"
    "microsoft.identity.web"                            = "MIT"
    "microsoft.identitymodel.clients.activedirectory"   = "MIT"
    "microsoft.identitymodel.jsonwebtokens"             = "MIT"
    "microsoft.identitymodel.logging"                   = "MIT"
    "microsoft.identitymodel.protocols"                 = "MIT"
    "microsoft.identitymodel.protocols.openidconnect"   = "MIT"
    "microsoft.identitymodel.tokens"                    = "MIT"
    "system.identitymodel.tokens.jwt"                   = "MIT"
    # ── NUnit / xUnit / testing ───────────────────────────────
    "nunit"                                             = "MIT"
    "nunit3testadapter"                                 = "MIT"
    "nunitlite"                                         = "MIT"
    "xunit"                                             = "Apache-2.0"
    "xunit.core"                                        = "Apache-2.0"
    "xunit.abstractions"                                = "Apache-2.0"
    "xunit.assert"                                      = "Apache-2.0"
    "xunit.extensibility.core"                          = "Apache-2.0"
    "xunit.extensibility.execution"                     = "Apache-2.0"
    "xunit.runner.visualstudio"                         = "Apache-2.0"
    "microsoft.net.test.sdk"                            = "MIT"
    "microsoft.testplatform.testhost"                   = "MIT"
    "fluentassertions"                                  = "Apache-2.0"
    "moq"                                               = "BSD-3-Clause"
    "castle.core"                                       = "Apache-2.0"
    "nsubstitute"                                       = "BSD-3-Clause"
    "bogus"                                             = "MIT"
    "fakeiteasly"                                       = "MIT"
    "comparenetobjects"                                 = "MIT"
    # ── Logging ───────────────────────────────────────────────
    "serilog"                                           = "Apache-2.0"
    "serilog.aspnetcore"                                = "Apache-2.0"
    "serilog.enrichers.environment"                     = "Apache-2.0"
    "serilog.enrichers.process"                         = "Apache-2.0"
    "serilog.enrichers.thread"                          = "Apache-2.0"
    "serilog.extensions.hosting"                        = "Apache-2.0"
    "serilog.extensions.logging"                        = "Apache-2.0"
    "serilog.formatting.compact"                        = "Apache-2.0"
    "serilog.sinks.applicationinsights"                 = "Apache-2.0"
    "serilog.sinks.console"                             = "Apache-2.0"
    "serilog.sinks.debug"                               = "Apache-2.0"
    "serilog.sinks.elasticsearch"                       = "Apache-2.0"
    "serilog.sinks.file"                                = "Apache-2.0"
    "serilog.sinks.mssqlserver"                         = "Apache-2.0"
    "serilog.sinks.seq"                                 = "Apache-2.0"
    "log4net"                                           = "Apache-2.0"
    "nlog"                                              = "BSD-3-Clause"
    "nlog.web.aspnetcore"                               = "BSD-3-Clause"
    "nlog.extensions.logging"                           = "BSD-3-Clause"
    "elmah"                                             = "Apache-2.0"
    # ── JSON / Serialization ──────────────────────────────────
    "newtonsoft.json"                                   = "MIT"
    "newtonsoft.json.schema"                            = "MIT"
    "messagepack"                                       = "MIT"
    "messagepack.annotations"                           = "MIT"
    "protobuf-net"                                      = "Apache-2.0"
    "protobuf-net.core"                                 = "Apache-2.0"
    "google.protobuf"                                   = "BSD-3-Clause"
    "apache.avro"                                       = "Apache-2.0"
    "csvhelper"                                         = "MS-PL"
    "tinyjson"                                          = "MIT"
    "system.text.json"                                  = "MIT"
    # ── Database / ORM ────────────────────────────────────────
    "dapper"                                            = "Apache-2.0"
    "dapper.contrib"                                    = "Apache-2.0"
    "nhibernate"                                        = "LGPL-2.1"
    "fluent-nhibernate"                                 = "BSD-3-Clause"
    "npgsql"                                            = "MIT"
    "npgsql.entityframeworkcore.postgresql"             = "MIT"
    "mongodb.driver"                                    = "Apache-2.0"
    "mongodb.bson"                                      = "Apache-2.0"
    "stackexchange.redis"                               = "MIT"
    "mysql.data"                                        = "GPL-2.0"
    "mysqlconnector"                                    = "MIT"
    "oracle.manageddataaccess"                          = "See URL"
    "system.data.sqlite"                                = "MS-PL"
    "sqlite-net-pcl"                                    = "MIT"
    "microsoft.data.sqlite"                             = "MIT"
    "microsoft.data.sqlite.core"                        = "MIT"
    "microsoft.data.sqlclient"                          = "MIT"
    "system.data.sqlclient"                             = "MIT"
    "linq2db"                                           = "MIT"
    "linq2db.sqlite"                                    = "MIT"
    "linq2db.sqlserver"                                 = "MIT"
    "marten"                                            = "MIT"
    "realm"                                             = "Apache-2.0"
    # ── HTTP / REST ───────────────────────────────────────────
    "restsharp"                                         = "Apache-2.0"
    "flurl"                                             = "MIT"
    "flurl.http"                                        = "MIT"
    "refit"                                             = "MIT"
    "polly"                                             = "BSD-3-Clause"
    "polly.extensions.http"                             = "BSD-3-Clause"
    "httpclientfactory"                                 = "MIT"
    "odata.core"                                        = "MIT"
    # ── Mapping ───────────────────────────────────────────────
    "automapper"                                        = "MIT"
    "automapper.extensions.microsoft.dependencyinjection" = "MIT"
    "mapster"                                           = "MIT"
    "tinymapper"                                        = "MIT"
    # ── Validation ────────────────────────────────────────────
    "fluentvalidation"                                  = "Apache-2.0"
    "fluentvalidation.aspnetcore"                       = "Apache-2.0"
    "fluentvalidation.dependencyinjectionextensions"    = "Apache-2.0"
    "jquery.validation"                                 = "MIT"
    "jquery.validation.unobtrusive"                     = "MIT"
    "jquery"                                            = "MIT"
    "jquery.ui.combined"                                = "MIT"
    "jquery.datatables"                                 = "MIT"
    # ── MediatR / CQRS ────────────────────────────────────────
    "mediatr"                                           = "Apache-2.0"
    "mediatr.extensions.microsoft.dependencyinjection" = "Apache-2.0"
    "massTransit"                                       = "Apache-2.0"
    "masstransit.rabbitmq"                              = "Apache-2.0"
    "masstransit.azure.servicebus.core"                 = "Apache-2.0"
    "nservicebus"                                       = "See URL"
    "rebus"                                             = "MIT"
    # ── AWS ───────────────────────────────────────────────────
    "awssdk.core"                                       = "Apache-2.0"
    "awssdk.s3"                                         = "Apache-2.0"
    "awssdk.sqs"                                       = "Apache-2.0"
    "awssdk.sns"                                        = "Apache-2.0"
    "awssdk.dynamodbv2"                                 = "Apache-2.0"
    "awssdk.lambda"                                     = "Apache-2.0"
    "awssdk.secretsmanager"                             = "Apache-2.0"
    "awssdk.securitytoken"                              = "Apache-2.0"
    "awssdk.cognitoidentityprovider"                    = "Apache-2.0"
    "awssdk.cloudwatch"                                 = "Apache-2.0"
    "awssdk.cloudwatchlogs"                             = "Apache-2.0"
    # ── Azure ─────────────────────────────────────────────────
    "azure.core"                                        = "MIT"
    "azure.storage.blobs"                               = "MIT"
    "azure.storage.queues"                              = "MIT"
    "azure.storage.files.shares"                        = "MIT"
    "azure.messaging.servicebus"                        = "MIT"
    "azure.messaging.eventhubs"                         = "MIT"
    "azure.keyvault.secrets"                            = "MIT"
    "azure.identity"                                    = "MIT"
    "azure.security.keyvault.secrets"                   = "MIT"
    "microsoft.azure.servicebus"                        = "MIT"
    "microsoft.azure.eventhubs"                         = "MIT"
    "microsoft.azure.storage.blob"                      = "MIT"
    "microsoft.azure.storage.queue"                     = "MIT"
    "microsoft.azure.webjobs"                           = "MIT"
    "microsoft.azure.functions.extensions"              = "MIT"
    "microsoft.azure.appservice.proxy"                  = "MIT"
    "windowsazure.storage"                              = "Apache-2.0"
    # ── Dependency Injection ──────────────────────────────────
    "autofac"                                           = "MIT"
    "autofac.extensions.dependencyinjection"            = "MIT"
    "ninject"                                           = "Apache-2.0"
    "simpleinjector"                                    = "MIT"
    "lamar"                                             = "MIT"
    "structuremap"                                      = "Apache-2.0"
    "unity"                                             = "Apache-2.0"
    "unity.container"                                   = "Apache-2.0"
    "dryloc.dll"                                        = "MIT"
    "lightinject"                                       = "MIT"
    # ── Utilities ─────────────────────────────────────────────
    "humanizer"                                         = "MIT"
    "humanizer.core"                                    = "MIT"
    "noda time"                                         = "Apache-2.0"
    "nodatime"                                          = "Apache-2.0"
    "cronexpressiondescriptor"                          = "MIT"
    "ncrontab"                                          = "Apache-2.0"
    "hangfire"                                          = "LGPL-3.0"
    "hangfire.core"                                     = "LGPL-3.0"
    "hangfire.aspnetcore"                               = "LGPL-3.0"
    "hangfire.sqlserver"                                = "LGPL-3.0"
    "quartz"                                            = "Apache-2.0"
    "quartz.net"                                        = "Apache-2.0"
    "coravel"                                           = "MIT"
    "ipnetwork2"                                        = "BSD-2-Clause"
    "handlebar.net"                                     = "MIT"
    "handlebars.net"                                    = "MIT"
    "scriban"                                           = "BSD-2-Clause"
    "fluid.core"                                        = "MIT"
    "dotliquid"                                         = "Apache-2.0"
    "markdig"                                           = "BSD-2-Clause"
    "commonmark.net"                                    = "BSD-3-Clause"
    "yaml-dotnet"                                       = "MIT"
    "yamldotnet"                                        = "MIT"
    "iron.python"                                       = "Apache-2.0"
    "ironpython"                                        = "Apache-2.0"
    "fody"                                              = "MIT"
    "propertychanged.fody"                              = "MIT"
    "methoddecorator.fody"                              = "MIT"
    "antlr4.runtime.standard"                           = "BSD-3-Clause"
    "antlr"                                             = "BSD-3-Clause"
    "antlr4"                                            = "BSD-3-Clause"
    # ── File / Document ───────────────────────────────────────
    "7zsharp"                                           = "LGPL-2.1"
    "7z.libs"                                           = "LGPL-2.1"
    "dotnetzip"                                         = "MS-PL"
    "sharpziplib"                                       = "MIT"
    "ionmezle.sharpziplib"                              = "MIT"
    "closedxml"                                         = "MIT"
    "documentformat.openxml"                            = "MIT"
    "epplus"                                            = "LGPL-3.0"
    "epplus.interfaces"                                 = "LGPL-3.0"
    "exceldatareader"                                   = "MIT"
    "exceldatareader.dataset"                           = "MIT"
    "itextsharp"                                        = "AGPL-3.0"
    "itext7"                                            = "AGPL-3.0"
    "itext7.bouncy-castle-adapter"                      = "AGPL-3.0"
    "pdfsharp"                                          = "MIT"
    "pdfsharp-wpf"                                      = "MIT"
    "dinktohtml"                                        = "MIT"
    "dinktohtml.native.osx"                             = "MIT"
    "dinktohtml.native.linux"                           = "MIT"
    "dinktohtml.native.windows"                         = "MIT"
    "wkhtmltopdf-dotnet"                                = "MIT"
    "ghostscript.net"                                   = "AGPL-3.0"
    "edftpnet"                                          = "MIT"
    "edftpnet-pro"                                      = "See URL"
    "fluentstorage"                                     = "MIT"
    "ckeditor"                                          = "GPL-2.0"
    "ckeditor-full"                                     = "GPL-2.0"
    "chosen"                                            = "MIT"
    "chosen.jquery"                                     = "MIT"
    # ── Imaging ───────────────────────────────────────────────
    "imagesharp"                                        = "Apache-2.0"
    "sixlabors.imagesharp"                              = "Apache-2.0"
    "sixlabors.imagesharp.web"                          = "Apache-2.0"
    "skiasharp"                                         = "MIT"
    "magick.net-q16-anycpu"                             = "Apache-2.0"
    "magick.net-q8-anycpu"                              = "Apache-2.0"
    "imageresizer"                                      = "Apache-2.0"
    "dotnetopenauth.core"                               = "MS-PL"
    "dotnetopenauth.aspnet"                             = "MS-PL"
    # ── Selenium / UI testing ─────────────────────────────────
    "selenium.webdriver"                                = "Apache-2.0"
    "selenium.webdriver.chromedriver"                   = "Apache-2.0"
    "selenium.webdriver.firefoxdriver"                  = "Apache-2.0"
    "selenium.support"                                  = "Apache-2.0"
    "dotnetseleniumextras.waithelpers"                  = "Apache-2.0"
    "dotnetseleniumextras.pageobjects"                  = "Apache-2.0"
    "playwright"                                        = "MIT"
    "microsoft.playwright"                              = "MIT"
    # ── SignalR / gRPC ────────────────────────────────────────
    "grpc"                                              = "Apache-2.0"
    "grpc.tools"                                        = "Apache-2.0"
    "grpc.aspnetcore"                                   = "Apache-2.0"
    "grpc.net.client"                                   = "Apache-2.0"
    "grpc.net.clientfactory"                            = "Apache-2.0"
    "google.api.commonprotos"                           = "Apache-2.0"
    # ── Caching ───────────────────────────────────────────────
    "easynetq"                                          = "MIT"
    "rabbitmq.client"                                   = "Apache-2.0"
    "confluent.kafka"                                   = "Apache-2.0"
    "confluent.schemaregistry"                          = "Apache-2.0"
    # ── Security / Crypto ─────────────────────────────────────
    "bouncycastle.cryptography"                         = "MIT"
    "bouncycastle"                                      = "MIT"
    "jose-jwt"                                          = "MIT"
    "system.security.cryptography.protecteddata"        = "MIT"
    # ── Misc popular packages ─────────────────────────────────
    "morelinq"                                          = "Apache-2.0"
    "linq.extras"                                       = "MIT"
    "z.extmethods"                                      = "MIT"
    "z.expressions.eval"                                = "MIT"
    "linq2twitter"                                      = "MS-PL"
    "twitterizer2"                                      = "BSD-3-Clause"
    "tweetinvi"                                         = "MIT"
    "mailkit"                                           = "MIT"
    "mimekit"                                           = "MIT"
    "fluentemail.core"                                  = "MIT"
    "fluentemail.smtp"                                  = "MIT"
    "twilio"                                            = "MIT"
    "stripe.net"                                        = "Apache-2.0"
    "braintree"                                         = "MIT"
    "paypalcheckoutsdk"                                 = "Apache-2.0"
    "smartformat.net"                                   = "MIT"
    "pdfpig"                                            = "Apache-2.0"
    "benchmark.net"                                     = "MIT"
    "benchmarkdotnet"                                   = "MIT"
    "nito.asyncex"                                      = "MIT"
    "nito.asyncex.coordination"                         = "MIT"
    "nito.asyncex.tasks"                                = "MIT"
    "scrutor"                                           = "MIT"
    "ardalis.result"                                    = "MIT"
    "ardalis.smartenum"                                 = "MIT"
    "ardalis.specification"                             = "MIT"
    "coverlet.collector"                                = "MIT"
    "microsoft.codecoverage"                            = "MIT"
    "opentelemetry"                                     = "Apache-2.0"
    "opentelemetry.api"                                 = "Apache-2.0"
    "opentelemetry.exporter.console"                    = "Apache-2.0"
    "opentelemetry.exporter.otlpexporter"               = "Apache-2.0"
    "opentelemetry.extensions.hosting"                  = "Apache-2.0"
    "opentelemetry.instrumentation.aspnetcore"          = "Apache-2.0"
    "opentelemetry.instrumentation.http"                = "Apache-2.0"
    "prometheus-net"                                    = "MIT"
    "prometheus-net.aspnetcore"                         = "MIT"
    "app-metrics-core"                                  = "Apache-2.0"
    "healthchecks.ui"                                   = "Apache-2.0"
    "healthchecks.sqlserver"                            = "MIT"
    "swashbuckle.aspnetcore"                            = "MIT"
    "swashbuckle.aspnetcore.swagger"                    = "MIT"
    "swashbuckle.aspnetcore.swaggergen"                 = "MIT"
    "swashbuckle.aspnetcore.swaggerui"                  = "MIT"
    "swashbuckle"                                       = "BSD-2-Clause"
    "nswag.aspnetcore"                                  = "MIT"
    "nswag.core"                                        = "MIT"
    "microsoft.aspnetcore.openapi"                      = "MIT"
    "microsoft.aspnetcore.mvc.versioning"               = "MIT"
    "asp.versioning.mvc"                                = "MIT"
    "asp.versioning.http"                               = "MIT"
    "specflow"                                          = "BSD-3-Clause"
    "specflow.nunit"                                    = "BSD-3-Clause"
    "specflow.xunit"                                    = "BSD-3-Clause"
    "reqnroll"                                          = "BSD-3-Clause"
    "telerik.justmock"                                  = "See URL"
    "wisej.net"                                         = "See URL"
    "devexpress"                                        = "See URL"
    "syncfusion"                                        = "See URL"
    "infragistics"                                      = "See URL"
    "componentone"                                      = "See URL"
}

# Known permissive / copyleft classification
$script:LicenseRiskMap = @{
    # Permissive (green)
    "MIT"                     = "Permissive"
    "Apache-2.0"              = "Permissive"
    "Apache 2.0"              = "Permissive"
    "BSD-2-Clause"            = "Permissive"
    "BSD-3-Clause"            = "Permissive"
    "ISC"                     = "Permissive"
    "Unlicense"               = "Permissive"
    "CC0-1.0"                 = "Permissive"
    "MS-PL"                   = "Permissive"
    "WTFPL"                   = "Permissive"
    "Zlib"                    = "Permissive"
    "PSF-2.0"                 = "Permissive"
    "0BSD"                    = "Permissive"
    "BSL-1.0"                 = "Permissive"
    # Weak copyleft (yellow)
    "LGPL-2.0"                = "WeakCopyleft"
    "LGPL-2.0-only"           = "WeakCopyleft"
    "LGPL-2.1"                = "WeakCopyleft"
    "LGPL-2.1-only"           = "WeakCopyleft"
    "LGPL-3.0"                = "WeakCopyleft"
    "LGPL-3.0-only"           = "WeakCopyleft"
    "MPL-2.0"                 = "WeakCopyleft"
    "EUPL-1.1"                = "WeakCopyleft"
    "EUPL-1.2"                = "WeakCopyleft"
    "MS-RL"                   = "WeakCopyleft"
    "CDDL-1.0"                = "WeakCopyleft"
    "EPL-1.0"                 = "WeakCopyleft"
    "EPL-2.0"                 = "WeakCopyleft"
    # Strong copyleft (red)
    "GPL-2.0"                 = "StrongCopyleft"
    "GPL-2.0-only"            = "StrongCopyleft"
    "GPL-2.0-or-later"        = "StrongCopyleft"
    "GPL-3.0"                 = "StrongCopyleft"
    "GPL-3.0-only"            = "StrongCopyleft"
    "GPL-3.0-or-later"        = "StrongCopyleft"
    "AGPL-3.0"                = "StrongCopyleft"
    "AGPL-3.0-only"           = "StrongCopyleft"
    "AGPL-3.0-or-later"       = "StrongCopyleft"
    "OSL-3.0"                 = "StrongCopyleft"
    "CC-BY-SA-4.0"            = "StrongCopyleft"
    "CC-BY-NC-4.0"            = "StrongCopyleft"
}

# ── Lookup license by package ID (case-insensitive) ──────────
function Get-KnownPackageLicense {
    param([string]$Id)
    if (-not $Id) { return $null }
    $key = $Id.ToLower()
    if ($script:KnownPackageLicenses.ContainsKey($key)) {
        return $script:KnownPackageLicenses[$key]
    }

    # Prefix matching: covers Microsoft.AspNetCore.*, Azure.*, etc.
    $prefixMap = [ordered]@{
        "microsoft.aspnetcore."         = "MIT"
        "microsoft.aspnet."             = "Apache-2.0"
        "microsoft.extensions."         = "MIT"
        "microsoft.entityframeworkcore."= "MIT"
        "microsoft.azure."              = "MIT"
        "microsoft.identity."           = "MIT"
        "microsoft.identitymodel."      = "MIT"
        "microsoft.net."                = "MIT"
        "microsoft.visualstudio."       = "MIT"
        "microsoft.codeanalysis."       = "MIT"
        "microsoft.build."              = "MIT"
        "system."                       = "MIT"
        "azure."                        = "MIT"
        "awssdk."                       = "Apache-2.0"
        "serilog."                      = "Apache-2.0"
        "nlog."                         = "BSD-3-Clause"
        "nunit."                        = "MIT"
        "xunit."                        = "Apache-2.0"
        "fluentvalidation."             = "Apache-2.0"
        "fluentassertions."             = "Apache-2.0"
        "automapper."                   = "MIT"
        "autofac."                      = "MIT"
        "mediatr."                      = "Apache-2.0"
        "masstransit."                  = "Apache-2.0"
        "hangfire."                     = "LGPL-3.0"
        "opentelemetry."                = "Apache-2.0"
        "grpc."                         = "Apache-2.0"
        "sixlabors."                    = "Apache-2.0"
        "polly."                        = "BSD-3-Clause"
        "npgsql."                       = "MIT"
        "magick.net"                    = "Apache-2.0"
    }

    foreach ($prefix in $prefixMap.Keys) {
        if ($key.StartsWith($prefix)) {
            return $prefixMap[$prefix]
        }
    }

    return $null
}

function Get-LicenseRisk {
    param([string]$License)
    if (-not $License -or $License -eq "Unknown") { return "Unknown" }

    # Direct lookup
    if ($script:LicenseRiskMap.ContainsKey($License)) {
        return $script:LicenseRiskMap[$License]
    }

    # Fuzzy match for compound expressions like "MIT OR Apache-2.0"
    if ($License -match "GPL" -and $License -notmatch "LGPL") { return "StrongCopyleft" }
    if ($License -match "LGPL")                                { return "WeakCopyleft"   }
    if ($License -match "MPL|EPL|EUPL|CDDL")                  { return "WeakCopyleft"   }
    if ($License -match "MIT|Apache|BSD|ISC|Unlicense|Ms-PL")  { return "Permissive"     }

    return "Unknown"
}

function Get-LicenseRiskColor {
    param([string]$Risk)
    switch ($Risk) {
        "Permissive"     { "Green"    }
        "WeakCopyleft"   { "Yellow"   }
        "StrongCopyleft" { "Red"      }
        default          { "DarkGray" }
    }
}

function Get-LicenseRiskHtmlColor {
    param([string]$Risk)
    switch ($Risk) {
        "Permissive"     { "#27ae60" }
        "WeakCopyleft"   { "#e67e22" }
        "StrongCopyleft" { "#e74c3c" }
        default          { "#aaa"    }
    }
}

# ── NEW: Risk order for sorting (worst → best) ────────────────
function Get-LicenseRiskOrder {
    param([string]$Risk)
    switch ($Risk) {
        "StrongCopyleft" { 0 }
        "WeakCopyleft"   { 1 }
        "Unknown"        { 2 }
        "Permissive"     { 3 }
        default          { 4 }
    }
}

# ── NEW: Try to resolve license from a licenseUrl by fetching content ──
function Resolve-LicenseFromUrl {
    param([string]$Url)

    if (-not $Url) { return $null }

    # ── Pattern matching on the URL itself (fast, no HTTP) ────
    $spdxFromUrl = switch -Wildcard ($Url) {
        "*opensource.org/licenses/MIT*"           { "MIT"           }
        "*apache.org/licenses/LICENSE-2.0*"       { "Apache-2.0"    }
        "*opensource.org/licenses/Apache-2.0*"    { "Apache-2.0"    }
        "*opensource.org/licenses/apache2*"       { "Apache-2.0"    }
        "*opensource.org/licenses/BSD-2-Clause*"  { "BSD-2-Clause"  }
        "*opensource.org/licenses/BSD-3-Clause*"  { "BSD-3-Clause"  }
        "*opensource.org/licenses/ISC*"           { "ISC"           }
        "*gnu.org/licenses/gpl-2*"                { "GPL-2.0"       }
        "*gnu.org/licenses/gpl-3*"                { "GPL-3.0"       }
        "*gnu.org/licenses/lgpl-2*"               { "LGPL-2.1"      }
        "*gnu.org/licenses/lgpl-3*"               { "LGPL-3.0"      }
        "*gnu.org/licenses/agpl*"                 { "AGPL-3.0"      }
        "*mozilla.org/MPL/2.0*"                   { "MPL-2.0"       }
        "*opensource.org/licenses/ms-pl*"         { "MS-PL"         }
        "*opensource.org/licenses/MS-PL*"         { "MS-PL"         }
        "*unlicense.org*"                         { "Unlicense"     }
        "*creativecommons.org/publicdomain/zero*" { "CC0-1.0"       }
        "*licenses.nuget.org/MIT*"                { "MIT"           }
        "*licenses.nuget.org/Apache-2.0*"         { "Apache-2.0"    }
        "*licenses.nuget.org/BSD-2-Clause*"       { "BSD-2-Clause"  }
        "*licenses.nuget.org/BSD-3-Clause*"       { "BSD-3-Clause"  }
        "*licenses.nuget.org/ISC*"                { "ISC"           }
        "*licenses.nuget.org/GPL-2.0*"            { "GPL-2.0"       }
        "*licenses.nuget.org/GPL-3.0*"            { "GPL-3.0"       }
        "*licenses.nuget.org/LGPL-2.1*"           { "LGPL-2.1"      }
        "*licenses.nuget.org/LGPL-3.0*"           { "LGPL-3.0"      }
        "*licenses.nuget.org/AGPL-3.0*"           { "AGPL-3.0"      }
        "*licenses.nuget.org/MPL-2.0*"            { "MPL-2.0"       }
        "*licenses.nuget.org/MS-PL*"              { "MS-PL"         }
        "*licenses.nuget.org/Unlicense*"          { "Unlicense"     }
        "*licenses.nuget.org/CC0-1.0*"            { "CC0-1.0"       }
        "*github.com/dotnet*"                     { "MIT"           }  # Most Microsoft/dotnet packages
        default                                   { $null           }
    }

    if ($spdxFromUrl) { return $spdxFromUrl }

    # ── Fetch the URL content and look for SPDX identifiers ───
    # Only attempt for licenses.nuget.org or well-known license hosts
    $fetchHosts = @("licenses.nuget.org", "raw.githubusercontent.com", "github.com")
    $shouldFetch = $false
    foreach ($h in $fetchHosts) {
        if ($Url -match [regex]::Escape($h)) { $shouldFetch = $true; break }
    }

    if (-not $shouldFetch) { return $null }

    try {
        $content = (Invoke-WebRequest -Uri $Url -TimeoutSec 5 -ErrorAction Stop).Content

        # Look for SPDX expression in page title or content
        $spdxPatterns = @(
            'MIT', 'Apache-2\.0', 'Apache 2\.0', 'BSD-2-Clause', 'BSD-3-Clause',
            'ISC', 'GPL-3\.0', 'GPL-2\.0', 'LGPL-3\.0', 'LGPL-2\.1', 'LGPL-2\.0',
            'AGPL-3\.0', 'MPL-2\.0', 'MS-PL', 'Unlicense', 'CC0-1\.0',
            'EPL-2\.0', 'EPL-1\.0', 'EUPL-1\.2', 'EUPL-1\.1', 'BSL-1\.0'
        )

        foreach ($pattern in $spdxPatterns) {
            if ($content -match "(?i)\b$pattern\b") {
                # Normalize to canonical SPDX
                $matched = $Matches[0]
                return ($matched -replace 'Apache 2\.0', 'Apache-2.0').Trim()
            }
        }
    } catch {}

    return $null
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
# NuGet API: deprecation + vulnerability + license metadata
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
        License            = "Unknown"
        LicenseUrl         = $null
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

                # ── Deprecation ──────────────────────────────
                if ($null -ne $entry.deprecation) {
                    $result.IsDeprecated       = $true
                    $result.DeprecatedSeverity = ($entry.deprecation.reasons -join ", ")
                    $result.DeprecationMessage = $entry.deprecation.message
                    $result.AltId              = $entry.deprecation.alternatePackage.id
                    $result.AltRange           = $entry.deprecation.alternatePackage.range
                }

                # ── Vulnerabilities ──────────────────────────
                if ($entry.vulnerabilities -and $entry.vulnerabilities.Count -gt 0) {
                    $result.Vulnerabilities = foreach ($v in $entry.vulnerabilities) {
                        [PSCustomObject]@{
                            Severity    = (Get-SeverityLabel -Value ([int]$v.severity))
                            AdvisoryUrl = $v.advisoryUrl
                        }
                    }
                }

                # ── License ──────────────────────────────────
                # Priority 1: SPDX expression directly in catalogEntry
                if ($entry.licenseExpression -and $entry.licenseExpression.Trim() -ne "") {
                    $result.License    = $entry.licenseExpression.Trim()
                    $result.LicenseUrl = $entry.licenseUrl
                }
                # Priority 2: Known package database (covers legacy pkgs with no SPDX)
                elseif ($null -ne (Get-KnownPackageLicense -Id $pkg.Id)) {
                    $result.License    = Get-KnownPackageLicense -Id $pkg.Id
                    $result.LicenseUrl = $entry.licenseUrl
                }
                # Priority 3: Derive from licenseUrl pattern / page content
                elseif ($entry.licenseUrl -and $entry.licenseUrl -ne "") {
                    $result.LicenseUrl = $entry.licenseUrl

                    $resolved = Resolve-LicenseFromUrl -Url $entry.licenseUrl
                    if ($resolved) {
                        $result.License = $resolved
                    } else {
                        $result.License = "See URL"
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
# NEW: Second-pass license resolution for remaining "See URL" / "Unknown"
# Fetches the actual license page content for SPDX identification
# ──────────────────────────────────────────────────────────────
$unresolvedCount = ($nugetResults | Where-Object { $_.License -in @("See URL", "Unknown") -and $_.LicenseUrl }).Count

if ($unresolvedCount -gt 0) {
    Write-Host "🔄 Resolving $unresolvedCount unidentified licenses from URLs..." -ForegroundColor Cyan

    $resolveSeq = 0
    foreach ($r in $nugetResults) {
        if ($r.License -notin @("See URL", "Unknown")) { continue }

        # Try known-package DB first (fast, no HTTP)
        $knownLic = Get-KnownPackageLicense -Id $r.Id
        if ($knownLic) {
            $r.License = $knownLic
            continue
        }

        if (-not $r.LicenseUrl) { continue }

        $resolveSeq++
        Write-Progress -Activity "Resolving license URLs" `
            -Status "$($r.Id)" `
            -PercentComplete (($resolveSeq / $unresolvedCount) * 100)

        try {
            $content = (Invoke-WebRequest -Uri $r.LicenseUrl -TimeoutSec 6 -ErrorAction Stop).Content

            # Ordered from most specific to least specific
            $candidates = [ordered]@{
                "AGPL-3.0"     = "GNU AFFERO GENERAL PUBLIC LICENSE.*Version 3|AGPL.?3\.0"
                "GPL-3.0"      = "GNU GENERAL PUBLIC LICENSE.*Version 3(?!.*Affero)|GPL.?3\.0"
                "GPL-2.0"      = "GNU GENERAL PUBLIC LICENSE.*Version 2(?!.*Affero)|GPL.?2\.0"
                "LGPL-3.0"     = "GNU LESSER GENERAL PUBLIC LICENSE.*Version 3|LGPL.?3\.0"
                "LGPL-2.1"     = "GNU LESSER GENERAL PUBLIC LICENSE.*Version 2\.1|LGPL.?2\.1"
                "LGPL-2.0"     = "GNU LESSER GENERAL PUBLIC LICENSE.*Version 2(?!\.1)|LGPL.?2\.0"
                "MPL-2.0"      = "Mozilla Public License.*2\.0|MPL.?2\.0"
                "EPL-2.0"      = "Eclipse Public License.*2\.0|EPL.?2\.0"
                "EPL-1.0"      = "Eclipse Public License.*1\.0|EPL.?1\.0"
                "EUPL-1.2"     = "European Union Public Licence.*1\.2|EUPL.?1\.2"
                "EUPL-1.1"     = "European Union Public Licence.*1\.1|EUPL.?1\.1"
                "Apache-2.0"   = "Apache License.*Version 2\.0|Apache.?2\.0"
                "BSD-3-Clause" = "BSD 3-Clause|Redistribution and use.*three.*conditions"
                "BSD-2-Clause" = "BSD 2-Clause|Redistribution and use.*two.*conditions"
                "MIT"          = "Permission is hereby granted.*free of charge|MIT License"
                "ISC"          = "ISC License|Permission to use.*copy.*modify"
                "MS-PL"        = "Microsoft Public License|Ms-PL"
                "Unlicense"    = "This is free and unencumbered software released into the public domain"
                "CC0-1.0"      = "CC0 1\.0 Universal|Creative Commons.*Public Domain"
                "BSL-1.0"      = "Boost Software License"
            }

            $found = $null
            foreach ($spdx in $candidates.Keys) {
                if ($content -match "(?i)$($candidates[$spdx])") {
                    $found = $spdx
                    break
                }
            }

            if ($found) {
                $r.License = $found
            }
        } catch {}
    }

    Write-Progress -Completed -Activity "Resolving license URLs"

    $resolvedNow = ($nugetResults | Where-Object { $_.License -notin @("See URL", "Unknown") }).Count - ($totalCount - $unresolvedCount)
    Write-Host "✅ Resolved $resolvedNow additional licenses from page content`n" -ForegroundColor Green
}

# ──────────────────────────────────────────────────────────────
# 1. Vulnerable Packages
# ──────────────────────────────────────────────────────────────
Write-Host "━━━ 🚨 VULNERABLE PACKAGES ━━━" -ForegroundColor Red

$vulnerableMap   = @{}
$skippedProjects = @()

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
# 4. License Audit
# ──────────────────────────────────────────────────────────────
Write-Host "`n━━━ 📜 LICENSE AUDIT ━━━" -ForegroundColor Magenta

$licenseList = $nugetResults |
    Sort-Object { Get-LicenseRiskOrder (Get-LicenseRisk $_.License) }, Id |   # ← FIXED: worst first
    ForEach-Object {
        $risk = Get-LicenseRisk $_.License
        [PSCustomObject]@{
            Package    = $_.Id
            Version    = $_.Version
            License    = $_.License
            Risk       = $risk
            LicenseUrl = $_.LicenseUrl
            Projects   = ($_.Projects | Select-Object -Unique) -join ", "
        }
    }

# Console: group by risk level — worst first
$riskGroups = $licenseList | Group-Object Risk

$riskOrder = @("StrongCopyleft", "WeakCopyleft", "Unknown", "Permissive")   # ← FIXED order

foreach ($riskName in $riskOrder) {
    $group = $riskGroups | Where-Object { $_.Name -eq $riskName }
    if (-not $group) { continue }

    $emoji = switch ($riskName) {
        "StrongCopyleft" { "🔴" }
        "WeakCopyleft"   { "🟡" }
        "Unknown"        { "⚪" }
        "Permissive"     { "🟢" }
    }
    $color = Get-LicenseRiskColor $riskName

    Write-Host "  $emoji $riskName ($($group.Count))" -ForegroundColor $color

    foreach ($item in ($group.Group | Sort-Object Package)) {
        $urlNote = if ($item.LicenseUrl) { "  → $($item.LicenseUrl)" } else { "" }
        Write-Host "     📦 $($item.Package) $($item.Version)  [$($item.License)]$urlNote" -ForegroundColor $color
    }
    Write-Host ""
}

# ──────────────────────────────────────────────────────────────
# 5. Redundant Packages (Snitch-like analysis — SDK + Legacy)
# ──────────────────────────────────────────────────────────────
Write-Host "`n━━━ 🔗 REDUNDANT PACKAGES (covered transitively) ━━━" -ForegroundColor Magenta

# Polyfill packages on .NET Framework — never flag as redundant
$frameworkPolyfills = @(
    'System.Buffers', 'System.Memory', 'System.Numerics.Vectors',
    'System.Runtime.CompilerServices.Unsafe', 'System.Threading.Tasks.Extensions',
    'System.ValueTuple', 'System.Text.Json', 'System.Text.Encodings.Web',
    'System.IO.Pipelines', 'System.Threading.Channels',
    'Microsoft.Bcl.AsyncInterfaces', 'System.Text.Encoding.CodePages'
)

function Test-IsLegacyProject {
    param([System.IO.FileInfo]$Project)
    Test-Path (Join-Path $Project.DirectoryName "packages.config")
}

function Test-IsSdkStyle {
    param([System.IO.FileInfo]$Project)
    [xml]$xml = Get-Content $Project.FullName
    $sdk = $xml.Project.GetAttribute("Sdk")
    return ([bool]$sdk)
}

function Get-PackageDepsFromNuspec {
    param([string]$NuspecPath)

    if (-not (Test-Path $NuspecPath)) { return @() }
    [xml]$nuspec = Get-Content $NuspecPath

    $deps = @()
    $nsUri = $nuspec.DocumentElement.NamespaceURI

    if ($nsUri) {
        $nsMgr = New-Object System.Xml.XmlNamespaceManager($nuspec.NameTable)
        $nsMgr.AddNamespace("ns", $nsUri)

        $groups   = $nuspec.SelectNodes("//ns:dependencies/ns:group", $nsMgr)
        $flatDeps = $nuspec.SelectNodes("//ns:dependencies/ns:dependency", $nsMgr)

        if ($groups -and $groups.Count -gt 0) {
            $bestGroup = $null
            foreach ($g in $groups) {
                $tf = $g.GetAttribute("targetFramework")
                if (-not $tf -or $tf -match "net4" -or $tf -match "netstandard") {
                    $bestGroup = $g; break
                }
            }
            if ($bestGroup) {
                foreach ($d in $bestGroup.SelectNodes("ns:dependency", $nsMgr)) {
                    $id = $d.GetAttribute("id")
                    if ($id) { $deps += $id }
                }
            }
        } elseif ($flatDeps -and $flatDeps.Count -gt 0) {
            foreach ($d in $flatDeps) {
                $id = $d.GetAttribute("id")
                if ($id) { $deps += $id }
            }
        }
    } else {
        foreach ($group in $nuspec.package.metadata.dependencies.group) {
            foreach ($d in $group.dependency) {
                $id = if ($d.id) { $d.id } else { $d.GetAttribute("id") }
                if ($id) { $deps += $id }
            }
        }
        foreach ($d in $nuspec.package.metadata.dependencies.dependency) {
            $id = if ($d.id) { $d.id } else { $d.GetAttribute("id") }
            if ($id) { $deps += $id }
        }
    }

    return ($deps | Where-Object { $_ })
}

$depCache = @{}

function Get-PackageDependencyIds {
    param([string]$Id, [string]$Version, [string]$PackagesFolder)

    $key = "$Id|$Version"
    if ($depCache.ContainsKey($key)) { return $depCache[$key] }

    $deps = @()

    # 1. Local nuspec from packages folder (legacy projects)
    if ($PackagesFolder -and (Test-Path $PackagesFolder)) {
        $pkgDir = Join-Path $PackagesFolder "$Id.$Version"
        if (Test-Path $pkgDir) {
            $nuspec = Get-ChildItem -Path $pkgDir -Filter "*.nuspec" -Recurse | Select-Object -First 1
            if ($nuspec) {
                $deps = Get-PackageDepsFromNuspec -NuspecPath $nuspec.FullName
            }
        }
    }

    # 2. NuGet registration API fallback
    if (-not $deps) {
        try {
            $url = "https://api.nuget.org/v3/registration5-gz-semver2/$($Id.ToLower())/index.json"
            $reg = Invoke-RestMethod -Uri $url -ErrorAction Stop

            foreach ($page in $reg.items) {
                $items = $page.items
                if (-not $items) {
                    $pd    = Invoke-RestMethod -Uri $page.'@id' -ErrorAction SilentlyContinue
                    $items = $pd.items
                }
                foreach ($item in $items) {
                    if ($item.catalogEntry.version -ne $Version) { continue }
                    foreach ($group in $item.catalogEntry.dependencyGroups) {
                        foreach ($d in $group.dependencies) { $deps += $d.id }
                    }
                    break
                }
            }
        } catch {}
    }

    $deps = $deps | Sort-Object -Unique
    $depCache[$key] = $deps
    return $deps
}

function Get-FullTransitiveClosure {
    param(
        [string]$Id,
        [string]$Version,
        [string]$PackagesFolder,
        [System.Collections.Generic.HashSet[string]]$Visited
    )

    $deps = Get-PackageDependencyIds -Id $Id -Version $Version -PackagesFolder $PackagesFolder

    foreach ($depId in $deps) {
        if ($Visited.Add($depId)) {
            $depVersion = $null
            $match = $allPackages.Values | Where-Object { $_.Id -eq $depId } | Select-Object -First 1
            if ($match) { $depVersion = $match.Version }
            if ($depVersion) {
                Get-FullTransitiveClosure -Id $depId -Version $depVersion `
                    -PackagesFolder $PackagesFolder -Visited $Visited | Out-Null
            }
        }
    }
    return $Visited
}

function Get-ProjectDirectPackages {
    param([string]$ProjectPath)

    $result = @{}
    if (-not (Test-Path $ProjectPath)) { return $result }

    [xml]$xml = Get-Content $ProjectPath
    foreach ($r in $xml.SelectNodes("//PackageReference")) {
        $id = $r.GetAttribute("Include")
        $v  = $r.GetAttribute("Version")
        if ($id -and $v -and $v -notmatch '\*') {
            $result[$id] = $v
        }
    }

    $cfgPath = Join-Path ([System.IO.Path]::GetDirectoryName($ProjectPath)) "packages.config"
    if (Test-Path $cfgPath) {
        [xml]$cfg = Get-Content $cfgPath
        foreach ($p in $cfg.SelectNodes("//package")) {
            $id = $p.GetAttribute("id")
            $v  = $p.GetAttribute("version")
            if ($id -and $v) { $result[$id] = $v }
        }
    }

    return $result
}

function Get-AllProjectReferencePaths {
    param(
        [string]$ProjectPath,
        [System.Collections.Generic.HashSet[string]]$Visited
    )

    if (-not (Test-Path $ProjectPath)) { return }
    $fullPath = [System.IO.Path]::GetFullPath($ProjectPath)
    if (-not $Visited.Add($fullPath)) { return }

    [xml]$xml = Get-Content $fullPath
    $projDir  = [System.IO.Path]::GetDirectoryName($fullPath)

    $refs = $xml.SelectNodes("//ProjectReference") | ForEach-Object {
        $refPath = $_.GetAttribute("Include")
        if ($refPath) {
            $resolved = [System.IO.Path]::GetFullPath((Join-Path $projDir $refPath))
            if (Test-Path $resolved) { $resolved }
        }
    }

    foreach ($ref in $refs) {
        Get-AllProjectReferencePaths -ProjectPath $ref -Visited $Visited
    }
}

$redundantFound = $false

foreach ($project in $projectFiles) {

    $isLegacy   = Test-IsLegacyProject -Project $project
    $isSdkStyle = Test-IsSdkStyle -Project $project

    [xml]$xml = Get-Content $project.FullName
    $direct = @{}

    foreach ($r in $xml.SelectNodes("//PackageReference")) {
        $v = $r.GetAttribute("Version")
        if ($v -and $v -notmatch '\*') {
            $direct[$r.GetAttribute("Include")] = $v
        }
    }

    $cfgPath = Join-Path $project.DirectoryName "packages.config"
    if (Test-Path $cfgPath) {
        [xml]$cfg = Get-Content $cfgPath
        foreach ($p in $cfg.SelectNodes("//package")) {
            $direct[$p.GetAttribute("id")] = $p.GetAttribute("version")
        }
    }

    if ($direct.Count -lt 2) { continue }

    $projectRefVisited = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    Get-AllProjectReferencePaths -ProjectPath $project.FullName -Visited $projectRefVisited
    $projectRefVisited.Remove([System.IO.Path]::GetFullPath($project.FullName)) | Out-Null

    $allProjectRefPackages = @{}
    foreach ($refProjPath in $projectRefVisited) {
        $refProj = Get-Item $refProjPath -ErrorAction SilentlyContinue
        if (-not $refProj) { continue }

        $refPackages = Get-ProjectDirectPackages -ProjectPath $refProjPath
        foreach ($id in $refPackages.Keys) {
            if (-not $allProjectRefPackages.ContainsKey($id)) {
                $allProjectRefPackages[$id] = @{
                    Version = $refPackages[$id]
                    Source  = [System.IO.Path]::GetFileNameWithoutExtension($refProjPath)
                }
            }
        }
    }

    $packagesFolder = Join-Path $solutionFile.DirectoryName "packages"
    if (-not (Test-Path $packagesFolder)) { $packagesFolder = $null }

    $closures = @{}
    $seq2 = 0
    foreach ($id in $direct.Keys) {
        $seq2++
        Write-Progress -Activity "Analyzing transitive deps: $($project.BaseName)" `
            -Status "$id" -PercentComplete (($seq2 / $direct.Count) * 100)

        $set = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        Get-FullTransitiveClosure -Id $id -Version $direct[$id] `
            -PackagesFolder $packagesFolder -Visited $set | Out-Null
        $closures[$id] = $set
    }

    Write-Progress -Completed -Activity "Analyzing transitive deps: $($project.BaseName)"

    $redundant = @()
    foreach ($x in $direct.Keys) {

        if (-not $isSdkStyle -and ($frameworkPolyfills -contains $x)) { continue }

        foreach ($y in $direct.Keys) {
            if ([string]::Equals($x, $y, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($closures[$y].Contains($x)) {

                $sourceNote = "this project"
                if ($allProjectRefPackages.ContainsKey($y)) {
                    $sourceNote = "also in ProjectRef → $($allProjectRefPackages[$y].Source)"
                }

                $redundant += [PSCustomObject]@{
                    Package          = $x
                    Version          = $direct[$x]
                    CoveredBy        = $y
                    CoveredByVersion = $direct[$y]
                    CoveredBySource  = $sourceNote
                }
                break
            }
        }
    }

    if ($isSdkStyle -and $allProjectRefPackages.Count -gt 0) {

        foreach ($x in $direct.Keys) {

            if ($frameworkPolyfills -contains $x) { continue }
            if ($redundant | Where-Object { $_.Package -eq $x }) { continue }

            if ($allProjectRefPackages.ContainsKey($x)) {
                $src = $allProjectRefPackages[$x]
                $redundant += [PSCustomObject]@{
                    Package          = $x
                    Version          = $direct[$x]
                    CoveredBy        = "ProjectRef → $($src.Source)"
                    CoveredByVersion = $src.Version
                    CoveredBySource  = "ProjectRef → $($src.Source)"
                }
            }
        }
    }

    if ($redundant) {
        $redundantFound = $true
        $projectType = if ($isLegacy) { "legacy ⚠️" } elseif ($isSdkStyle) { "SDK" } else { "unknown" }
        Write-Host "  📂 $($project.BaseName)  ($projectType)" -ForegroundColor White

        if ($isLegacy) {
            Write-Host "     ⚠️  packages.config — cannot remove, informational only" -ForegroundColor Yellow
        }

        foreach ($r in ($redundant | Sort-Object Package)) {
            $color = if ($isLegacy) { "DarkGray" } else { "Magenta" }

            $sourceLabel = ""
            if ($r.CoveredBySource -and $r.CoveredBySource -ne "this project") {
                $sourceLabel = "  ($($r.CoveredBySource))"
            }

            Write-Host "     🔗 $($r.Package) $($r.Version)  ← pulled by  $($r.CoveredBy) $($r.CoveredByVersion)$sourceLabel" -ForegroundColor $color
        }
        Write-Host ""
    }
}

if (-not $redundantFound) {
    Write-Host "  ✅ No redundant packages found." -ForegroundColor Green
}

# ──────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────
Write-Host "`n━━━ 📊 SUMMARY ━━━" -ForegroundColor Cyan

$copyleftCount = ($licenseList | Where-Object { $_.Risk -eq "StrongCopyleft" }).Count
$unknownCount  = ($licenseList | Where-Object { $_.Risk -eq "Unknown" }).Count

Write-Host "  Vulnerable      : $(if ($vulnerableList) { '🚨 ' + @($vulnerableList).Count } else { '✅ 0' })"
Write-Host "  Deprecated      : $(if (@($deprecatedList).Count -gt 0) { '⚠️ ' + @($deprecatedList).Count } else { '✅ 0' })"

if ($outdatedErrors) {
    Write-Host "  Outdated        : ⚠️  scan failed (build errors)" -ForegroundColor Yellow
} else {
    Write-Host "  Outdated        : $(if ($outdatedList) { '📦 ' + @($outdatedList).Count } else { '✅ 0' })"
}

Write-Host "  Licenses total  : $($licenseList.Count)  (🔴 StrongCopyleft: $copyleftCount  ⚪ Unknown: $unknownCount)"

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

    # License CSV as a separate sheet-friendly file — sorted worst → best
    $licenseCsvPath = "$OutputFile-licenses.csv"
    $licenseList |
        Sort-Object { Get-LicenseRiskOrder $_.Risk }, Package |
        Select-Object Package, Version, License, Risk, LicenseUrl, Projects |
        Export-Csv -Path $licenseCsvPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n💾 CSV saved       : $csvPath"        -ForegroundColor Green
    Write-Host   "💾 License CSV     : $licenseCsvPath" -ForegroundColor Green
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

# ── Main issues table ─────────────────────────────────────────
$flatResults = @($vulnerableList) + @($deprecatedList) + @($outdatedList)

$allResults = $flatResults |
    Sort-Object `
        @{ Expression = { Get-CategoryOrder $_.Category } },
        @{ Expression = { Get-MaxSeverityForPackage -Results $flatResults -Category $_.Category -Package $_.Package } },
        Package,
        @{ Expression = { Get-SeverityOrder $_.Severity } }

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

# ── License table rows — sorted worst → best ─────────────────
$licenseRowsSorted = $licenseList | Sort-Object { Get-LicenseRiskOrder $_.Risk }, Package

$licenseRows = $licenseRowsSorted | ForEach-Object {
    $riskColor = Get-LicenseRiskHtmlColor $_.Risk
    $urlCell   = if ($_.LicenseUrl) { "<a href='$($_.LicenseUrl)' target='_blank'>🔗</a>" } else { "—" }
@"
<tr>
<td><strong>$($_.Package)</strong></td>
<td><code>$($_.Version)</code></td>
<td><span class='lic-badge' style='background:$riskColor'>$($_.License)</span></td>
<td style='color:$riskColor;font-weight:600'>$($_.Risk)</td>
<td>$urlCell</td>
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
h2{font-size:1.2rem;margin:2rem 0 .75rem;color:#2c3e50}
.sub{color:#888;margin-bottom:1.5rem}
.summary{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}
.card{background:#fff;border-radius:10px;padding:1rem 1.5rem;box-shadow:0 1px 4px rgba(0,0,0,.08);flex:1;min-width:140px;text-align:center}
.num{font-size:2.2rem;font-weight:700}
.lbl{font-size:.8rem;color:#888;margin-top:.25rem}
.build-error{background:#fff8e1;border:1px solid #ffe082;border-radius:8px;padding:.75rem 1rem;margin-bottom:1rem;color:#7a5f00;font-size:.88rem}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:2rem}
th{background:#2c3e50;color:#fff;padding:.75rem 1rem;text-align:left;font-size:.8rem;text-transform:uppercase}
td{padding:.65rem 1rem;border-bottom:1px solid #f0f0f0;font-size:.88rem;vertical-align:top}
tr:hover td:not(.pkg-cell){background:#fafafa}
.group-start td{border-top:2px solid #d0d7de}
.pkg-cell{background:#fafbfc;border-right:1px solid #eaecef}
.badge{display:inline-block;padding:.2rem .65rem;border-radius:20px;color:#fff;font-size:.72rem;font-weight:600}
.lic-badge{display:inline-block;padding:.2rem .65rem;border-radius:20px;color:#fff;font-size:.78rem;font-weight:600}
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
<div class="card"><div class="num" style="color:#e74c3c">$copyleftCount</div><div class="lbl">Strong Copyleft</div></div>
<div class="card"><div class="num" style="color:#aaa">$unknownCount</div><div class="lbl">Unknown License</div></div>
</div>

$outdatedNote

<h2>🚨 Issues</h2>
<table>
<thead>
<tr><th>Category</th><th>Package</th><th>Version</th><th>Severity</th><th>Advisory</th><th>Message</th><th>Alternative</th><th>Projects</th></tr>
</thead>
<tbody>
$($rows -join "`n")
</tbody>
</table>

<h2>📜 License Audit</h2>
<table>
<thead>
<tr><th>Package</th><th>Version</th><th>License</th><th>Risk</th><th>URL</th><th>Projects</th></tr>
</thead>
<tbody>
$($licenseRows -join "`n")
</tbody>
</table>

</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "`n💾 HTML saved: $htmlPath" -ForegroundColor Green
Start-Process $htmlPath