# Prepara un clone nuovo: ambiente, certificati, TPM, container e healthcheck.
[CmdletBinding()]
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$PreviousComposeBake = $env:COMPOSE_BAKE
$env:COMPOSE_BAKE = "false"

function Write-Step {
    param([string]$Message)
    Write-Host "[STEP] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Fail {
    param([string]$Message)
    throw $Message
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "Comando fallito ($LASTEXITCODE): $Command $($Arguments -join ' ')"
    }
}

function Find-GitBash {
    $Candidates = @(
        "$env:ProgramFiles\Git\bin\bash.exe",
        "$env:ProgramFiles\Git\usr\bin\bash.exe",
        "${env:ProgramFiles(x86)}\Git\bin\bash.exe"
    )

    foreach ($Candidate in $Candidates) {
        if ($Candidate -and (Test-Path -LiteralPath $Candidate)) {
            return $Candidate
        }
    }

    $Git = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($Git) {
        $GitRoot = Split-Path -Parent (Split-Path -Parent $Git.Source)
        $Candidate = Join-Path $GitRoot "bin\bash.exe"
        if (Test-Path -LiteralPath $Candidate) {
            return $Candidate
        }
    }

    return $null
}

function Initialize-Environment {
    if (Test-Path -LiteralPath ".env") {
        Write-Ok "File .env gia presente: valori conservati"
        return
    }

    if (-not (Test-Path -LiteralPath ".env.example")) {
        Fail "File .env.example mancante"
    }

    $Content = Get-Content -LiteralPath ".env.example" -Raw
    $Content = $Content.Replace("CHANGE_ME_MONGO_ROOT_2026!", "MongoPassword123!")
    $Content = $Content.Replace("CHANGE_ME_MONGO_APP_2026!", "MongoPassword123!")
    $Content = $Content.Replace("CHANGE_ME_SPLUNK_ADMIN_2026!", "SplunkPassword123!")
    $Content = $Content.Replace(
        "00000000-0000-0000-0000-000000000000",
        [guid]::NewGuid().ToString()
    )

    Set-Content -LiteralPath ".env" -Value $Content -Encoding ASCII
    Write-Ok "Creato .env con credenziali dimostrative e token HEC univoco"
}

function Test-AllFiles {
    param([string[]]$Paths)

    foreach ($Path in $Paths) {
        if (-not (Test-Path -LiteralPath $Path)) {
            return $false
        }
    }

    return $true
}

function Invoke-BashScript {
    param(
        [Parameter(Mandatory = $true)][string]$Bash,
        [Parameter(Mandatory = $true)][string]$Script
    )

    $env:MSYS2_ARG_CONV_EXCL = "*"
    & $Bash $Script
    if ($LASTEXITCODE -ne 0) {
        Fail "Script fallito: $Script"
    }
}

function Get-ContainerHealth {
    param([string]$Service)

    $ContainerId = (& docker compose --profile testing ps -q $Service 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $ContainerId) {
        return "missing"
    }

    $Status = (& docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" $ContainerId 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $Status) {
        return "unknown"
    }

    return $Status.Trim()
}

function Wait-Service {
    param(
        [Parameter(Mandatory = $true)][string]$Service,
        [int]$TimeoutSeconds = 300
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $LastStatus = ""

    while ((Get-Date) -lt $Deadline) {
        $Status = Get-ContainerHealth $Service
        if ($Status -ne $LastStatus) {
            Write-Host "[WAIT] $Service -> $Status"
            $LastStatus = $Status
        }

        if ($Status -eq "healthy" -or $Status -eq "running") {
            Write-Ok "$Service pronto"
            return
        }

        if ($Status -in @("unhealthy", "exited", "dead")) {
            & docker compose --profile testing logs --tail 80 $Service
            Fail "$Service non e avviato correttamente: $Status"
        }

        Start-Sleep -Seconds 5
    }

    & docker compose --profile testing logs --tail 80 $Service
    Fail "Timeout durante l'attesa di $Service (ultimo stato: $LastStatus)"
}

try {
    Write-Step "Controllo dei prerequisiti"

    if (-not (Get-Command docker.exe -ErrorAction SilentlyContinue)) {
        Fail "Docker Desktop non e installato o non e nel PATH"
    }

    Invoke-Checked docker info
    Invoke-Checked docker compose version

    $Bash = Find-GitBash
    if (-not $Bash) {
        Fail "Git Bash non trovato. Installare Git for Windows e riprovare"
    }
    Write-Ok "Git Bash rilevato"

    Write-Step "Preparazione del file .env"
    Initialize-Environment

    Write-Step "Inizializzazione dei dati runtime"
    Invoke-BashScript -Bash $Bash -Script "scripts/init_runtime.sh"

    Write-Step "Validazione della configurazione Docker Compose"
    Invoke-Checked docker compose --profile testing config --quiet

    $InfrastructureCertificates = @(
        "certs\ca\ca.crt",
        "certs\ca\ca.key",
        "certs\server\server.crt",
        "certs\server\server.key",
        "certs\mongodb\mongodb-server.pem",
        "certs\mongodb\api-client.pem",
        "certs\mongodb\healthcheck-client.pem"
    )

    if (-not (Test-AllFiles $InfrastructureCertificates)) {
        Write-Step "Generazione della PKI infrastrutturale"
        Invoke-BashScript -Bash $Bash -Script "scripts/generate_certs.sh"
    }
    else {
        Write-Ok "Certificati infrastrutturali gia presenti"
    }

    Write-Step "Provisioning delle identita TPM"
    $PreviousBindingsFile = $env:BINDINGS_FILE
    try {
        $env:BINDINGS_FILE = "scripts/identity_bindings.testing.conf"
        Invoke-BashScript -Bash $Bash -Script "scripts/generate_device_certs.sh"
    }
    finally {
        if ($null -eq $PreviousBindingsFile) {
            Remove-Item Env:BINDINGS_FILE -ErrorAction SilentlyContinue
        }
        else {
            $env:BINDINGS_FILE = $PreviousBindingsFile
        }
    }

    Write-Step "Controlli preliminari"
    Invoke-BashScript -Bash $Bash -Script "scripts/preflight.sh"

    Write-Step "Avvio dello stack completo"
    $UpArguments = @("compose", "--profile", "testing", "up", "-d")
    if (-not $SkipBuild) {
        $UpArguments += "--build"
    }
    Invoke-Checked docker @UpArguments

    Write-Step "Attesa dei servizi principali"
    $CoreServices = @(
        "db_primary",
        "api_backend",
        "pdp_engine",
        "firewall_perimeter",
        "pep_gateway",
        "ids_network_monitor",
        "swtpm_d001",
        "swtpm_d002",
        "swtpm_dsoc",
        "client_d001_tpm",
        "client_d002_tpm",
        "client_dsoc_tpm"
    )

    foreach ($Service in $CoreServices) {
        Wait-Service -Service $Service -TimeoutSeconds 360
    }

    Wait-Service -Service "siem_central" -TimeoutSeconds 720

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "AMBIENTE PRONTO PER I TEST" -ForegroundColor Green
    Write-Host "Splunk: http://localhost:8000"
    Write-Host "Login Splunk: admin / valore SPLUNK_PASSWORD nel file .env"
    Write-Host "============================================================" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "[ERRORE] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    if ($null -eq $PreviousComposeBake) {
        Remove-Item Env:COMPOSE_BAKE -ErrorAction SilentlyContinue
    }
    else {
        $env:COMPOSE_BAKE = $PreviousComposeBake
    }
}
