# ==============================================================================
#  Vestigo SOC Intelligence Platform -- Instalador automatico
#  Uso: .\install.ps1
# ==============================================================================

$ErrorActionPreference = "Stop"

function Write-Step { param($msg) Write-Host "`n  >> $msg" -ForegroundColor Cyan }
function Write-Ok   { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "  [X]  $msg" -ForegroundColor Red }
function Write-Info { param($msg) Write-Host "       $msg" -ForegroundColor DarkGray }

# ------------------------------------------------------------------------------
Clear-Host
Write-Host ""
Write-Host "  VESTIGO - SOC Intelligence Platform" -ForegroundColor Blue
Write-Host "  =====================================" -ForegroundColor Blue
Write-Host "  Instalador automatico" -ForegroundColor White
Write-Host ""

# -- 1. Docker instalado -------------------------------------------------------
Write-Step "Verificando pre-requisitos..."

if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
    Write-Fail "Docker nao encontrado."
    Write-Info "Instale o Docker Desktop: https://www.docker.com/products/docker-desktop/"
    exit 1
}
Write-Ok "Docker encontrado"

# -- 2. Docker rodando ---------------------------------------------------------
$dockerOk = $false
try {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { $dockerOk = $true }
} catch {}

if (-not $dockerOk) {
    Write-Warn "Docker Desktop nao esta rodando."
    $iniciar = Read-Host "  Tentar iniciar o Docker Desktop agora? (s/n)"
    if ($iniciar -eq "s") {
        $dockerExe = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
        if (Test-Path $dockerExe) {
            Start-Process $dockerExe
        } else {
            Write-Fail "Docker Desktop.exe nao encontrado. Inicie manualmente."
            exit 1
        }
        Write-Info "Aguardando Docker inicializar (ate 90s)..."
        for ($i = 0; $i -lt 18; $i++) {
            Start-Sleep 5
            docker info 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $dockerOk = $true; break }
            Write-Host "." -NoNewline -ForegroundColor DarkGray
        }
        Write-Host ""
    }
    if (-not $dockerOk) {
        Write-Fail "Docker nao respondeu. Abra o Docker Desktop manualmente e execute o instalador novamente."
        exit 1
    }
}
Write-Ok "Docker esta rodando"

# -- 3. docker-compose ---------------------------------------------------------
$usePlugin = $false
if (Get-Command "docker-compose" -ErrorAction SilentlyContinue) {
    Write-Ok "docker-compose encontrado"
} else {
    docker compose version 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $usePlugin = $true
        Write-Ok "docker compose (plugin) encontrado"
    } else {
        Write-Fail "docker-compose nao encontrado. Atualize o Docker Desktop."
        exit 1
    }
}

function Invoke-Compose {
    if ($usePlugin) { docker compose @args } else { docker-compose @args }
}

# -- 4. Diretorio do projeto ---------------------------------------------------
Write-Step "Localizando o projeto..."

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeFile = Join-Path $scriptDir "docker-compose.yml"

if (-not (Test-Path $composeFile)) {
    Write-Fail "docker-compose.yml nao encontrado em: $scriptDir"
    Write-Info "Execute este script na pasta raiz do Vestigo."
    exit 1
}

Set-Location $scriptDir
Write-Ok "Projeto em: $scriptDir"

# -- 5. Configurar .env --------------------------------------------------------
Write-Step "Configurando variaveis de ambiente..."

$envFile    = Join-Path $scriptDir ".env"
$envExample = Join-Path $scriptDir ".env.example"

if (Test-Path $envFile) {
    Write-Warn ".env ja existe -- mantendo configuracao atual."
    Write-Info "Delete o arquivo .env e execute novamente para reconfigurar."
} else {
    if (-not (Test-Path $envExample)) {
        Write-Fail ".env.example nao encontrado."
        exit 1
    }

    Copy-Item $envExample $envFile

    # Gerar INTERNAL_API_SECRET via CSPRNG do .NET
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $secret = [System.BitConverter]::ToString($bytes).Replace("-", "").ToLower()

    $bytes2 = New-Object byte[] 16
    $rng.GetBytes($bytes2)
    $dbPass = [System.BitConverter]::ToString($bytes2).Replace("-", "")

    (Get-Content $envFile) `
        -replace "INTERNAL_API_SECRET=.*", "INTERNAL_API_SECRET=$secret" `
        -replace "POSTGRES_PASSWORD=.*",   "POSTGRES_PASSWORD=$dbPass" |
        Set-Content $envFile -Encoding utf8
    Write-Ok "Secrets gerados automaticamente"

    # Provider LLM
    Write-Host ""
    Write-Host "  Escolha o provider de IA:" -ForegroundColor White
    Write-Host "    1) Groq   - LLaMA 3.3 70B, gratuito (recomendado)" -ForegroundColor Gray
    Write-Host "    2) OpenAI - GPT-4o" -ForegroundColor Gray
    Write-Host "    3) Ollama - 100% local, sem internet, sem chave de API" -ForegroundColor Gray
    Write-Host ""

    do { $choice = Read-Host "  Opcao [1/2/3]" } while ($choice -notin @("1","2","3"))

    switch ($choice) {
        "1" {
            Write-Host ""
            Write-Host "  Obtenha sua chave em: https://console.groq.com/keys" -ForegroundColor DarkGray
            $apiKey = Read-Host "  GROQ_API_KEY (Enter para configurar depois)"
            $content = (Get-Content $envFile) -replace "LLM_PROVIDER=.*", "LLM_PROVIDER=groq"
            if ($apiKey) { $content = $content -replace "GROQ_API_KEY=.*", "GROQ_API_KEY=$apiKey" }
            $content | Set-Content $envFile -Encoding utf8
            Write-Ok "Provider: Groq"
        }
        "2" {
            Write-Host ""
            Write-Host "  Obtenha sua chave em: https://platform.openai.com/api-keys" -ForegroundColor DarkGray
            $apiKey = Read-Host "  OPENAI_API_KEY (Enter para configurar depois)"
            $content = (Get-Content $envFile) -replace "LLM_PROVIDER=.*", "LLM_PROVIDER=openai"
            if ($apiKey) { $content = $content -replace "OPENAI_API_KEY=.*", "OPENAI_API_KEY=$apiKey" }
            $content | Set-Content $envFile -Encoding utf8
            Write-Ok "Provider: OpenAI"
        }
        "3" {
            (Get-Content $envFile) -replace "LLM_PROVIDER=.*", "LLM_PROVIDER=ollama" |
                Set-Content $envFile -Encoding utf8
            Write-Ok "Provider: Ollama (modo offline)"
            Write-Warn "O modelo qwen2.5:7b (~4.4 GB) sera baixado na primeira execucao."
        }
    }

    # Enriquecimento (opcional)
    Write-Host ""
    $addEnrich = Read-Host "  Configurar AbuseIPDB e VirusTotal agora? (s/n)"
    if ($addEnrich -eq "s") {
        $abKey = Read-Host "  ABUSEIPDB_API_KEY"
        $vtKey = Read-Host "  VIRUSTOTAL_API_KEY"
        $content = Get-Content $envFile
        if ($abKey) { $content = $content -replace "ABUSEIPDB_API_KEY=.*", "ABUSEIPDB_API_KEY=$abKey" }
        if ($vtKey) { $content = $content -replace "VIRUSTOTAL_API_KEY=.*", "VIRUSTOTAL_API_KEY=$vtKey" }
        $content | Set-Content $envFile -Encoding utf8
        Write-Ok "Chaves de enriquecimento configuradas"
    }

    Write-Ok ".env configurado"
}

# -- 6. Build e start ----------------------------------------------------------
Write-Step "Construindo e iniciando os containers..."
Write-Info "Isso pode levar alguns minutos na primeira execucao."
Write-Host ""

$envContent = Get-Content $envFile -Raw
$useOllama  = $envContent -match "LLM_PROVIDER\s*=\s*ollama"

try {
    if ($useOllama) {
        Write-Warn "Modo Ollama ativo -- usando profile ollama..."
        Invoke-Compose --profile ollama up --build -d
    } else {
        Invoke-Compose up --build -d
    }
} catch {
    Write-Fail "Falha ao iniciar os containers."
    Write-Info "Verifique os logs com: docker-compose logs"
    exit 1
}

# -- 7. Health check -----------------------------------------------------------
Write-Step "Aguardando os servicos ficarem prontos..."

$maxWait = 90
$interval = 3
$elapsed  = 0
$ready    = $false

while ($elapsed -lt $maxWait) {
    Start-Sleep $interval
    $elapsed += $interval
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
    Write-Host "." -NoNewline -ForegroundColor DarkGray
}
Write-Host ""

if ($ready) {
    Write-Ok "Todos os servicos estao prontos"
} else {
    Write-Warn "Servicos ainda inicializando. Tente acessar http://localhost:8000 em instantes."
}

# -- 8. Resumo -----------------------------------------------------------------
Write-Host ""
Write-Host "  ======================================================" -ForegroundColor DarkGray
Write-Host "  Vestigo instalado com sucesso!" -ForegroundColor Green
Write-Host "  ======================================================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Acesse:" -ForegroundColor White
Write-Host "    http://localhost:8000                   Analisar logs" -ForegroundColor Cyan
Write-Host "    http://localhost:8000/dashboard.html    Dashboard" -ForegroundColor Cyan
Write-Host "    http://localhost:8000/settings.html     Configuracoes" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Comandos uteis:" -ForegroundColor White
Write-Host "    docker-compose ps          status dos containers" -ForegroundColor DarkGray
Write-Host "    docker-compose logs -f     logs em tempo real" -ForegroundColor DarkGray
Write-Host "    docker-compose down        parar tudo" -ForegroundColor DarkGray
Write-Host "    docker-compose up -d       iniciar novamente" -ForegroundColor DarkGray
Write-Host ""

# -- 9. Abrir navegador --------------------------------------------------------
if ($ready) {
    try {
        $open = Read-Host "  Abrir no navegador agora? (s/n)"
        if ($open -eq "s") { Start-Process "http://localhost:8000" }
    } catch {
        Start-Process "http://localhost:8000"
    }
}

Write-Host ""
