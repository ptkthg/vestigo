# =============================================================================
#  Vestigo SOC Intelligence Platform — Instalador automático
#  Uso: .\install.ps1
# =============================================================================

$ErrorActionPreference = "Stop"

# ── Cores ─────────────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "`n  $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "  [X]  $msg" -ForegroundColor Red }
function Write-Info  { param($msg) Write-Host "       $msg" -ForegroundColor DarkGray }

# ── Banner ────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  ██╗   ██╗███████╗███████╗████████╗██╗ ██████╗  ██████╗ " -ForegroundColor Blue
Write-Host "  ██║   ██║██╔════╝██╔════╝╚══██╔══╝██║██╔════╝ ██╔═══██╗" -ForegroundColor Blue
Write-Host "  ██║   ██║█████╗  ███████╗   ██║   ██║██║  ███╗██║   ██║" -ForegroundColor Blue
Write-Host "  ╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   ██║██║   ██║██║   ██║" -ForegroundColor Blue
Write-Host "   ╚████╔╝ ███████╗███████║   ██║   ██║╚██████╔╝╚██████╔╝" -ForegroundColor Blue
Write-Host "    ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝  ╚═════╝ " -ForegroundColor Blue
Write-Host ""
Write-Host "  SOC Intelligence Platform — Instalador" -ForegroundColor White
Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# ── 1. Docker instalado ────────────────────────────────────────────────────────
Write-Step "Verificando pré-requisitos..."

if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
    Write-Fail "Docker não encontrado."
    Write-Info "Instale o Docker Desktop: https://www.docker.com/products/docker-desktop/"
    exit 1
}
Write-Ok "Docker encontrado"

# ── 2. Docker rodando ─────────────────────────────────────────────────────────
try {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Ok "Docker está rodando"
} catch {
    Write-Fail "Docker Desktop não está rodando."
    Write-Info "Inicie o Docker Desktop e tente novamente."

    $iniciar = Read-Host "`n  Tentar iniciar o Docker Desktop agora? (s/n)"
    if ($iniciar -eq "s") {
        Write-Warn "Iniciando Docker Desktop..."
        Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe" -ErrorAction SilentlyContinue
        Write-Info "Aguardando Docker inicializar (até 60s)..."
        $ok = $false
        for ($i = 0; $i -lt 12; $i++) {
            Start-Sleep 5
            $result = docker info 2>&1
            if ($LASTEXITCODE -eq 0) { $ok = $true; break }
            Write-Host "." -NoNewline -ForegroundColor DarkGray
        }
        Write-Host ""
        if (-not $ok) {
            Write-Fail "Docker não respondeu. Abra o Docker Desktop manualmente e execute o instalador novamente."
            exit 1
        }
        Write-Ok "Docker pronto"
    } else {
        exit 1
    }
}

# ── 3. docker-compose ─────────────────────────────────────────────────────────
if (-not (Get-Command "docker-compose" -ErrorAction SilentlyContinue)) {
    # Tenta via plugin
    docker compose version 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "docker-compose não encontrado. Atualize o Docker Desktop."
        exit 1
    }
    Set-Alias -Name docker-compose -Value { docker compose @args } -Scope Script
}
Write-Ok "docker-compose disponível"

# ── 4. Diretório do projeto ───────────────────────────────────────────────────
Write-Step "Localizando o projeto..."

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeFile = Join-Path $scriptDir "docker-compose.yml"

if (-not (Test-Path $composeFile)) {
    Write-Fail "docker-compose.yml não encontrado em: $scriptDir"
    Write-Info "Execute este script na pasta raiz do Vestigo."
    exit 1
}

Set-Location $scriptDir
Write-Ok "Projeto encontrado em: $scriptDir"

# ── 5. Configurar .env ────────────────────────────────────────────────────────
Write-Step "Configurando variáveis de ambiente..."

$envFile = Join-Path $scriptDir ".env"
$envExample = Join-Path $scriptDir ".env.example"

if (Test-Path $envFile) {
    Write-Warn ".env já existe — mantendo configuração atual."
    Write-Info "Delete o arquivo .env e execute novamente para reconfigurar."
} else {
    if (-not (Test-Path $envExample)) {
        Write-Fail ".env.example não encontrado."
        exit 1
    }

    Copy-Item $envExample $envFile

    # Gerar INTERNAL_API_SECRET
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $secret = [System.BitConverter]::ToString($bytes).Replace("-", "").ToLower()
    (Get-Content $envFile) -replace "INTERNAL_API_SECRET=.*", "INTERNAL_API_SECRET=$secret" |
        Set-Content $envFile -Encoding utf8
    Write-Ok "INTERNAL_API_SECRET gerado automaticamente"

    # Senha do banco
    $bytes2 = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes2)
    $dbPass = [System.BitConverter]::ToString($bytes2).Replace("-", "")
    (Get-Content $envFile) -replace "POSTGRES_PASSWORD=.*", "POSTGRES_PASSWORD=$dbPass" |
        Set-Content $envFile -Encoding utf8
    Write-Ok "POSTGRES_PASSWORD gerado automaticamente"

    # Escolha do provider LLM
    Write-Host ""
    Write-Host "  Escolha o provider de IA:" -ForegroundColor White
    Write-Host "    1) Groq   — LLaMA 3.3 70B, gratuito (recomendado)" -ForegroundColor Gray
    Write-Host "    2) OpenAI — GPT-4o" -ForegroundColor Gray
    Write-Host "    3) Ollama — 100% local, sem internet, sem chave de API" -ForegroundColor Gray
    Write-Host ""

    do {
        $providerChoice = Read-Host "  Opção [1/2/3]"
    } while ($providerChoice -notin @("1","2","3"))

    switch ($providerChoice) {
        "1" {
            $provider = "groq"
            Write-Host ""
            Write-Host "  Obtenha sua chave em: https://console.groq.com/keys" -ForegroundColor DarkGray
            $apiKey = Read-Host "  GROQ_API_KEY (deixe vazio para configurar depois)"
            (Get-Content $envFile) -replace "LLM_PROVIDER=.*", "LLM_PROVIDER=groq" |
                Set-Content $envFile -Encoding utf8
            if ($apiKey) {
                (Get-Content $envFile) -replace "GROQ_API_KEY=.*", "GROQ_API_KEY=$apiKey" |
                    Set-Content $envFile -Encoding utf8
            }
            Write-Ok "Provider: Groq"
        }
        "2" {
            $provider = "openai"
            Write-Host ""
            Write-Host "  Obtenha sua chave em: https://platform.openai.com/api-keys" -ForegroundColor DarkGray
            $apiKey = Read-Host "  OPENAI_API_KEY (deixe vazio para configurar depois)"
            (Get-Content $envFile) -replace "LLM_PROVIDER=.*", "LLM_PROVIDER=openai" |
                Set-Content $envFile -Encoding utf8
            if ($apiKey) {
                (Get-Content $envFile) -replace "OPENAI_API_KEY=.*", "OPENAI_API_KEY=$apiKey" |
                    Set-Content $envFile -Encoding utf8
            }
            Write-Ok "Provider: OpenAI"
        }
        "3" {
            $provider = "ollama"
            (Get-Content $envFile) -replace "LLM_PROVIDER=.*", "LLM_PROVIDER=ollama" |
                Set-Content $envFile -Encoding utf8
            Write-Ok "Provider: Ollama (modo offline)"
            Write-Warn "O modelo qwen2.5:7b (~4.4 GB) será baixado na primeira execução."
        }
    }

    # Chaves de enriquecimento (opcionais)
    Write-Host ""
    $addEnrich = Read-Host "  Configurar AbuseIPDB e VirusTotal agora? (s/n)"
    if ($addEnrich -eq "s") {
        $abKey = Read-Host "  ABUSEIPDB_API_KEY"
        $vtKey = Read-Host "  VIRUSTOTAL_API_KEY"
        if ($abKey) {
            (Get-Content $envFile) -replace "ABUSEIPDB_API_KEY=.*", "ABUSEIPDB_API_KEY=$abKey" |
                Set-Content $envFile -Encoding utf8
        }
        if ($vtKey) {
            (Get-Content $envFile) -replace "VIRUSTOTAL_API_KEY=.*", "VIRUSTOTAL_API_KEY=$vtKey" |
                Set-Content $envFile -Encoding utf8
        }
        Write-Ok "Chaves de enriquecimento configuradas"
    }

    Write-Ok ".env configurado"
}

# ── 6. Build e start ──────────────────────────────────────────────────────────
Write-Step "Construindo e iniciando os containers..."
Write-Info "Isso pode levar alguns minutos na primeira execução."
Write-Host ""

# Detecta provider do .env para saber se usa profile ollama
$envContent = Get-Content $envFile -Raw
$useOllama = $envContent -match "LLM_PROVIDER=ollama"

try {
    if ($useOllama) {
        Write-Warn "Modo Ollama ativo — iniciando com profile ollama..."
        docker-compose --profile ollama up --build -d 2>&1 | ForEach-Object { Write-Info $_ }
    } else {
        docker-compose up --build -d 2>&1 | ForEach-Object { Write-Info $_ }
    }
} catch {
    Write-Fail "Falha ao iniciar os containers: $_"
    Write-Info "Verifique os logs com: docker-compose logs"
    exit 1
}

# ── 7. Health check ───────────────────────────────────────────────────────────
Write-Step "Aguardando os serviços ficarem prontos..."

$maxWait = 60
$interval = 3
$elapsed = 0
$ready = $false

while ($elapsed -lt $maxWait) {
    Start-Sleep $interval
    $elapsed += $interval
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {}
    Write-Host "." -NoNewline -ForegroundColor DarkGray
}
Write-Host ""

if (-not $ready) {
    Write-Warn "Serviços ainda inicializando. Verifique com: docker-compose ps"
    Write-Info "Acesse http://localhost:8000 em alguns instantes."
} else {
    Write-Ok "Todos os serviços estão prontos"
}

# ── 8. Resumo ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Vestigo instalado com sucesso!" -ForegroundColor Green
Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Acesse:" -ForegroundColor White
Write-Host "    http://localhost:8000              — Analisar logs" -ForegroundColor Cyan
Write-Host "    http://localhost:8000/dashboard.html  — Dashboard" -ForegroundColor Cyan
Write-Host "    http://localhost:8000/settings.html   — Configurações" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Comandos úteis:" -ForegroundColor White
Write-Host "    docker-compose ps            — status dos containers" -ForegroundColor DarkGray
Write-Host "    docker-compose logs -f       — logs em tempo real" -ForegroundColor DarkGray
Write-Host "    docker-compose down          — parar tudo" -ForegroundColor DarkGray
Write-Host "    docker-compose up -d         — iniciar novamente" -ForegroundColor DarkGray
Write-Host ""

# ── 9. Abrir navegador ────────────────────────────────────────────────────────
if ($ready) {
    $openBrowser = Read-Host "  Abrir no navegador agora? (s/n)"
    if ($openBrowser -eq "s") {
        Start-Process "http://localhost:8000"
    }
}

Write-Host ""
