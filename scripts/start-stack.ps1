# Starts the stack: uses the existing external Postgres if reachable,
# otherwise falls back to the local "postgres" container defined in docker-compose.yml.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$envVars = @{}
Get-Content .env | ForEach-Object {
    if ($_ -match '^\s*(DD_DATABASE_(?:HOST|PORT|NAME|USER|PASSWORD))=(.*)$') {
        $envVars[$Matches[1]] = $Matches[2]
    }
}

$dbHost = $envVars['DD_DATABASE_HOST']
if (-not $dbHost) { $dbHost = "postgres" }
$dbPort = $envVars['DD_DATABASE_PORT']
if (-not $dbPort) { $dbPort = 5432 }

$dbReachable = (Test-NetConnection -ComputerName $dbHost -Port $dbPort -WarningAction SilentlyContinue).TcpTestSucceeded

if ($dbReachable) {
    Write-Host "Postgres tai ${dbHost}:${dbPort} da san sang -> dung truc tiep, bo qua container postgres."
    $services = (docker compose config --services) -split "`n" | Where-Object { $_ -and $_ -ne "postgres" }
    docker compose up -d @services
} else {
    Write-Host "Khong ket noi duoc ${dbHost}:${dbPort} -> khoi tao postgres bang container local."
    $env:DD_DATABASE_HOST = "postgres"
    $env:DD_DATABASE_PORT = "5432"
    docker compose up -d
}
