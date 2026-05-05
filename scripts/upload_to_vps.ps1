param(
    [Parameter(Mandatory = $true)]
    [string]$HostName,

    [string]$User = "root",
    [int]$Port = 22,
    [string]$RemoteDir = "/root/vps-init"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Files = @(
    "install.sh",
    "setup-ssh-key-login.sh",
    "README.md",
    "说明.md"
)

Write-Host "==> Local repo: $RepoRoot"
Write-Host "==> Target: $User@$HostName:$RemoteDir"

ssh -p $Port "$User@$HostName" "mkdir -p '$RemoteDir'"

foreach ($file in $Files) {
    $path = Join-Path $RepoRoot $file
    if (-not (Test-Path $path)) {
        throw "Missing file: $path"
    }
    scp -P $Port $path "$User@$HostName:$RemoteDir/"
}

ssh -p $Port "$User@$HostName" "chmod +x '$RemoteDir/install.sh' '$RemoteDir/setup-ssh-key-login.sh'"

Write-Host ""
Write-Host "Upload done."
Write-Host "Run in Xshell:"
Write-Host "  cd $RemoteDir"
Write-Host "  sudo bash ./install.sh menu"
