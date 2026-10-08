#!/usr/bin/env pwsh
<#
.SYNOPSIS
  兼容入口:转发到 deploy.ps1(唯一实现)。

.DESCRIPTION
  所有部署逻辑由 deploy.ps1 实现;仅转发用户显式提供的参数。

.EXAMPLE
  .\setup-local.ps1                      # 等价于 .\deploy.ps1(完整一键部署)
  .\setup-local.ps1 -BootstrapOnly        # 只接入清单,暂不启用 MCP 通道
  .\setup-local.ps1 -TargetHost 192.0.2.10   # 指定目标
#>
[CmdletBinding()]
param(
  [string]$Directory,
  [string]$KeyName = 'vps_ops_ed25519',
  [string]$TargetHost,
  [string]$Name,
  [switch]$Force,
  [switch]$BootstrapOnly,
  [ValidateRange(1,65535)][int]$Port = 22,
  [string]$ExpectedFingerprint,
  [string]$ViaExistingUser,
  [switch]$NoSudo,
  [switch]$UpdateServer,
  [string]$ProfileFile,
  [string]$InventoryPath
)

$ErrorActionPreference = 'Stop'
$deploy = Join-Path $PSScriptRoot 'deploy.ps1'
if (-not (Test-Path $deploy)) {
  Write-Host "[失败] 找不到 $deploy" -ForegroundColor Red
  exit 1
}

Write-Host '[i] setup-local.ps1 已改为 deploy.ps1 的转发入口(避免两套实现分叉)' -ForegroundColor DarkGray

$forward = @{}
if ($Directory) { $forward.CredDir = $Directory }
foreach ($paramName in @('KeyName', 'InventoryPath', 'TargetHost', 'Name', 'Force', 'BootstrapOnly', 'Port', 'ExpectedFingerprint', 'ViaExistingUser', 'NoSudo', 'UpdateServer', 'ProfileFile')) {
  if ($PSBoundParameters.ContainsKey($paramName)) { $forward[$paramName] = $PSBoundParameters[$paramName] }
}
& $deploy @forward
exit $LASTEXITCODE
