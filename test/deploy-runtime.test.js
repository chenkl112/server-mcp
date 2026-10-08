import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, copyFileSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { parse } from 'yaml';
import { configureProfile, PROJECT } from '../src/profile.js';
import { PUB_PATH, KEY_PATH } from './helpers/paths.js';
import { powershellEnv } from './helpers/powershell.js';

const ps = s => `'${s.replaceAll("'", "''")}'`;
const windows = { skip: process.platform !== 'win32' };
const raw = readFileSync(join(PROJECT, 'deploy.ps1'), 'utf8');
const acl = raw.match(/function Lock-Acl[\s\S]*?\r?\n}/)[0];

test('通过 powershell -File 启动时默认清单相对脚本目录解析', windows, () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-cli-'));
  try {
    const script = join(dir, 'deploy.ps1');
    writeFileSync(script, '\uFEFF' + raw.replace(/^\uFEFF/, ''));
    const env = powershellEnv();
    delete env.DSH_VPS_INVENTORY;
    const result = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-File', script], { encoding: 'utf8', env });
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.ok(result.stdout.includes(join(dir, 'servers.json')), result.stdout + result.stderr);
    assert.equal(result.stderr.includes('ParameterArgumentValidationErrorEmptyString'), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

function deploy({ denyCode = 1, pins = ['SHA256:fixture'], expected = 'SHA256:fixture', groups = 'ops-us', freshKey = false, explicitKey = true, profileFile = true, duplicateKeygen = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'mcp deploy runtime-'));
  mkdirSync(join(dir, 'credentials'));
  const key = join(dir, 'credentials', 'key');
  if (!freshKey) copyFileSync(KEY_PATH, key);
  const pub = readFileSync(PUB_PATH, 'utf8').trim();
  if (!freshKey) writeFileSync(`${key}.pub`, pub);
  const inv = join(dir, 'servers.json');
  writeFileSync(inv, JSON.stringify({ default: 'fixture', servers: { fixture: { host: '192.0.2.1', port: 2222, user: 'ops-us', key, fingerprints: pins, note: 'preserved' } } }));
  writeFileSync(join(dir, 'deploy.ps1'), '\uFEFF' + raw.replace(/^\uFEFF/, ''));
  const marker = join(dir, 'enabled');
  const calls = join(dir, 'ssh-calls.jsonl');
  const harness = `
    $ErrorActionPreference = 'Stop'
    function Test-NetConnection { return $true }
    function ssh-keygen { $global:LASTEXITCODE = 0; return ${ps(pub)} }
    function node {
      $global:LASTEXITCODE = 0
      if ($args[0] -like '*verify-host-fingerprint.js') {
        return '{"observedFingerprint":"SHA256:fixture","observedPublicKey":"ssh-ed25519 AAAA"}'
      }
      if ($args[0] -like '*configure-profile.js') { Set-Content -LiteralPath ${ps(marker)} -Value profile }
      if ($args[0] -like '*configure-mcp.js') { Set-Content -LiteralPath ${ps(marker)} -Value generic }
    }
    function ssh {
      Add-Content -LiteralPath ${ps(calls)} -Value (ConvertTo-Json -Compress -InputObject @($args))
      $cmd = $args[-1]
      $global:LASTEXITCODE = 0
      if ($cmd -eq 'id') { return 'uid=1001(ops-us)' }
      if ($cmd -eq 'id -nG') { return ${ps(groups)} }
      if ($cmd -like 'sudo -n -l -- *') { $global:LASTEXITCODE = ${denyCode}; return }
      if ($cmd -match 'systemctl (start|edit|stop)|docker (run|volume rm)|useradd|cat /etc/shadow') { throw 'A dangerous command was executed' }
      return 'safe diagnostic'
    }
    $env:VPS_OPS_CRED_DIR = ''
    $env:DSH_VPS_INVENTORY = ''
    ${duplicateKeygen ? `
    $extraBin = ${ps(join(dir, 'extra-bin'))}
    New-Item -ItemType Directory -Path $extraBin | Out-Null
    $keygen = (Get-Command ssh-keygen -CommandType Application | Select-Object -First 1).Source
    Copy-Item -LiteralPath $keygen -Destination (Join-Path $extraBin 'ssh-keygen.exe')
    $env:PATH += ';' + $extraBin
    if (@(Get-Command ssh-keygen -CommandType Application).Count -lt 2) { throw 'Duplicate executable fixture was not created' }
    ` : ''}
    & ${ps(join(dir, 'deploy.ps1'))} ${explicitKey ? `-CredDir ${ps(join(dir, 'credentials'))} -KeyName key` : ''} -ExpectedFingerprint ${ps(expected)} ${profileFile ? `-ProfileFile ${ps(join(dir, 'profile.yml'))}` : ''}
    exit $LASTEXITCODE
  `;
  const runner = join(dir, 'runner.ps1');
  writeFileSync(runner, '\uFEFF' + harness);
  const result = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-File', runner], { encoding: 'utf8', timeout: 20000, env: powershellEnv() });
  return { dir, result, marker, calls, inv };
}

test('验收拒绝查询成功/SSH 异常/特权组均禁止启用 MCP', windows, () => {
  for (const options of [{ denyCode: 0 }, { denyCode: 255 }, { groups: 'ops-us docker' }]) {
    const r = deploy(options);
    try {
      assert.equal(r.result.status, 1, r.result.stdout + r.result.stderr);
      assert.equal(existsSync(r.marker), false);
    } finally { rmSync(r.dir, { recursive: true, force: true }); }
  }
});
test('验收通过后才启用,全部 SSH 使用专用 known_hosts 与自定义端口', windows, () => {
  const r = deploy();
  try {
    assert.equal(r.result.status, 0, r.result.stdout + r.result.stderr);
    assert.ok(existsSync(r.marker));
    const calls = readFileSync(r.calls, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
    assert.ok(calls.length >= 10);
    for (const args of calls) {
      assert.ok(args.includes('2222'));
      assert.ok(args.some(a => a.startsWith('UserKnownHostsFile=')));
      assert.ok(args.includes('StrictHostKeyChecking=yes'));
    }
    assert.equal(readFileSync(join(r.dir, 'credentials', 'known_hosts-fixture'), 'utf8'), '[192.0.2.1]:2222 ssh-ed25519 AAAA\n');
    assert.equal(JSON.parse(readFileSync(r.inv)).servers.fixture.note, 'preserved');
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
});
test('Windows PowerShell 5.1 能生成无口令密钥,路径含空格也可部署', windows, () => {
  const r = deploy({ freshKey: true });
  try {
    assert.equal(r.result.status, 0, r.result.stdout + r.result.stderr);
    assert.ok(existsSync(join(r.dir, 'credentials', 'key')));
    assert.ok(existsSync(r.marker));
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
});
test('PATH 含多套 OpenSSH 时只选择第一套可执行程序', windows, () => {
  const r = deploy({ duplicateKeygen: true });
  try {
    assert.equal(r.result.status, 0, r.result.stdout + r.result.stderr);
    assert.ok(existsSync(r.marker));
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
});
test('默认复用清单密钥且仅生成通用配置,丢失已有密钥时中止', windows, () => {
  const r = deploy({ explicitKey: false, profileFile: false });
  try {
    assert.equal(r.result.status, 0, r.result.stdout + r.result.stderr);
    assert.equal(readFileSync(r.marker, 'utf8').trim().replace(/^\uFEFF/, ''), 'generic');
    assert.equal(JSON.parse(readFileSync(r.inv, 'utf8')).servers.fixture.key, join(r.dir, 'credentials', 'key'));
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
  const missing = deploy({ explicitKey: false, freshKey: true, profileFile: false });
  try {
    assert.equal(missing.result.status, 1, missing.result.stdout + missing.result.stderr);
    assert.equal(existsSync(join(missing.dir, 'credentials', 'key')), false);
    assert.equal(existsSync(missing.calls), false);
    assert.equal(existsSync(missing.marker), false);
  } finally { rmSync(missing.dir, { recursive: true, force: true }); }
});
test('首次独立核对不匹配时不写入信任、不发出 SSH 命令', windows, () => {
  const r = deploy({ pins: [], expected: 'SHA256:wrong' });
  try {
    assert.equal(r.result.status, 1, r.result.stdout + r.result.stderr);
    assert.equal(existsSync(r.calls), false);
    assert.equal(existsSync(join(r.dir, 'credentials', 'known_hosts-fixture')), false);
    assert.deepEqual(JSON.parse(readFileSync(r.inv)).servers.fixture.fingerprints, []);
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
});
test('setup-local 参数以名称正确转发,包含 KeyName 与开关', windows, () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-forward-'));
  try {
    copyFileSync(join(PROJECT, 'setup-local.ps1'), join(dir, 'setup-local.ps1'));
    writeFileSync(join(dir, 'deploy.ps1'), `param($TargetHost,$Name,$KeyName,$CredDir,$Port,$ExpectedFingerprint,[switch]$BootstrapOnly,[switch]$Force)\n$PSBoundParameters | ConvertTo-Json | Set-Content -LiteralPath ${ps(join(dir, 'out.json'))}\nexit 0\n`);
    const r = spawnSync('powershell', ['-NoProfile', '-File', join(dir, 'setup-local.ps1'), '-TargetHost', '192.0.2.9', '-Name', 'web1', '-KeyName', 'unique', '-Directory', dir, '-Port', '2222', '-BootstrapOnly', '-Force'], { encoding: 'utf8', env: powershellEnv() });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const result = JSON.parse(readFileSync(join(dir, 'out.json'), 'utf8').replace(/^\uFEFF/, ''));
    assert.equal(result.TargetHost, '192.0.2.9');
    assert.equal(result.KeyName, 'unique');
    assert.equal(result.CredDir, dir);
    assert.equal(result.Port, 2222);
    assert.ok(result.BootstrapOnly.IsPresent ?? result.BootstrapOnly);
    assert.ok(result.Force.IsPresent ?? result.Force);
    const implicit = spawnSync('powershell', ['-NoProfile', '-File', join(dir, 'setup-local.ps1'), '-TargetHost', '192.0.2.9'], { encoding: 'utf8', env: powershellEnv() });
    assert.equal(implicit.status, 0, implicit.stdout + implicit.stderr);
    const forwarded = JSON.parse(readFileSync(join(dir, 'out.json'), 'utf8').replace(/^\uFEFF/, ''));
    assert.equal(Object.hasOwn(forwarded, 'KeyName'), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('凭据 ACL 重建会移除显式 Everyone 和任意第三方 ACE', windows, () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-acl-'));
  const file = join(dir, 'fixture');
  writeFileSync(file, 'fixture');
  try {
    const script = `${acl}\n$a=Get-Acl -LiteralPath ${ps(file)}\n$a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('Everyone','Read','Allow')))\nSet-Acl -LiteralPath ${ps(file)} -AclObject $a\nLock-Acl ${ps(file)} -StripEveryone\n$a=Get-Acl -LiteralPath ${ps(file)}\nif (-not $a.AreAccessRulesProtected -or $a.Access.Count -ne 3) {exit 1}\nif ($a.Access | Where-Object {$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0'}) {exit 2}\n`;
    const r = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8', env: powershellEnv() });
    assert.equal(r.status, 0, r.stdout + r.stderr);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('YAML 更新不依赖字段顺序,保留其他配置与注释,拒绝重复条目', () => {
  const source = '# retained comment\n- id: other\n  config: {x: 1}\n- enabled: false\n  id: mcp-vps-ops\n  config: {custom: retained, args: [old]}\n';
  const result = configureProfile(source, { enabled: true });
  assert.match(result, /retained comment/);
  const entries = parse(result);
  assert.deepEqual(entries[0], { id: 'other', config: { x: 1 } });
  assert.equal(entries[1].enabled, true);
  assert.equal(entries[1].config.custom, 'retained');
  assert.equal(entries[1].config.args[0], join(PROJECT, 'src', 'index.js'));
  assert.throws(() => configureProfile('- id: mcp-vps-ops\n- id: mcp-vps-ops\n'));
  assert.throws(() => configureProfile('invalid: [yaml'));
});
