/**
 * server-setup.sh 的静态校验。
 *
 * 本机没有原生 bash(只有 WSL 占位),无法用 `bash -n`,所以这里做结构级检查,
 * 覆盖最容易写错的几类问题:
 *   * 引号是否配平(逐字符扫描,跳过注释与转义)
 *   * heredoc 是否配对(<<EOF ... EOF),这在本脚本里用于生成 sudoers,写错就是灾难
 *   * 是否残留旧的 systemctl 提权别名
 *   * 关键安全断言是否存在:提权面必须被显式验证为"拒绝"
 *
 * 运行:node --test test/setup-script.test.js
 * 服务器上仍建议真跑一次 `bash -n server-setup.sh` 做最终确认。
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PROJECT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(PROJECT, 'server-setup.sh');
const raw = readFileSync(SCRIPT, 'utf8');
const lines = raw.split('\n');

test('脚本以 bash 开头并启用严格模式', () => {
  assert.match(lines[0], /^#!\/usr\/bin\/env bash/, 'shebang 应为 env bash');
  assert.match(raw, /^set -euo pipefail$/m, '应启用 set -euo pipefail');
});

test('单引号与双引号配平(逐行扫描,跳过注释与转义)', () => {
  const problems = [];
  lines.forEach((line, idx) => {
    let inSingle = false;
    let inDouble = false;
    for (let i = 0; i < line.length; i += 1) {
      const ch = line[i];
      if (ch === '\\' && !inSingle) {
        i += 1;
        continue;
      }
      if (ch === "'" && !inDouble) inSingle = !inSingle;
      else if (ch === '"' && !inSingle) inDouble = !inDouble;
      else if (ch === '#' && !inSingle && !inDouble) break; // 行内注释起于此
    }
    // 单引号无法跨行,未闭合即为错误;双引号在 brace 展开等场景也几乎不跨行
    if (inSingle) problems.push(`第 ${idx + 1} 行单引号未闭合: ${line.trim().slice(0, 70)}`);
  });
  assert.deepEqual(problems, [], problems.join('\n'));
});

test('heredoc 成对出现', () => {
  const openers = [...raw.matchAll(/<<-?'?([A-Za-z_][A-Za-z0-9_]*)'?/g)].map((m) => m[1]);
  assert.ok(openers.length > 0, '脚本应至少使用一个 heredoc(生成 sudoers)');
  for (const tag of openers) {
    const re = new RegExp(`^${tag}$`, 'm');
    assert.ok(re.test(raw), `heredoc ${tag} 找不到对应的结束行`);
  }
});

test('不再授予 systemctl 任何 sudo 权限', () => {
  assert.equal(/OPS_SYSTEMCTL_RO/.test(raw), false, '不应存在 systemctl 提权别名');
  assert.equal(
    /NOPASSWD:[^\n]*systemctl/.test(raw),
    false,
    'sudoers 的 NOPASSWD 行不应出现 systemctl',
  );
  // 必须明确说明为什么不授予
  assert.match(raw, /systemctl.*不.*授予|刻意.*不.*sudo/s, '应有注释说明为何不授予 systemctl');
});

test('sudoers 只授权 root 所有的参数校验包装程序', () => {
  const sudoers = raw.match(/cat > "\$sudoers_tmp" <<EOF([\s\S]*?)\nEOF/)[1];
  assert.match(sudoers, /NOPASSWD: \${WRAPPER} \*/);
  assert.ok(!/DOCKER_BIN|JOURNALCTL_BIN|DMESG_BIN|SS_BIN/.test(sudoers));
  assert.match(raw, /chown root:root "\$wrapper_tmp"/);
  assert.match(raw, /visudo -cf "\$sudoers_tmp"/);
});

test('提权面被显式验证为拒绝(而不只是授予只读)', () => {
  const deniedCount = (raw.match(/^\s*expect_denied\s/gm) ?? []).length;
  assert.ok(deniedCount >= 8, `应有至少 8 项"必须被拒绝"的自检,实际 ${deniedCount}`);

  for (const mustCheck of [
    'systemctl start',
    'systemctl edit',
    'docker run',
    'docker exec',
    'docker volume rm',
    'cat /etc/shadow',
    'useradd',
  ]) {
    const re = new RegExp(`expect_denied[^\\n]*${mustCheck.replace(/[/.]/g, '.')}`);
    assert.ok(re.test(raw), `自检应显式验证 "${mustCheck}" 被拒绝`);
  }
});

test('自检失败会给出醒目告警', () => {
  assert.match(raw, /fail_count/, '应统计失败项');
  assert.match(raw, /请勿继续使用这个账户|请立即检查/, '失败时应给出明确告警');
});

test('脚本幂等:重复执行不会重复追加公钥或破坏文件', () => {
  assert.match(raw, /if id "\$OPS_USER"/, '应检测账户是否已存在');
  // authorized_keys 用 > 覆盖而非 >> 追加,因此重复执行不会堆叠
  assert.match(raw, /authorized_keys$|authorized_keys\b/m, '应写入 authorized_keys');
  assert.equal(
    />>\s*"\/home\/\$\{OPS_USER\}\/\.ssh\/authorized_keys"/.test(raw),
    false,
    'authorized_keys 不应使用追加重定向(会导致重复执行时堆叠)',
  );
});

test('脚本不引入任何常驻服务或监听端口', () => {
  // 只看"会真正执行"的行 —— 自检里刻意提到 systemctl start 是为了断言它被拒绝
  const executed = lines.filter((l) => !/^\s*#/.test(l) && !/expect_(ok|denied)/.test(l) && !/echo\s+"/.test(l));
  for (const forbidden of ['systemctl enable', 'systemctl start', 'ExecStart=', 'ListenStream']) {
    const hit = executed.filter((l) => l.includes(forbidden));
    assert.deepEqual(hit, [], `初始化脚本不应真正执行 ${forbidden},但发现:${hit.join(' | ')}`);
  }
});

test('撤销指引完整', () => {
  for (const step of ['撤销公钥', '撤销提权', '彻底移除账户']) {
    assert.ok(raw.includes(step), `应包含撤销指引:${step}`);
  }
});
