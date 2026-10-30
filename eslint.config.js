import js from '@eslint/js';
import globals from 'globals';

/**
 * 代码风格与静态检查。
 *
 * 取舍说明:
 * - 只开 recommended 这一档(会抓未定义变量、不可达代码、重复键这类真问题),
 *   不加需要大改代码的规则。
 * - 风格规则挑的是这个仓库本来就在用的写法(单引号、分号、2 空格、EOF 换行),
 *   所以接入时不需要重排文件。
 * - 格式化交给编辑器,不引入 Prettier:现有 46 个文件都没按 Prettier 排过,
 *   一旦启用要么 CI 一直红,要么一次性重排全部文件。
 */
export default [
  {
    // review-artifacts/ 与 keys/ 等一样已被 .gitignore 排除,是本地草稿,不进检查
    ignores: ['node_modules/**', 'output/**', 'coverage/**', '.pnpm-store/**', 'review-artifacts/**'],
  },
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.node },
    },
    rules: {
      // —— 风格:与现有代码保持一致 ——
      quotes: ['error', 'single', { avoidEscape: true, allowTemplateLiterals: true }],
      semi: ['error', 'always'],
      'no-var': 'error',
      'prefer-const': 'error',
      eqeqeq: ['error', 'smart'],
      'no-trailing-spaces': 'error',
      'eol-last': ['error', 'always'],
      'no-multiple-empty-lines': ['error', { max: 2, maxEOF: 1 }],

      // —— 实用:抓真正会咬人的地方 ——
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
      'no-implied-eval': 'error',
      'no-return-await': 'error',
      'require-atomic-updates': 'off',

      // 这个项目大量用 console 输出工具结果,不当作问题
      'no-console': 'off',

      // 这个项目是**靠匹配控制字符**来拒绝它们的(路径/主机名/命令里的 \x00-\x1f),
      // 正则里出现控制字符是本意,不是笔误
      'no-control-regex': 'off',
    },
  },
];
