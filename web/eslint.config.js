import js from '@eslint/js';
import parser from '@babel/eslint-parser';
import security from 'eslint-plugin-security';
import hooks from 'eslint-plugin-react-hooks';

export default [
  { ignores: ['dist/**', 'node_modules/**'] },
  js.configs.recommended,
  security.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parser,
      parserOptions: {
        requireConfigFile: false,
        babelOptions: { plugins: ['@babel/plugin-syntax-typescript'], parserOpts: { plugins: ['jsx'] } },
      },
      globals: { document: 'readonly', localStorage: 'readonly' },
    },
    plugins: { 'react-hooks': hooks },
    // TypeScript's noUnusedLocals/noUnusedParameters checks JSX references and
    // type-only bindings correctly; ESLint's JS-only rule does not.
    rules: { ...hooks.configs.recommended.rules, 'no-unused-vars': 'off' },
  },
];
