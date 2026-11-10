'use strict';

const globals = require('globals');
const prettier = require('eslint-config-prettier');

module.exports = [
  {
    ignores: ['node_modules/**', 'media/**', '**/*.vsix']
  },
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: globals.node
    },
    rules: {
      curly: 'error',
      eqeqeq: 'error',
      'no-undef': 'error',
      'no-unused-vars': 'warn'
    }
  },
  prettier
];
