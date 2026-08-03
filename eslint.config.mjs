import { defineConfig } from 'eslint/config'
import tseslint from '@electron-toolkit/eslint-config-ts'
import eslintConfigPrettier from '@electron-toolkit/eslint-config-prettier'

export default defineConfig(
  {
    ignores: ['**/node_modules', '**/dist', '**/out', '**/release', 'build/hooks/**', 'scripts/**']
  },
  tseslint.configs.recommended,
  eslintConfigPrettier
)
