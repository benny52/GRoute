import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  server: {
    fs: { allow: [fileURLToPath(new URL('.', import.meta.url)), fileURLToPath(new URL('../build/windows/icon.png', import.meta.url))] },
  },
  build: { outDir: 'dist', emptyOutDir: true, target: 'es2021', chunkSizeWarningLimit: 800 },
});
