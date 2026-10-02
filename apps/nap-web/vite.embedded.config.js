// One file a site can load to open a Zyn account with the wallet a holder
// already has (src/embedded.js). The private channel's prover is a separate
// chunk and its WebAssembly a separate file, fetched only when a private
// deposit or withdrawal needs them. (Not library mode: that inlines assets.)
import { defineConfig } from 'vite';

export default defineConfig({
  publicDir: false,
  build: {
    outDir: 'dist-embedded',
    emptyOutDir: true,
    assetsInlineLimit: 0,
    target: 'es2022',
    modulePreload: false,
    rollupOptions: {
      input: 'src/embedded.js',
      preserveEntrySignatures: 'exports-only',
      output: { entryFileNames: 'zyn-embedded.js', chunkFileNames: 'zyn-[name]-[hash].js', assetFileNames: 'zyn-[name]-[hash][extname]' },
    },
  },
});
