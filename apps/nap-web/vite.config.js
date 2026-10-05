// The wallet's pages, one origin: the full view, the compact wallet and the
// connect window share the kept key, the chain route and the content policy,
// so none is a second place to trust.
import { defineConfig } from 'vite';

const devProxy = () => {
  const proxy = {};
  if (process.env.NAP_DEV_RPC) proxy['/rpc'] = { target: process.env.NAP_DEV_RPC, changeOrigin: true, rewrite: () => '/' };
  // A block server's HTTP door (`ZYN_LIGHTD_HTTP`), for the Zcash wallet.
  if (process.env.NAP_DEV_ZEC) proxy['/zec'] = { target: process.env.NAP_DEV_ZEC, changeOrigin: true, rewrite: () => '/' };
  // A local zyn-attend (§150): `/attend[/testnet]/<door>` → `<door>`.
  if (process.env.NAP_DEV_ATTEND) proxy['/attend'] = { target: process.env.NAP_DEV_ATTEND, changeOrigin: true, rewrite: (p) => p.replace(/^\/attend(\/testnet)?/, '') };
  return Object.keys(proxy).length ? { proxy } : {};
};

// `vite build --mode extension` (or `--mode mobile`) builds the same pages
// for the browser extension (apps/extension) or the phone app (apps/nap-mobile): the endpoints stay on Nap's server
// (`VITE_NAP_API` in .env.extension), so each page's policy admits that
// origin too, and the web app's install manifest does not apply.
const extensionPages = (mode) => ({
  name: 'nap-extension-pages',
  transformIndexHtml(html) {
    if (mode !== 'extension' && mode !== 'mobile') return html;
    const api = new URL(process.env.VITE_NAP_API || 'https://nap.zyn-network.com').origin;
    return html
      // The phone app's pages also reach its native side (Tauri IPC), for
      // biometric unlock (§151).
      .replace(/connect-src 'self'/, `connect-src 'self' ${api}${mode === 'mobile' ? ' ipc: http://ipc.localhost' : ''}`)
      .replace(/\s*<link rel="manifest"[^>]*>/, '')
      // Ignored in a <meta> policy, and Chrome lists that under the
      // extension's Errors; the manifest's own policy governs these pages.
      .replace(mode === 'extension' ? / frame-ancestors 'none';/ : /$^/, '');
  },
});

export default defineConfig(({ mode }) => ({
  plugins: [extensionPages(mode)],
  build: {
    // The oldest engines Nap runs on: iOS 16's WebKit (the app's minimum;
    // AbortSignal.timeout and wasm-unsafe-eval arrived in Safari 16), the
    // Android WebView of Chrome 103, Firefox 114. Syntax newer than these
    // fails the build instead of the phone.
    target: ['safari16', 'chrome103', 'firefox114'],
    rollupOptions: {
      // popup.html, the compact wallet: the extension's toolbar popup and the phone app's home.
      input: { wallet: 'index.html', connect: 'connect.html', ...(mode === 'extension' || mode === 'mobile' ? { popup: 'popup.html' } : {}) },
    },
  },
  // Local development only: `NAP_DEV_RPC=http://127.0.0.1:8399 npm run dev`
  // points /rpc at a node on this machine, the way the Pages function does in
  // production; `NAP_DEV_ZEC=http://127.0.0.1:8095` does the same for /zec. Unset, there is no proxy and nothing changes.
  // `vite preview` too: the dev server injects styles inline, which the
  // shipped CSP rightly blocks, so the built pages are what to look at.
  server: devProxy(),
  preview: devProxy(),
}));
