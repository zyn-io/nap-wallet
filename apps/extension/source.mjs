// The source package AMO reviewers ask for when a add-on's code is built:
// release/nap-wallet-<version>-source.zip — the wallet's pages (apps/nap-web),
// the extension shell (apps/extension) and BUILDING.md, from which
// `npm run build` reproduces the Firefox package.
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

const v = JSON.parse(readFileSync('src/manifest.json', 'utf8')).version;
const STAGE = 'release/source';
rmSync(STAGE, { recursive: true, force: true });
mkdirSync(`${STAGE}/apps`, { recursive: true });

const web = ['index.html', 'popup.html', 'connect.html', 'vite.config.js', 'package.json', 'package-lock.json', '.env.extension', 'public', 'src', 'zec-core/Cargo.toml', 'zec-core/Cargo.lock', 'zec-core/build.sh', 'zec-core/src'];
for (const f of web) cpSync(`../nap-web/${f}`, `${STAGE}/apps/nap-web/${f}`, { recursive: true });
for (const f of ['build.mjs', 'package.json', 'src', 'icons']) cpSync(f, `${STAGE}/apps/extension/${f}`, { recursive: true });

writeFileSync(`${STAGE}/BUILDING.md`, `# Building Nap Wallet ${v} for Firefox

Requirements: Node.js 20 or newer (built with ${process.version}), npm, and \`zip\`.

\`\`\`sh
cd apps/nap-web && npm ci          # the wallet's pages and their dependencies
cd ../extension && npm run build   # builds apps/nap-web in extension mode, then the add-on
\`\`\`

The add-on is \`apps/extension/dist-firefox/\` (and zipped as
\`apps/extension/release/nap-wallet-${v}-firefox.zip\`).

## What is built from what

- \`apps/nap-web\` — the wallet (Vite). \`npm run build:extension\` builds its three
  pages with \`VITE_NAP_API=https://nap.zyn-network.com\` (\`.env.extension\`), the
  one server the add-on talks to (\`src/origin.js\`).
- \`apps/extension\` — \`build.mjs\` copies those pages next to the extension's
  own \`background.js\`, \`content.js\` and \`inpage.js\` (unminified, in \`src/\`)
  and writes the manifest.
- \`apps/nap-web/src/zec-pkg/\` — the Zcash wallet core, compiled from Rust
  (\`apps/nap-web/zec-core\`) to WebAssembly by \`zec-core/build.sh\` (needs the
  wasm32-unknown-unknown target, wasm-bindgen-cli 0.2.128 and an LLVM clang
  that targets wasm32). The compiled \`nap_zec_bg.wasm\` and its bindings are
  included so the add-on builds with Node alone.
`);

const name = `nap-wallet-${v}-source.zip`;
rmSync(`release/${name}`, { force: true });
execFileSync('zip', ['-qr', '-X', `../${name}`, '.'], { cwd: STAGE });
rmSync(STAGE, { recursive: true, force: true });
console.log(`release/${name}`);
