// Builds the Nap Wallet extension: dist/ (Chrome, Edge, Brave) and
// dist-firefox/, plus store-ready zips in release/.
//
// The extension is Nap in the browser, packaged: the wallet's own pages, built
// for the extension (`npm run build:extension` in apps/nap-web — endpoints on
// nap.zyn-network.com, keys on the extension's origin), with a toolbar popup, a
// content script that announces Nap to sites, and a background that opens the
// connect window. No desktop app is needed.
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

const WEB = '../nap-web';
const PAGES = `${WEB}/dist-extension`;
// What the web deployment serves that has no meaning inside an extension.
const WEB_ONLY = ['sw.js', 'manifest.webmanifest', '_headers', '_redirects', 'privacy.html'];

if (!process.argv.includes('--no-web')) execFileSync('npm', ['run', 'build:extension'], { cwd: WEB, stdio: 'inherit' });
if (!existsSync(`${PAGES}/index.html`)) throw new Error(`no extension build of the wallet at ${PAGES}`);

const manifest = JSON.parse(readFileSync('src/manifest.json', 'utf8'));

function stage(dir, mf) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  cpSync(PAGES, dir, { recursive: true, filter: (src) => !WEB_ONLY.some((f) => src.endsWith(`/${f}`)) });
  cpSync('icons', `${dir}/icons`, { recursive: true });
  for (const f of ['background.js', 'content.js', 'inpage.js']) cpSync(`src/${f}`, `${dir}/${f}`);
  writeFileSync(`${dir}/manifest.json`, JSON.stringify(mf, null, 2) + '\n');
}

stage('dist', manifest);

// Firefox implements MV3 with event pages rather than service workers, and
// requires an explicit add-on id. Everything else in the manifest is shared,
// so the two builds cannot drift apart: this is the whole difference.
const firefox = structuredClone(manifest);
firefox.background = { scripts: ['background.js'] };
firefox.browser_specific_settings = {
  gecko: {
    id: 'nap-wallet@cavebro.win',
    strict_min_version: '121.0',
    // Mozilla asks every add-on to declare what leaves the browser. A wallet
    // sends the transactions it signs to the network (Nap's server relays
    // them); nothing else — no browsing, no analytics.
    data_collection_permissions: { required: ['financialAndPaymentInfo'] },
  },
};
stage('dist-firefox', firefox);

// Store uploads: the extension's files at the zip's root.
mkdirSync('release', { recursive: true });
const v = manifest.version;
for (const [dir, name] of [['dist', `nap-wallet-${v}-chrome.zip`], ['dist-firefox', `nap-wallet-${v}-firefox.zip`]]) {
  rmSync(`release/${name}`, { force: true });
  execFileSync('zip', ['-qr', '-X', `../release/${name}`, '.'], { cwd: dir });
}
console.log(`dist/ and dist-firefox/ ready; release/nap-wallet-${v}-{chrome,firefox}.zip`);
