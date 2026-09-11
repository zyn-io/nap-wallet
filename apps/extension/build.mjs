// Builds dist/ from src/ plus the shared page. Extension pages forbid
// inline scripts, so the page's script becomes popup.js with the app's
// address set first; the rest of the page is the popup as-is.
import { readFileSync, writeFileSync, mkdirSync, cpSync, copyFileSync } from 'node:fs';
mkdirSync('dist', { recursive: true });
cpSync('src', 'dist', { recursive: true });
cpSync('icons', 'dist/icons', { recursive: true });
cpSync('../../zynzapd/ui/fonts', 'dist/fonts', { recursive: true });
// The page and its assets travel together. The daemon serves the mark from
// its own route; in the popup it has to be a real file next to the page, or
// the header renders an empty frame.
copyFileSync('../../zynzapd/ui/nap-mark.png', 'dist/nap-mark.png');
let html = readFileSync('../../zynzapd/ui/index.html', 'utf8');
const m = html.match(/<script>([\s\S]*?)<\/script>\s*<\/body>/);
if (!m) throw new Error('no inline script in the page');
const js = "window.ZYN_API_BASE = 'http://127.0.0.1:8977';\n" + m[1];
html = html.replace(m[0], '<script src="popup.js"></script>\n</body>');
// A popup is at most 800px wide; the page lays itself out to that.
html = html.replace('</style>', 'html, body { width: 420px; min-height: 560px; } main { padding: 14px; grid-template-columns: 1fr; gap: 12px; }\n</style>');
writeFileSync('dist/popup.html', html);
writeFileSync('dist/popup.js', js);
console.log('dist/ ready — load it unpacked from chrome://extensions');
