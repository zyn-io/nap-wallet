// The desktop and mobile shells show the same page zyn-app serves. Copy it
// in (the shell's api() detects Tauri and calls in-process instead of HTTP).
import { copyFileSync, cpSync, mkdirSync } from 'node:fs';
mkdirSync('dist', { recursive: true });
copyFileSync('../../zynzapd/ui/index.html', 'dist/index.html');
copyFileSync('../../zynzapd/ui/nap-mark.png', 'dist/nap-mark.png');
cpSync('../../zynzapd/ui/fonts', 'dist/fonts', { recursive: true });
console.log('dist/index.html ← zynzapd/ui/index.html');
console.log('dist/nap-mark.png ← zynzapd/ui/nap-mark.png');
console.log('dist/fonts ← zynzapd/ui/fonts');
