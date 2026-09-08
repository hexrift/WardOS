// PLAYWRIGHT=/path/to/playwright/index.mjs overrides resolution (ESM ignores NODE_PATH).
const { chromium } = await import(process.env.PLAYWRIGHT ?? 'playwright');
import fs from 'node:fs';
const dir = process.argv[2];
const b = await chromium.launch(process.env.CHROME ? { executablePath: process.env.CHROME } : {});
const p = await b.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.html')).sort()) {
  await p.goto('file://' + dir + '/' + f);
  await (await p.$('.screen')).screenshot({ path: dir + '/' + f.replace('.html', '.png') });
}
await b.close();
