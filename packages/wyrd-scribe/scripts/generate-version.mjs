#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = path.join(packageRoot, 'package.json');
const dist = path.join(packageRoot, 'dist');

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
if (typeof manifest.version !== 'string'
    || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(manifest.version)) {
    throw new Error('package.json.version must be a valid semantic version');
}

fs.mkdirSync(dist, { recursive: true });
fs.writeFileSync(
    path.join(dist, 'version.js'),
    `// Generated from package.json by scripts/generate-version.mjs.\nexport const SERVER_VERSION = ${JSON.stringify(manifest.version)};\n`,
    'utf8'
);
fs.writeFileSync(
    path.join(dist, 'version.d.ts'),
    '// Generated from package.json by scripts/generate-version.mjs.\nexport declare const SERVER_VERSION: string;\n',
    'utf8'
);
