import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { assertInternalDependencyVersions, inspectInternalDependencyVersions }
    from '../../wyrd-fence/scripts/internal-dependency-preflight.mjs';
import { declare as arm } from './manifest.mjs';

const temporaryBases = new Set();
process.once('exit', () => {
    for (const base of temporaryBases) fs.rmSync(base, { recursive: true, force: true });
});

function temporaryDirectory(prefix) {
    const base = fs.mkdtempSync(prefix);
    temporaryBases.add(base);
    return base;
}


const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workspaceRoot = path.resolve(packageRoot, '..', '..');
const manifest = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
const fenceManifest = JSON.parse(fs.readFileSync(
    path.join(workspaceRoot, 'packages', 'wyrd-fence', 'package.json'),
    'utf8'
));
const httpManifest = JSON.parse(fs.readFileSync(
    path.join(workspaceRoot, 'packages', 'wyrd-http', 'package.json'), 'utf8'
));
const readme = fs.readFileSync(path.join(packageRoot, 'README.md'), 'utf8');

function npmCli() {
    const nodeDir = path.dirname(process.execPath);
    const candidates = [
        process.env.npm_execpath,
        path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
        path.join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
        path.join(nodeDir, '..', 'share', 'nodejs', 'npm', 'bin', 'npm-cli.js')
    ].filter(candidate => candidate
        && path.basename(candidate).toLowerCase() === 'npm-cli.js'
        && fs.existsSync(candidate));
    if (candidates.length === 0) throw new Error('npm-cli.js was not found on a known runtime layout');
    return candidates[0];
}

function packedFiles() {
    let raw;
    const cache = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-scribe-npm-cache-'));
    try {
        raw = execFileSync(process.execPath, [
            npmCli(), 'pack', '--dry-run', '--json', '--ignore-scripts', packageRoot
        ], {
            cwd: packageRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000,
            env: { ...process.env, npm_config_cache: cache }
        });
    } catch (error) {
        throw new Error(`UNDETERMINED — npm pack could not establish the tarball: ${error.message}`);
    } finally { fs.rmSync(cache, { recursive: true, force: true }); }
    const parsed = JSON.parse(raw);
    const files = (Array.isArray(parsed) ? parsed[0] : parsed)?.files;
    if (!Array.isArray(files) || files.length === 0) {
        throw new Error('UNDETERMINED — npm pack reported no tarball files');
    }
    return new Set(files.map(file => String(file.path).replace(/\\/g, '/')));
}

// ⚠ THIS ARM PINNED `private: true` AT `0.0.0` UNTIL 2026-09-22, and that pin was the catch that
// kept the Scribe from shipping by accident. Publishing was ruled that day; the pin moved to the
// current published version rather than being loosened, so a later edit to either field still reddens
// here and has to be made on purpose.
test('PK1-manifest-surface — the published package has its exact binary surface and metadata', () => {
    arm('PK1-manifest-surface');
    assert.equal(manifest.name, 'wyrd-scribe');
    assert.equal(manifest.version, '0.2.0');
    assert.equal(manifest.private, false);
    assert.equal(typeof manifest.private, 'boolean');
    assert.equal(manifest.license, 'Apache-2.0');
    assert.equal(manifest.type, 'module');
    assert.equal(manifest.description,
        'wyrd-scribe — a tier-A MCP server for create-only provenance-stamped page writes.');
    assert.deepEqual(manifest.exports, {});
    assert.equal(manifest.main, undefined);
    assert.equal(manifest.types, undefined);
    assert.deepEqual(manifest.bin, { 'wyrd-scribe': 'dist/index.js' });
    assert.deepEqual(manifest.files, ['dist', 'README.md', 'LICENSE']);
    assert.doesNotMatch(manifest.description, /\bprivate\b/i);
    assert.deepEqual(manifest.keywords, [
        'mcp', 'model-context-protocol', 'markdown', 'provenance', 'lineage', 'create-only'
    ]);
    assert.deepEqual(manifest.repository, {
        type: 'git',
        url: 'git+https://github.com/MortalPastry/wyrd-mcp.git',
        directory: 'packages/wyrd-scribe'
    });
    assert.equal(manifest.homepage,
        'https://github.com/MortalPastry/wyrd-mcp/tree/main/packages/wyrd-scribe#readme');
    assert.equal(manifest.bugs?.url, 'https://github.com/MortalPastry/wyrd-mcp/issues');
    assert.deepEqual(manifest.engines, { node: '>=20' });
    assert.equal(manifest.dependencies?.['wyrd-fence'], fenceManifest.version);
    assert.equal(manifest.dependencies?.['wyrd-http'], httpManifest.version);
    assert.equal(manifest.dependencies?.['@modelcontextprotocol/server'], '2.0.0');
    assert.equal(manifest.dependencies?.['@modelcontextprotocol/sdk'], undefined);
    assert.equal(manifest.scripts?.build, 'tsc -b && node scripts/generate-version.mjs');
    assert.equal(manifest.scripts?.prepack, 'npm run build');
    assert.equal(manifest.scripts?.pretest, undefined);
    assert.equal(manifest.scripts?.['pretest:portable'], undefined);
    assert.equal(manifest.scripts?.test,
        'node ../wyrd-fence/scripts/battery-lock.mjs run test -- "node ../wyrd-fence/scripts/internal-dependency-preflight.mjs . && npm --prefix ../wyrd run build && npm run build && node scripts/run-tests.mjs"');
    assert.equal(manifest.scripts?.['test:portable'],
        'node ../wyrd-fence/scripts/battery-lock.mjs run test:portable -- "node ../wyrd-fence/scripts/internal-dependency-preflight.mjs . && npm --prefix ../wyrd run build && npm run build && node scripts/run-tests.mjs --portable"');
    assert.equal(manifest.scripts?.mutate,
        'node ../wyrd-fence/scripts/battery-lock.mjs run mutate -- "node scripts/mutate.mjs"');
    assert.equal(manifest.scripts?.publish, undefined);
    assert.equal(manifest.publishConfig, undefined);
    assert.equal(manifest.mcpName, 'com.wyrdmcp/wyrd-scribe');
    assert.equal(manifest.server, undefined);
});

test('PK2-packed-files — npm derives only the documented package payload', () => {
    arm('PK2-packed-files');
    const actual = packedFiles();
    const modules = [
        'config', 'frontmatter', 'http', 'http-policy', 'index', 'ledger', 'lineage', 'main', 'mutate',
        'refusal', 'server', 'source', 'span', 'stamp', 'write-completion'
    ];
    const expected = new Set(['package.json', 'README.md', 'LICENSE', 'dist/version.js', 'dist/version.d.ts']);
    for (const module of modules) {
        expected.add(`dist/${module}.js`);
        expected.add(`dist/${module}.js.map`);
        expected.add(`dist/${module}.d.ts`);
    }
    assert.deepEqual([...actual].sort(), [...expected].sort());
    assert.equal(actual.has(manifest.bin['wyrd-scribe']), true, 'the declared bin target must be packed');
    for (const file of actual) {
        assert.doesNotMatch(file, /^(?:src|scripts|test)\//);
        assert.doesNotMatch(file, /(?:^|\/)(?:tsconfig(?:\.tsbuildinfo)?|.*\.tsbuildinfo)$/);
    }
});

test('PK3-version-single-source — generated runtime provenance equals the manifest', async () => {
    arm('PK3-version-single-source');
    const generated = await import('../dist/version.js');
    assert.equal(generated.SERVER_VERSION, manifest.version);
    const serverSource = fs.readFileSync(path.join(packageRoot, 'src', 'server.ts'), 'utf8');
    assert.match(serverSource, /from ['"]\.\/version\.js['"]/);
    assert.doesNotMatch(serverSource, /SERVER_VERSION\s*=\s*['"]/);
});

test('PK4-readme-contract — the package account is complete without copying the Fence window', () => {
    arm('PK4-readme-contract');
    for (const heading of [
        'Installation and configuration', '`write_page`', 'Outcomes and recovery',
        'Security boundary and limits', 'Privacy and data flow', 'Build and test from source', 'License'
    ]) assert.match(readme, new RegExp(`^## ${heading.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')}$`, 'm'));
    for (const pattern of [
        /Tier-A|Tier A/i,
        /create-only/i,
        /npm install -g wyrd-scribe/,
        /--grant[\s\S]*precedence over `WYRD_GRANT`/i,
        /WYRD_SCRIBE_TIER[\s\S]*defaults to `A`/i,
        /Tier B adds `overwrite_page`[\s\S]*tier C is recognised but unavailable/i,
        /write_page/,
        /derived_from/,
        /\.wyrd\/scribe\.json/,
        /write_frontmatter[\s\S]*false/i,
        /page first[\s\S]*then appends|creates the page first[\s\S]*then appends/i,
        /PAGE_WRITTEN_LEDGER_FAILED/,
        /wyrd\.lineage\/v1/,
        /wyrd_lineage/,
        /stdio/i,
        /Apache-2\.0/
    ]) assert.match(readme, pattern);
    for (const exactShape of [
        /"command": "wyrd-scribe"/,
        /"args": \["--grant", "\/absolute\/path\/to\/folder"\]/,
        /"path": "Notes\/new-page\.md"/,
        /"content": "Page text\\n"/,
        /"derived_from": \[/,
        /"source": "Sources\/source\.md"/,
        /"spans": \[/,
        /\{ "offset": 0, "length": 9 \}/,
        /\{ "quote": "source text" \}/,
        /\{ "offset": 0, "length": 9, "quote": "source te" \}/
    ]) assert.match(readme, exactShape);
    assert.match(readme, /must already contain a `\.wyrd\/` directory/i);
    assert.match(readme, /mints `\.wyrd\/scribe\.json`/i);
    assert.match(readme, /Unknown input keys are refused/i);
    // ⚠ ABSOLUTE, NOT `../wyrd-fence/…`: the README is rendered on npm, where a monorepo-relative
    // link is dead. Found by the publish-prep review 2026-09-22.
    assert.match(readme, /\(https:\/\/github\.com\/MortalPastry\/wyrd-mcp\/blob\/main\/packages\/wyrd-fence\/README\.md#security-boundary-and-limits\)/);
    assert.doesNotMatch(readme, /\]\(\.\.\//, 'no monorepo-relative link may reach the npm-rendered README');
    assert.doesNotMatch(readme, /before the single write, the file can be renamed out/i);
    assert.doesNotMatch(readme, /hard link created after the pre-open/i);
});

test('PK5-internal-dependency-preflight — local and registry dependency contracts cannot split', () => {
    arm('PK5-internal-dependency-preflight');
    const fixture = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-dependency-preflight-'));
    const consumerRoot = path.join(fixture, 'packages', 'fixture-consumer');
    const siblingRoot = path.join(fixture, 'packages', 'fixture-sibling');
    fs.mkdirSync(consumerRoot, { recursive: true });
    fs.mkdirSync(siblingRoot, { recursive: true });
    fs.writeFileSync(path.join(fixture, 'package.json'), JSON.stringify({
        name: 'fixture-workspace', private: true, workspaces: ['packages/*']
    }));
    fs.writeFileSync(path.join(siblingRoot, 'package.json'), JSON.stringify({
        name: 'fixture-sibling', version: '1.2.3', private: false
    }));

    const writeConsumer = spec => fs.writeFileSync(
        path.join(consumerRoot, 'package.json'),
        JSON.stringify({
            name: 'fixture-consumer', version: '4.5.6', private: false,
            dependencies: { 'fixture-sibling': spec }
        })
    );
    try {
        // Failure cases come first: a permissive implementation must not reach the passing control.
        for (const spec of ['9.9.9', 'workspace:*', 'file:../fixture-sibling', 'link:../fixture-sibling']) {
            writeConsumer(spec);
            assert.throws(
                () => assertInternalDependencyVersions(consumerRoot, { workspaceRoot: fixture }),
                error => {
                    assert.match(error.message, /fixture-consumer/);
                    assert.match(error.message, /fixture-sibling/);
                    assert.ok(error.message.includes(JSON.stringify(spec)),
                        `the refusal did not name declared spec ${JSON.stringify(spec)}: ${error.message}`);
                    assert.ok(error.message.includes('"1.2.3"'),
                        `the refusal did not name local version 1.2.3: ${error.message}`);
                    return true;
                }
            );
        }

        fs.writeFileSync(path.join(consumerRoot, 'package.json'), JSON.stringify({
            name: 'fixture-consumer', version: '4.5.6', private: false,
            dependencies: { 'fixture-sibling': '1.2.3' },
            devDependencies: { 'fixture-sibling': '1.2.3' },
            optionalDependencies: { 'fixture-sibling': '1.2.3' },
            peerDependencies: { 'fixture-sibling': '1.2.3' }
        }));
        const result = assertInternalDependencyVersions(consumerRoot, { workspaceRoot: fixture });
        assert.equal(result.checked, 4, 'every standard dependency section must be inspected');
        assert.deepEqual(result.problems, []);
    } finally {
        fs.rmSync(fixture, { recursive: true, force: true });
    }
});

test('PK6-internal-dependency-identity — workspace membership uses filesystem identity', () => {
    arm('PK6-internal-dependency-identity');
    const fixture = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-dependency-identity-'));
    const consumerRoot = path.join(fixture, 'packages', 'fixture-consumer');
    const outsiderRoot = path.join(fixture, 'not-a-workspace-package');
    fs.mkdirSync(consumerRoot, { recursive: true });
    fs.mkdirSync(outsiderRoot, { recursive: true });
    fs.writeFileSync(path.join(fixture, 'package.json'), JSON.stringify({
        name: 'fixture-workspace', private: true, workspaces: ['packages/*']
    }));
    const consumerManifest = JSON.stringify({
        name: 'fixture-consumer', version: '4.5.6', private: false
    });
    fs.writeFileSync(path.join(consumerRoot, 'package.json'), consumerManifest);
    fs.writeFileSync(path.join(outsiderRoot, 'package.json'), consumerManifest);

    try {
        if (process.platform === 'win32') {
            const differentlyCased = consumerRoot.replace(/[A-Za-z]/, letter =>
                letter === letter.toUpperCase() ? letter.toLowerCase() : letter.toUpperCase());
            assert.notEqual(differentlyCased, consumerRoot);
            assert.deepEqual(
                inspectInternalDependencyVersions(differentlyCased, { workspaceRoot: fixture }),
                { packageName: 'fixture-consumer', checked: 0, problems: [] }
            );
        }
        assert.throws(
            () => inspectInternalDependencyVersions(outsiderRoot, { workspaceRoot: fixture }),
            /is not a package in/
        );
    } finally {
        fs.rmSync(fixture, { recursive: true, force: true });
    }
});
