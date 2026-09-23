import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { unsupportedKeywords, validate } from '../../wyrd/test/jsonschema.mjs';
import { declare as arm } from './manifest.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const schemaPath = path.resolve(packageRoot, '..', 'wyrd', 'test', 'server.schema.json');
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));

test('MF1-manifest-schema — server.json conforms to the Reader vendored registry schema', () => {
    arm('MF1-manifest-schema');
    const schema = readJson(schemaPath);
    const manifest = readJson(path.join(packageRoot, 'server.json'));

    assert.deepEqual(
        unsupportedKeywords(schema),
        [],
        'the vendored schema exceeds the bounded validator'
    );
    const errors = validate(manifest, schema);
    assert.deepEqual(
        errors,
        [],
        'server.json does not conform to the vendored registry schema:\n'
        + errors.map(error => `  ${error.path}: ${error.message}`).join('\n')
    );
});

test('MF2-manifest-cross-reference — registry facts agree with the package and built program', () => {
    arm('MF2-manifest-cross-reference');
    const schema = readJson(schemaPath);
    const manifest = readJson(path.join(packageRoot, 'server.json'));
    const pkg = readJson(path.join(packageRoot, 'package.json'));
    const built = fs.readFileSync(path.join(packageRoot, 'dist', 'main.js'), 'utf8');

    assert.equal(manifest.$schema, schema.$id);
    assert.equal(manifest.name, pkg.mcpName);
    assert.equal(manifest.version, pkg.version);
    assert.equal(manifest.description.length <= 100, true);

    const npmPackages = manifest.packages.filter(entry => entry.registryType === 'npm');
    assert.equal(npmPackages.length, 1, 'server.json must declare exactly one npm package');
    const npmPackage = npmPackages[0];
    assert.equal(npmPackage.identifier, pkg.name);
    assert.equal(npmPackage.version, pkg.version);

    assert.equal(manifest.remotes, undefined, 'server.json must not advertise remote transports');
    for (const entry of manifest.packages) {
        assert.equal(entry.transport?.type, 'stdio');
        assert.equal(entry.transport?.url, undefined);
    }

    const declaredNames = [
        ...(npmPackage.packageArguments ?? []).map(argument => argument.name),
        ...(npmPackage.environmentVariables ?? []).map(variable => variable.name)
    ];
    assert.deepEqual(declaredNames, ['--grant', 'WYRD_GRANT', 'WYRD_SCRIBE_TIER']);
    for (const name of declaredNames) {
        assert.equal(typeof name, 'string');
        assert.ok(
            built.includes(name),
            `server.json declares ${name} but it does not appear in dist/main.js`
        );
    }
});
