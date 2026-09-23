import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { declare as arm } from './manifest.mjs';
import { unsupportedKeywords, validate } from './jsonschema.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const readJson = rel => JSON.parse(fs.readFileSync(path.join(repoRoot, rel), 'utf8'));

const SCHEMA_REL = 'test/server.schema.json';

/**
 * ⚠⚠ `server.json` IS THE ONE PRODUCT SURFACE WHOSE VALIDATOR IS A THIRD PARTY. Everything else
 * this suite checks is refused by this repo's own code the moment it is wrong; a malformed registry
 * manifest is refused by the MCP Registry, at SUBMISSION, in front of the registry, with the
 * publish half-done. The file declares its own contract on line 1 — a `$schema` URL — and until
 * this arm nothing in the tree read that line, let alone honoured it.
 *
 * ⚠ THE SCHEMA IS VENDORED (`test/server.schema.json`) RATHER THAN FETCHED, and that is the whole
 * design. A validator that downloads its schema at test time turns a suite run into a network call
 * — offline runs fail, and worse, a registry-side schema revision silently changes what this
 * package is measured against, so the arm goes red for a change nobody here made. Vendored, a
 * schema revision is a VISIBLE EVENT: someone re-fetches the file, the diff is reviewable, and
 * `MF2-manifest-cross-reference` below is what stops the two separating quietly in the meantime.
 */

test('MF1-manifest-schema — the vendored schema still spans the validator, and the manifest conforms', async () => {
    arm('MF1-manifest-schema');

    const schema = readJson(SCHEMA_REL);
    const manifest = readJson('server.json');

    /**
     * ⚠ THE COVERAGE CHECK RUNS FIRST AND IT IS THE LOAD-BEARING HALF. `test/jsonschema.mjs` is a
     * bounded draft-07 subset, not a complete implementation; a bounded validator that MEETS a
     * keyword it does not implement and skips it reports "valid" for a document it did not fully
     * read. So the schema's own keyword vocabulary is asserted to lie inside what the validator
     * asserts or knowingly ignores. A re-vendored schema introducing `oneOf`, `if`/`then`,
     * `dependencies` or `patternProperties` fails HERE, naming the keyword, rather than passing
     * through the gap it opened.
     */
    assert.deepEqual(
        unsupportedKeywords(schema),
        [],
        'the vendored schema uses a keyword test/jsonschema.mjs neither asserts nor knowingly ignores — '
        + 'the validator is now narrower than the schema and its green covers a subset'
    );

    const errors = validate(manifest, schema);
    assert.deepEqual(
        errors,
        [],
        'server.json does not conform to its own declared schema:\n'
        + errors.map(e => `  ${e.path}: ${e.message}`).join('\n')
    );

    /**
     * ⚠ THE VALIDATOR IS PROVED TO BITE INSIDE THE ARM, not only by the mutation harness. A
     * validator whose only evidence is that it returned zero errors is indistinguishable from one
     * that returns zero errors unconditionally — the failure mode a hand-rolled checker actually
     * has. These are the constraint families the manifest depends on: a `required` field, a
     * `pattern`, the `anyOf` that selects the transport, and the `not`/`const` pair that rejects a
     * floating package version.
     *
     * ⚠ THE `not`/`const` ROW IS HERE BECAUSE ITS ABSENCE ALREADY COST SOMETHING. The first draft
     * of `test/jsonschema.mjs` had `const` inverted — it failed on a match instead of requiring one
     * — and the three rows above all passed anyway, because none of them reaches that keyword. What
     * caught it was the conformance check on the REAL manifest, which is luck rather than design:
     * an inverted `const` inside a `not` is a validator that accepts what the schema forbids, and
     * nothing here would have said so if the live manifest had happened not to exercise it.
     */
    const broken = [
        [structuredClone(manifest), m => { delete m.version; }, 'a missing required field'],
        [structuredClone(manifest), m => { m.name = 'no-slash-here'; }, 'a name that breaks the reverse-DNS pattern'],
        [structuredClone(manifest), m => { m.packages[0].transport = { type: 'carrier-pigeon' }; }, 'a transport matching no alternative'],
        [structuredClone(manifest), m => { m.packages[0].version = 'latest'; }, 'a floating `latest` package version, which the schema forbids by `not`/`const`']
    ];
    for (const [copy, mutate, what] of broken) {
        mutate(copy);
        assert.notDeepEqual(validate(copy, schema), [], `the validator accepted ${what}`);
    }

    /**
     * ⚠ THE COVERAGE GUARD IS PROVED TO BITE ON THE ONE KEYWORD THAT SHARES A NAME WITH ONE IT
     * IMPLEMENTS. draft-07 `items` has two forms; the validator implements the single-schema form
     * only, and until 2026-09-02 the TUPLE form (an array) walked as nothing and validated every
     * element against nothing — the exact silent green `unsupportedKeywords()` exists to refuse,
     * arriving through it. A re-vendored schema using tuple items must fail HERE, by name.
     */
    assert.deepEqual(
        unsupportedKeywords({ type: 'array', items: [{ type: 'string' }] }),
        ['items (tuple form)'],
        'tuple-form `items` must be reported as unsupported, not walked as nothing'
    );
    assert.throws(
        () => validate(['x'], { type: 'array', items: [{ type: 'number' }] }),
        /tuple-form/,
        'a validator handed the tuple form must throw, never treat the array as a schema'
    );
    // And length is measured in code points, as draft-07 says — one astral character is ONE.
    assert.deepEqual(validate('\u{1F600}', { type: 'string', maxLength: 1 }), []);
    assert.notDeepEqual(validate('\u{1F600}\u{1F600}', { type: 'string', maxLength: 1 }), []);
});

test('MF2-manifest-cross-reference — the $schema it declares is the one vendored here, and its facts agree with package.json', async () => {
    arm('MF2-manifest-cross-reference');

    const schema = readJson(SCHEMA_REL);
    const manifest = readJson('server.json');
    const pkg = readJson('package.json');

    /**
     * ⚠⚠ THE PIN. The vendored copy is one dated revision of a schema that will be revised. Nothing
     * about validating against it is meaningful if `server.json` can start declaring a DIFFERENT
     * revision while this arm goes on measuring the old one — the manifest would then be checked
     * against a contract it no longer claims, and pass. Asserting the two are the same string makes
     * a schema upgrade a two-file edit somebody has to mean, which is the point: a future revision
     * must be a decision, never a drift.
     */
    assert.equal(
        manifest.$schema,
        schema.$id,
        `server.json declares ${manifest.$schema} but ${SCHEMA_REL} is ${schema.$id} — `
        + 'the manifest and the schema it is checked against have separated. Re-vendor the schema '
        + 'from the declared URL and review the diff, or revert the declaration.'
    );

    /**
     * ⚠ SCHEMA CONFORMANCE CANNOT CATCH THIS CLASS AND IT IS THE ONE THAT ACTUALLY BREAKS A
     * RELEASE. A manifest can be perfectly well-formed and describe a DIFFERENT package than the
     * one being published: a version bumped in `package.json` and not here, an identifier naming
     * something else on npm. Each pair below is two files that must say the same thing and had
     * nothing making them.
     *
     * ⚠ `mcpName` IS THE ROW WITH TEETH. The MCP Registry proves npm ownership by reading
     * `mcpName` out of the PUBLISHED package and requiring it to equal the manifest's `name`. It
     * was cross-referenced by nothing in this tree before this arm — the two could disagree
     * through a full green suite and the release would be refused at the registry, after publish.
     */
    const npmPackage = manifest.packages.find(entry => entry.registryType === 'npm');
    assert.ok(npmPackage, 'server.json declares no npm package entry — nothing here describes what ships');

    assert.equal(manifest.name, pkg.mcpName,
        'server.json `name` and package.json `mcpName` disagree — the registry reads mcpName out of the '
        + 'PUBLISHED tarball to prove ownership of this name, so a mismatch refuses the submission after publish');
    assert.equal(npmPackage.identifier, pkg.name,
        'server.json\'s npm `identifier` is not this package\'s name — the manifest points the registry at a different package');
    assert.equal(manifest.version, pkg.version,
        'server.json `version` and package.json `version` disagree — the registry would advertise a version that is not what shipped');
    assert.equal(npmPackage.version, pkg.version,
        'the npm package entry\'s `version` is not this package\'s version');

    /**
     * ⚠ THE GRANT FLAGS ARE DERIVED FROM THE PROGRAM, not retyped. `server.json` tells a client how
     * to configure this server; if it names a flag or a variable `main()` does not read, the
     * instructions are wrong in the one place a user follows them literally. Read out of the BUILT
     * output rather than the source, because the built output is what runs.
     *
     * The declared names are checked for PRESENCE in `dist/main.js` rather than parsed out of it: a
     * derivation precise enough to enumerate every flag the program accepts would be a second
     * implementation of the argument reader, and the failure this guards is a manifest naming
     * something that does not exist at all.
     */
    const built = fs.readFileSync(path.join(repoRoot, 'dist', 'main.js'), 'utf8');
    const declaredPackageArgumentNames = (npmPackage.packageArguments ?? [])
        .map(a => a.name)
        .filter(name => typeof name === 'string');
    const declaredNames = [
        ...declaredPackageArgumentNames,
        ...(npmPackage.environmentVariables ?? []).map(v => v.name)
    ].filter(name => typeof name === 'string');

    /**
     * ⚠⚠ THE POLICY: THIS MANIFEST ADVERTISES STDIO AND NOTHING ELSE, AND THE CHECK IS ON THE WHOLE
     * DOCUMENT RATHER THAN ON ONE FIELD.
     *
     * A registry manifest tells a STRANGER how to connect. `--http` starts a self-hosted loopback
     * listener nobody else can reach, so it is not a registry transport and must not appear here as
     * a connection instruction. The Reader gaining HTTP (2026-09-14) is exactly when this could
     * start drifting, which is why it is asserted rather than assumed.
     *
     * ⚠ THE FIRST VERSION OF THIS CHECK WAS TOO NARROW, AND A COLD READ MEASURED THREE WAYS AROUND
     * IT AGAINST THE VENDORED SCHEMA. Each is schema-valid, so `MF1` passes on all three:
     *
     *   1. `remotes[]` is a property of `ServerDetail` and holds `RemoteTransport` entries — HTTP and
     *      SSE endpoints advertised DIRECTLY, never touching `packages[]` at all.
     *   2. `Argument` is `anyOf[PositionalArgument, NamedArgument]`, and `PositionalArgument` has NO
     *      `name` — it carries `value`/`valueHint`. A positional `--http` was invisible to a filter
     *      reading `name`.
     *   3. `packages[]` is an array. The old check read only the FIRST `registryType === 'npm'`
     *      entry, so a second entry could advertise any transport it liked.
     *
     * So the assertion below walks every package, every argument shape, and `remotes`. **It pins the
     * POLICY, not one encoding of it** — which is the difference between a check that holds and a
     * check that happened to catch the one case its author thought of.
     *
     * ⚠ The `stdio` expectation is deliberately hard-coded rather than derived. This is a policy
     * invariant, and a genuine remote transport SHOULD fail here until the manifest policy and this
     * test are changed together, on purpose. That is the protection, not an obstruction.
     */
    const HTTP_SELECTOR = '--http';
    const advertisedTransportRoutes = [];

    for (const [index, entry] of (manifest.packages ?? []).entries()) {
        const where = `packages[${index}]`;
        if (entry.transport?.type !== 'stdio') {
            advertisedTransportRoutes.push(`${where}.transport.type=${JSON.stringify(entry.transport?.type)}`);
        }
        // A stdio transport object carrying a URL is misleading metadata even where a conforming
        // client ignores it: the vendored StdioTransport sets no `additionalProperties: false`.
        if (entry.transport?.url !== undefined) {
            advertisedTransportRoutes.push(`${where}.transport.url=${JSON.stringify(entry.transport.url)}`);
        }
        for (const [argIndex, argument] of (entry.packageArguments ?? []).entries()) {
            // Named arguments carry `name`; positional ones carry `value`/`valueHint` and no name.
            const carried = [argument.name, argument.value, argument.valueHint];
            if (carried.some(field => typeof field === 'string' && field.includes(HTTP_SELECTOR))) {
                advertisedTransportRoutes.push(
                    `${where}.packageArguments[${argIndex}] carries ${HTTP_SELECTOR}`
                );
            }
        }
    }

    for (const [index, remote] of (manifest.remotes ?? []).entries()) {
        advertisedTransportRoutes.push(`remotes[${index}].type=${JSON.stringify(remote.type)}`);
    }

    assert.deepEqual(
        advertisedTransportRoutes,
        [],
        'server.json advertises a transport route that is not plain stdio: '
        + `${JSON.stringify(advertisedTransportRoutes)} — this manifest tells a STRANGER how to connect, `
        + `and ${HTTP_SELECTOR} starts only a self-hosted loopback server they cannot reach. Every `
        + 'packages[] entry must declare transport type "stdio" with no url, no argument of any shape '
        + `may carry ${HTTP_SELECTOR}, and remotes[] must be absent or empty. If a genuinely remote `
        + 'transport is being added, change the manifest policy and this assertion together.'
    );

    assert.ok(declaredNames.length > 0, 'the manifest declares no way to pass a grant at all');
    for (const name of declaredNames) {
        assert.ok(
            built.includes(name),
            `server.json declares "${name}" but it appears nowhere in dist/main.js — the manifest tells `
            + 'clients to configure this server with something the program does not read'
        );
    }
});

test('MF3-version-single-source — generated runtime version equals package.json', async () => {
    arm('MF3-version-single-source');

    const manifest = readJson('package.json');
    const generated = await import('../dist/version.js');
    assert.equal(generated.SERVER_VERSION, manifest.version);

    const serverSource = fs.readFileSync(path.join(repoRoot, 'src', 'server.ts'), 'utf8');
    assert.match(serverSource, /from ['"]\.\/version\.js['"]/);
    assert.doesNotMatch(serverSource, /SERVER_VERSION\s*=\s*['"]/);
    assert.equal(manifest.scripts?.build, 'tsc -b && node scripts/generate-version.mjs');
    assert.equal(manifest.scripts?.prepack, 'npm run build');
});
