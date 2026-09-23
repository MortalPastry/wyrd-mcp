#!/usr/bin/env node
/**
 * Drive the built server over real stdio, as a client — `npm run drive`.
 *
 * ⚠ WHY THIS EXISTS SEPARATELY FROM THE TEST SUITE. `test/` proves the fence against fixtures it
 * builds itself. This spawns `dist/index.js` as a subprocess, speaks the client half of MCP to it,
 * and prints a SUMMARY of what a driving model receives — the initialize result, the `tools/list`
 * payload the model's selection loop runs on, and real calls against a real folder.
 *
 * ⚠ IT IS A SUMMARY, NOT A TRANSCRIPT. Response bodies are truncated for readability and call
 * failures are caught and accounted rather than thrown.
 *
 * ⚠ IT DOES EXIT NON-ZERO on a thrown call, a failed ordinary read, or a refusal probe that did not
 * refuse — so it is a narrow gate, not the no-gate its header claimed until 2026-08-29. What it is
 * NOT is the acceptance gate: it exercises a handful of paths against one folder, and a green here
 * says nothing about the 71-arm battery. `npm test` is that gate. Read the per-call `isError` lines
 * rather than trusting the absence of a stack trace.
 *
 * ⚠ IT IS STILL NOT A THIRD-PARTY CLIENT. This uses the repository's independent wire client, so
 * it proves the protocol exchange and the product surface — not that Claude Code, Cursor, ChatGPT
 * or Codex parse it the same way. That gap stays open in NEXT.md until a real client has connected.
 *
 * SEQUENCING RAIL: there is NO default grant. A new mechanism proves itself against a disposable
 * test folder before it points at a real Mage, and the folder is named on every run:
 *     npm run drive -- --grant <path>        or        WYRD_DRIVE_GRANT=<path> npm run drive
 * ⚠ Until 2026-09-02 this script defaulted to a folder beside the author's checkout, spelled by
 * name — a path from one machine, shipped in every tarball. The completeness half of the release
 * gate found it on its first run. A shipped script has no business knowing where its author keeps
 * anything; a driver with no default cannot leak one.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { RawMcpClient } from '../test/raw-stdio.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SERVER = path.join(repo, 'dist', 'index.js');

/**
 * ⚠ THE GRANT IS SUPPLIED, NEVER DERIVED. An earlier version computed a default by counting `..`
 * from this file to a folder outside the repo, and the count broke silently on the 2026-08-31 move
 * under `packages/wyrd/` — it failed loudly only because nothing happened to exist at the wrong
 * path. A relative path that counts `..` is a claim about directory depth, and a restructure is
 * exactly what invalidates it without touching the line. Requiring the path removes the claim.
 */
const flag = process.argv.indexOf('--grant');
const GRANT = flag !== -1 ? process.argv[flag + 1] : process.env.WYRD_DRIVE_GRANT;
if (!GRANT) {
    console.error('drive: no grant. Name a DISPOSABLE folder — `npm run drive -- --grant <path>` or '
        + 'WYRD_DRIVE_GRANT=<path>. This driver has no default on purpose: a default is a path from '
        + 'somebody\'s machine, shipped.');
    process.exit(2);
}

console.log(`server : ${SERVER}`);
console.log(`grant  : ${GRANT}`);

const client = new RawMcpClient({
    entrypoint: SERVER,
    entrypointLabel: 'dist/index.js',
    args: ['--grant', GRANT],
    clientInfo: { name: 'wyrd-drive', version: '0.0.0' }
});

const timer = setTimeout(() => {
    console.error('\n⛔ TIMEOUT — the server did not complete the exchange in 20s.');
    process.exit(1);
}, 20_000);

let serverStderr = '';
client.stderr?.on('data', chunk => {
    serverStderr += chunk;
});
await client.connect();

console.log('\n=== 1. INITIALIZE ===');
console.log('serverInfo   :', JSON.stringify(client.getServerVersion()));
console.log('capabilities :', JSON.stringify(client.getServerCapabilities()));
console.log('instructions :', JSON.stringify(client.getInstructions() ?? null));

console.log('\n=== 2. tools/list — THE PRODUCT SURFACE ===');
const listed = await client.listTools();
for (const tool of listed.tools) {
    console.log(`name        : ${tool.name}`);
    console.log(`title       : ${tool.title ?? '(none)'}`);
    console.log(`schema keys : ${Object.keys(tool.inputSchema.properties ?? {}).join(', ')}`);
    console.log(`required    : ${JSON.stringify(tool.inputSchema.required ?? [])}`);
    console.log(`description :\n${tool.description}`);
}

/**
 * ⚠ EVERY CALL HAS THREE OUTCOMES, NOT TWO, AND CONFLATING THE THIRD WITH EITHER OTHER ONE IS HOW
 * THIS SCRIPT USED TO EXIT 0 ON A BROKEN SURFACE. A thrown exception was previously printed and
 * then dropped on the floor: it incremented nothing, so a run in which every ordinary read THREW
 * still reported `reads that failed: 0` and exited 0. Both round-3 review lenses flagged it.
 *
 *   'ok'      the call returned and the server did not mark it an error
 *   'refused' the call returned with `isError: true` — the fence firing, which is a RESULT
 *   'threw'   the call did not return at all — transport, protocol or crash
 *
 * A throw is never a refusal. The designed refusal shape is an `isError` result carrying a reason;
 * a throw means the exchange itself broke, which is a different failure and must not be allowed to
 * satisfy a refusal probe.
 */
async function call(label, args) {
    console.log(`\n--- ${label} — read(${JSON.stringify(args)}) ---`);
    try {
        const result = await client.callTool({ name: 'read', arguments: args });
        console.log('isError:', result.isError === true);
        for (const part of result.content) {
            const text = part.type === 'text' ? part.text : `<${part.type}>`;
            // ⚠ TRUNCATED FOR READING, and the marker says so — a reader must not mistake a
            // clipped body for the whole response.
            console.log(text.length > 300 ? `${text.slice(0, 300)}\n   …[TRUNCATED — ${text.length} chars total]` : text);
        }
        return result.isError === true ? 'refused' : 'ok';
    } catch (error) {
        console.log('THREW:', error.message);
        return 'threw';
    }
}

console.log('\n=== 3. REAL READS — these must SUCCEED ===');
const reads = [
    await call('an ordinary file', { path: 'README.md' }),
    await call('a tiny window, forcing truncation', { path: 'README.md', offset: 0, limit: 40 })
];
// Anything that is not 'ok' failed, whether it refused or threw. A read that throws is at least as
// broken as one that refuses, and the old accounting counted neither.
const readFailures = reads.filter(outcome => outcome !== 'ok').length;

console.log('\n=== 4. REFUSALS — these must FAIL, and the reason is the point ===');
const probes = [
    await call('climbing out with ..', { path: '../Wyrd/package.json' }),
    await call('an absolute path', { path: 'C:/Windows/win.ini' }),
    await call('a file that is not there', { path: 'no-such-file.md' }),
    await call('the grant root itself', { path: '.' }),
    await call('a directory, not a file', { path: 'example' })
];
const refusalCount = probes.filter(outcome => outcome === 'refused').length;
// Tracked separately and reported separately: a probe that THREW did not refuse. Folding it into
// the refusal count would let a broken exchange stand in for a working fence.
const threwCount = [...reads, ...probes].filter(outcome => outcome === 'threw').length;

clearTimeout(timer);
await client.close();
if (serverStderr.trim()) {
    // ⚠ NOT THE DISCLOSURE. The model-facing disclosure is `initialize.instructions`, printed in
    // section 1. This is the operator-facing startup line, which a client is free to discard and
    // most do — calling it "the disclosure" is how the two get confused.
    console.log('\n=== SERVER STDERR — the OPERATOR-facing startup line, which no model sees ===');
    console.log(serverStderr.trim());
}

console.log(
    `\nreads that failed: ${readFailures} (expected 0)` +
    ` · refusals that fired: ${refusalCount} (expected 5)` +
    ` · calls that THREW: ${threwCount} (expected 0)`
);
// ⚠ THROWS ARE DIAGNOSED FIRST, AND THE ORDER IS THE WHOLE POINT OF THIS BLOCK. Both review lenses
// found this check placed LAST, where it was unreachable: a thrown read already trips the read gate,
// and a thrown refusal probe already trips the refusal gate by not counting as a refusal. Nothing
// could exit 0 — the behaviour was safe — but the branch was dead and its comment claimed the gates
// above did not cover throws, which was false. A throw is a broken exchange rather than a fence
// result, so it is both the most severe diagnosis and the most specific: it goes first, where it can
// actually fire and say the true thing.
if (threwCount > 0) {
    console.error(`⛔ ${threwCount} call(s) threw rather than returning — the exchange broke, so nothing below is a fence result.`);
    process.exit(1);
}
if (readFailures > 0) {
    console.error('⛔ an ordinary read failed — the surface is not healthy.');
    process.exit(1);
}
if (refusalCount < 5) {
    console.error('⛔ a refusal probe did NOT refuse — the fence did not fire where it must.');
    process.exit(1);
}
