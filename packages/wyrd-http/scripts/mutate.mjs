#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALL_ARMS as HTTP_ARMS } from '../test/arms.mjs';
import { ALL_ARMS as READER_ARMS } from '../../wyrd/test/arms.mjs';
import { lineEndingOf, withLineEnding } from '../../wyrd-fence/scripts/mutation-text.mjs';
import { guardBattery, batteryLockFixture, registerBatteryTargets, recordBatteryMutant, assertNoBatteryLockRefusal } from '../../wyrd-fence/scripts/battery-lock.mjs';
import {
    loadContract, refuse, verifyMutationResults, verifyMutationRows
} from '../../wyrd/scripts/verify-relocation-contract.mjs';

const pkg = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
if (!process.argv.some(arg => ['--selftest', '--eol-fixture', '--restore-fixture'].includes(arg))) guardBattery('http mutation');
batteryLockFixture();
const root = path.resolve(pkg, '..', '..');
const reader = path.join(root, 'packages', 'wyrd');
const ALL_ARMS = Object.freeze({ ...READER_ARMS, ...HTTP_ARMS });
const FILES = {
    bind: path.join(pkg, 'dist', 'bind.js'),
    tlsconfig: path.join(pkg, 'dist', 'tls-config.js'),
    http: path.join(pkg, 'dist', 'http.js')
};
const ROWS = [
    { id: 'M227-http-socket-close-retention', file: 'http',
        what: 'retain every closed connection in listener socket tracking',
        plan: 'HH26-reader-listener-state-bounded',
        from: '            sockets.delete(socket);',
        to: '            void socket;' },
    { id: 'M205-http-internal-drain-bypassed', file: 'http',
        what: 'end an unfinished internal-error refusal without the bounded upload drain',
        plan: 'HH25-internal-upload-500-delivered',
        from: 'sendEarlyRefusal(request, response, record.controller.signal, drainShutdown.signal, reserveDrain, 500,',
        to: 'sendStatus(response, 500,' },
    { id: 'M204-http-early-refusal-drain-bypassed', file: 'http',
        what: 'end unfinished early refusals without the bounded upload drain',
        plan: 'HH18-route-upload-404-delivered, HH19-method-upload-405-delivered, HH20-origin-upload-403-delivered, HH21-unauth-upload-401-delivered, HH22-unavailable-upload-503-delivered',
        from: 'if (!incoming.complete) {',
        to: 'if (false && !incoming.complete) {' },
    { id: 'M203-http-oversize-drain-cap-bypassed', file: 'http',
        what: 'admit unlimited concurrent oversized-upload drains',
        plan: 'HH14-oversize-drain-concurrency-cap',
        from: 'activeOversizeDrains >= MAX_CONCURRENT_OVERSIZE_DRAINS',
        to: 'false && activeOversizeDrains >= MAX_CONCURRENT_OVERSIZE_DRAINS' },
    { id: 'M206-http-oversize-drain-deadline-removed', file: 'http',
        what: 'extend the bounded oversized-upload drain deadline past the client timeout',
        plan: 'HH13-oversize-drain-deadline',
        from: 'setTimeout(finish, 1_500)',
        to: 'setTimeout(finish, 15_000)' },
    { id: 'M175-http-tls-shutdown-tracks-raw-socket', file: 'http',
        what: 'track only the raw TCP socket after a TLS handshake',
        plan: 'HH10-https-executing-response-during-close',
        from: '        trackSocket(secureSocket);',
        to: '        if (raw !== undefined) sockets.add(raw);' },
    { id: 'M173-http-runtime-error-handler-removed', file: 'http',
        what: 'suppress reporting of a live listener error after ordered shutdown begins',
        plan: 'HH9-runtime-server-error',
        from: 'options.onServerError?.(error, shutdown);',
        to: 'void error;' },
    { id: 'M133-tls-key-match-check-disabled', file: 'tlsconfig',
        what: 'disable the TLS certificate and private-key match check',
        plan: 'H29-tls-startup-validation',
        from: 'if (!certificate.checkPrivateKey(privateKey)) {',
        to: 'if (false && !certificate.checkPrivateKey(privateKey)) {' },
    { id: 'M134-tls-expiry-boundary-exclusive', file: 'tlsconfig',
        what: 'accept a TLS certificate at its exact expiry boundary',
        plan: 'H29-tls-startup-validation',
        from: 'if (nowMs >= validToMs)',
        to: 'if (nowMs > validToMs)' },
    { id: 'M110-auth-denial-bypassed', file: 'http',
        what: 'bypass the unauthenticated decision and continue to body collection and handler.fetch',
        plan: 'H15-auth-401-no-tool, H24-network-plain-http-auth',
        from: "if (authDecision.kind === 'unauthenticated') {\n        sendEarlyRefusal(",
        to: "if (false && authDecision.kind === 'unauthenticated') {\n        sendEarlyRefusal(" },
    { id: 'M111-auth-denial-is-403', file: 'http',
        what: 'map unauthenticated to 403 instead of the fixed 401',
        plan: 'H15-auth-401-no-tool, H24-network-plain-http-auth',
        from: "401, refusals.unauthenticated.body, refusals.unauthenticated.headers);",
        to: "403, refusals.unauthenticated.body, refusals.unauthenticated.headers);" },
    { id: 'M113-query-routed-by-pathname', file: 'http',
        what: 'route by pathname and accept a query string on /mcp',
        plan: 'H17-no-query-token-or-leak',
        from: "if (incoming.url !== '/mcp') {",
        to: "if (new URL(incoming.url ?? '/', 'http://localhost').pathname !== '/mcp') {" },
    { id: 'M118-tls-selects-http-server', file: 'http',
        what: 'select http.createServer while validated TLS material is present',
        plan: 'H28-generated-cert-trust-control',
        from: 'https.createServer(configuration.serverOptions, requestListener)',
        to: 'http.createServer(requestListener)' },
    { id: 'M119-tls-metadata-says-http', file: 'http',
        what: 'emit http scheme metadata for a TLS listener',
        plan: 'H30-tls-disclosure',
        from: '            scheme: tls.scheme,',
        to: "            scheme: 'http'," },
    { id: 'M121-tls-handshake-socket-untracked', file: 'http',
        what: 'skip listener-level tracking for sockets stalled during the TLS handshake',
        plan: 'H31-tls-handshake-shutdown',
        from: "    listener.on('connection', socket => {\n",
        to: "    listener.on('connection', socket => {\n        if (tls !== null) return;\n" },
    { id: 'M122-response-body-buffered', file: 'http',
        what: 'buffer the complete fetch response body before ending the HTTP response',
        plan: 'H19-response-stream',
        from: 'await pipeline(Readable.fromWeb(source.body), target);',
        to: 'target.end(await source.text());' },
    { id: 'M125-origins-manually-serialized', file: 'http',
        what: 'manually concatenate allowed origins instead of using URL serialization',
        plan: 'H21-origin-serialization',
        from: 'return Object.freeze(hosts.map(interfaceAddress => httpEndpointUrl(Object.freeze({ ...endpoint, interfaceAddress }), port).origin));',
        to: "return Object.freeze(hosts.map(interfaceAddress => `${endpoint.scheme}://${urlHost(interfaceAddress)}:${port}`));" },
    { id: 'M126-ipv6-url-host-unbracketed', file: 'http',
        what: 'return a bare IPv6 address instead of bracketing it for URL serialization',
        plan: 'H21-origin-serialization',
        from: "return bare.includes(':') ? `[${bare}]` : bare;",
        to: 'return bare;' },
    { id: 'M128-bind-kind-host-mismatch-disabled', file: 'http',
        what: 'disable the pre-handler bind kind and host mismatch guard',
        plan: 'H22-consent-and-guards',
        from: "if ((requestedKind === 'loopback') !== requestedLoopback) {",
        to: "if (false && (requestedKind === 'loopback') !== requestedLoopback) {" },
    { id: 'M129-reported-address-mismatch-dropped', file: 'http',
        what: 'drop the reported-address mismatch from the post-bind guard',
        plan: 'H22-consent-and-guards',
        from: 'if (refusal !== null || reportedAddress !== requestedAddress) {',
        to: 'if (refusal !== null) {' },
    { id: 'M127-network-consent-disabled', file: 'bind',
        what: 'disable refusal of a non-loopback HTTP address without public consent',
        plan: 'H22-consent-and-guards, H1-transport-selection',
        from: 'if (!publicRequested) {',
        to: 'if (false && !publicRequested) {' }
];

function prepareMutationRows(rows, source, ending) {
    return rows.map(row => {
        const from = withLineEnding(row.from, ending);
        const to = withLineEnding(row.to, ending);
        const occurrences = source.split(from).length - 1;
        if (occurrences !== 1) throw new Error(`${row.id}: anchor matched ${occurrences} times before mutation`);
        return { row, from, to };
    });
}

function applyMutationRow(prepared, source) {
    return source.replace(prepared.from, () => prepared.to);
}

if (process.argv.includes('--check-anchors')) {
    const problems = [];
    for (const row of ROWS) {
        const target = FILES[row.file];
        if (!target) {
            problems.push(`${row.id}: no mutation target is registered for file ${JSON.stringify(row.file)}`);
            continue;
        }
        const source = fs.readFileSync(target, 'utf8');
        const ending = lineEndingOf(source, target);
        const hits = source.split(withLineEnding(row.from, ending)).length - 1;
        if (hits !== 1) problems.push(`${row.id}: ${row.file} (${target}) anchor matched ${hits} times: ${JSON.stringify(row.from)}`);
    }
    if (problems.length) throw new Error(`mutation anchors are not applicable:\n${problems.join('\n')}`);
    console.log(`✔ HTTP mutation anchors: ${ROWS.length} rows apply to their registered targets.`);
    process.exit(0);
}

if (process.argv[2] === '--eol-fixture') {
    const [arm, target] = process.argv.slice(3);
    const bytes = fs.readFileSync(target);
    const source = bytes.toString('utf8');
    try {
        if (arm === 'BH2-eol-mixed') {
            let refused = false;
            try { lineEndingOf(source, target); } catch (error) {
                refused = /mixed or unsupported line endings/.test(error.message);
            }
            if (!refused) throw new Error('mixed-ending target was accepted');
        } else {
            const ending = lineEndingOf(source, target);
            if (arm === 'BH1-eol-crlf') {
                const prepared = prepareMutationRows([{ id: 'fixture',
                    from: 'alpha\nbeta', to: 'alpha\ndelta' }], source, ending);
                fs.writeFileSync(target, applyMutationRow(prepared[0], source));
                if (fs.readFileSync(target, 'utf8') !== 'alpha\r\ndelta\r\ngamma\r\n') throw new Error('CRLF edit did not land');
            } else if (arm === 'BH3-eol-all-edits') {
                const rows = [{ id: 'first', from: 'alpha', to: 'delta' },
                    { id: 'second', from: 'absent\nsecond', to: 'nope' }];
                let refused = false;
                try { prepareMutationRows(rows, source, ending); }
                catch (error) { refused = /second: anchor matched 0 times/.test(error.message); }
                if (!refused) throw new Error('second row was not refused before mutation');
            } else throw new Error('unknown EOL fixture arm');
        }
    } finally {
        fs.writeFileSync(target, bytes);
        if (!fs.readFileSync(target).equals(bytes)) throw new Error('fixture restore changed bytes');
    }
    console.log(`fixture ${arm}: http PASS`);
    process.exit(0);
}

// Match the suite classifiers: a signal or timeout outranks any printed red title, and
// only registered arm titles on a failed run can establish a kill.
function redTests(out) {
    const named = [...out.matchAll(/^✖ (.+?) \([\d.]+ms\)\r?$/gm)]
        .map(match => match[1].split(' — ')[0].trim());
    return [...new Set(named.filter(id => Object.hasOwn(ALL_ARMS, id)))];
}

// TLS rows require H29 assertion failures. Listener rows may deliberately cause timeouts inside named arms.
function assertionFailure(out, id) {
    const section = out.indexOf('✖ failing tests:');
    if (section === -1) return false;
    const detail = out.slice(section);
    const described = detail.indexOf(`✖ ${id} — `);
    const start = described === -1 ? detail.indexOf(`✖ ${id} (`) : described;
    if (start === -1) return false;
    const rest = detail.slice(start);
    const next = rest.slice(1).search(/\n✖ /);
    const body = next === -1 ? rest : rest.slice(0, next + 1);
    return body.includes("code: 'ERR_ASSERTION'");
}

function classifyRunner(run, requireAssertion = true, greenMarker = '✔ suite gate:') {
    const out = `${run.stdout ?? ''}\n${run.stderr ?? ''}`;
    assertNoBatteryLockRefusal(out);
    if (run.error?.code === 'ETIMEDOUT') return { status: 'TIMEOUT', red: [], out };
    if (run.signal) return { status: 'SIGNAL', red: [], out };
    if (run.error || run.status === null) return { status: 'INFRASTRUCTURE', red: [], out };
    if (run.status === 0) {
        return { status: out.includes(greenMarker) && redTests(out).length === 0
            ? 'SURVIVED' : 'NONZERO_NO_ARM', red: [], out };
    }
    const red = redTests(out);
    if (!red.length || (requireAssertion && !red.every(id => assertionFailure(out, id)))) {
        return { status: 'NONZERO_NO_ARM', red: [], out };
    }
    return { status: 'KILLED', red, out };
}

function selftest() {
    const title = '✖ H29-tls-startup-validation — synthetic (1.25ms)\n';
    const assertion = `✖ failing tests:\n${title}  code: 'ERR_ASSERTION'\n`;
    const fixture = `✖ failing tests:\n${title}  code: 'EACCES'\n`;
    const cases = [
        ['green', { status: 0, stdout: '✔ suite gate: 69 declared arms all executed' }, 'SURVIVED'],
        ['assertion', { status: 1, stdout: assertion }, 'KILLED'],
        ['fixture failure with red title', { status: 1, stdout: fixture }, 'NONZERO_NO_ARM'],
        ['signal with red title', { status: null, signal: 'SIGKILL', stdout: assertion }, 'SIGNAL'],
        ['timeout with red title', { status: null, error: { code: 'ETIMEDOUT' }, stdout: assertion }, 'TIMEOUT'],
        ['nonzero without arm', { status: 1, stdout: 'runner error' }, 'NONZERO_NO_ARM'],
        ['zero without suite gate', { status: 0, stdout: title }, 'NONZERO_NO_ARM'],
        ['zero with red title', { status: 0, stdout: `✔ suite gate:\n${title}` }, 'NONZERO_NO_ARM']
    ];
    for (const [name, run, expected] of cases) {
        const actual = classifyRunner(run);
        if (actual.status !== expected) throw new Error(`${name}: expected ${expected}, got ${actual.status}`);
        if (expected === 'KILLED' && actual.red.join(',') !== 'H29-tls-startup-validation') {
            throw new Error(`${name}: the registered red arm was lost`);
        }
    }
    const listenerTimeout = classifyRunner({ status: 1, stdout:
        '\u2716 H15-auth-401-no-tool \u2014 synthetic (1.25ms)\n\u2716 failing tests:\n  Error: timeout inside arm\n' }, false);
    if (listenerTimeout.status !== 'KILLED' || listenerTimeout.red.join(',') !== 'H15-auth-401-no-tool') {
        throw new Error('listener arm timeout was not attributed to its registered arm');
    }
    console.log(`HTTP mutation classifier self-test: ${cases.length + 1}/${cases.length + 1}`);
}

function filesUnder(dir) {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
        const file = path.join(dir, entry.name);
        if (entry.isDirectory()) return filesUnder(file);
        if (!entry.isFile()) throw new Error(`unexpected HTTP source/output entry: ${file}`);
        return [file];
    });
}

function snapshot() {
    const files = [...filesUnder(path.join(pkg, 'src')), ...filesUnder(path.join(pkg, 'dist'))];
    for (const target of Object.values(FILES)) {
        if (!files.includes(target)) throw new Error('mutation target missing from built-output snapshot');
    }
    return new Map(files.map(file => [file, fs.readFileSync(file)]));
}

function restoreAndVerify(original) {
    const actual = [...filesUnder(path.join(pkg, 'src')), ...filesUnder(path.join(pkg, 'dist'))];
    const extras = actual.filter(file => !original.has(file));
    for (const [file, bytes] of original) fs.writeFileSync(file, bytes);
    const digest = bytes => createHash('sha256').update(bytes).digest('hex');
    const differing = [...original].filter(([file, bytes]) => {
        const restored = fs.readFileSync(file);
        return digest(restored) !== digest(bytes) || !restored.equals(bytes);
    })
        .map(([file]) => file);
    if (extras.length || differing.length) {
        throw new Error(`HTTP restore infrastructure error: extra ${extras.join(', ') || '(none)'}; differing ${differing.join(', ') || '(none)'}`);
    }
}

if (process.argv.includes('--bh6-spawn-fixture')) {
    const failed = spawnSync(path.join(root, 'missing-executable'), [], { encoding: 'utf8' });
    const verdict = classifyRunner(failed);
    if (verdict.status !== 'INFRASTRUCTURE') throw new Error(`spawn failure received ${verdict.status}`);
    console.log(`INFRASTRUCTURE: ${verdict.status}`);
    process.exit(0);
}

if (process.argv.includes('--selftest')) {
    selftest();
    process.exit(0);
}

const { contract, problems } = loadContract();
if (problems.length) refuse(problems, 'the contract is not internally consistent');
const rowProblems = verifyMutationRows(contract, 'wyrd-http', ROWS.map(
    ({ id, file, what, plan }) => ({ id, file, mutates: what, plan })
));
if (rowProblems.length) refuse(rowProblems, 'the HTTP mutation rows do not match the contract');

const only = process.argv.find((value, index) => process.argv[index - 1] === '--only');
const selected = only === undefined ? ROWS : ROWS.filter(row => only.split(',').includes(row.id));
if (selected.length === 0 || (only !== undefined && selected.length !== only.split(',').length)) {
    throw new Error('--only must name existing HTTP mutation rows exactly once');
}

const build = spawnSync(`npm --prefix "${root}" --workspace wyrd-mcp run build`, {
    cwd: root, shell: true, stdio: 'inherit'
});
if (build.error || build.status !== 0) throw new Error(`Reader build failed: ${build.error ?? build.status}`);

const original = snapshot();
registerBatteryTargets([...original.keys()]);
const prepared = selected.map(row => {
    const target = FILES[row.file];
    const originalText = original.get(target).toString('utf8');
    const ending = lineEndingOf(originalText, target);
    return { target, originalText, ...prepareMutationRows([row], originalText, ending)[0] };
});
const runReader = (requireAssertion = true) => classifyRunner(spawnSync(process.execPath, [path.join(reader, 'scripts', 'run-tests.mjs')], {
    cwd: reader, encoding: 'utf8', timeout: 240_000, maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' }
}), requireAssertion);
const runHttp = () => classifyRunner(spawnSync(process.execPath, [path.join(pkg, 'scripts', 'run-tests.mjs')], {
    cwd: pkg, encoding: 'utf8', timeout: 240_000, maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' }
}), true, 'HTTP gate:');
const httpOnlyRows = ['M227-http-socket-close-retention', 'M205-http-internal-drain-bypassed', 'M204-http-early-refusal-drain-bypassed', 'M175-http-tls-shutdown-tracks-raw-socket', 'M173-http-runtime-error-handler-removed', 'M206-http-oversize-drain-deadline-removed', 'M203-http-oversize-drain-cap-bypassed'];
const needsHttp = selected.some(row => httpOnlyRows.includes(row.id));
const needsReader = selected.some(row => !['M227-http-socket-close-retention', 'M205-http-internal-drain-bypassed', 'M204-http-early-refusal-drain-bypassed', 'M175-http-tls-shutdown-tracks-raw-socket', 'M206-http-oversize-drain-deadline-removed', 'M203-http-oversize-drain-cap-bypassed'].includes(row.id));
for (const [name, control] of [
    ...(needsReader ? [['Reader', runReader()]] : []),
    ...(needsHttp ? [['HTTP', runHttp()]] : [])
]) {
    if (control.status !== 'SURVIVED') {
        throw new Error(`unmutated ${name} control failed: ${control.status}\n${control.out.slice(-4000)}`);
    }
}
const results = [];
let restored = false;
try {
    for (const { row, from, to, target, originalText } of prepared) {
        const occurrences = originalText.split(from).length - 1;
        if (occurrences !== 1) {
            results.push({ id: row.id, status: 'ANCHOR-NOT-FOUND', red: [] });
            continue;
        }
        const mutant = applyMutationRow({ from, to }, originalText);
        recordBatteryMutant(target, Buffer.from(mutant));
        fs.writeFileSync(target, mutant);
        try {
            // Both runners consume mutated HTTP dist directly. Rebuilding here would erase it.
            const result = httpOnlyRows.includes(row.id)
                ? runHttp()
                : runReader(row.file === 'tlsconfig');
            results.push({ id: row.id, status: result.status, red: result.red });
            console.log(`${row.id}: ${result.status}; red: ${result.red.join(', ') || '(none)'}`);
            if (row.id === 'M227-http-socket-close-retention') {
                const heap = result.out.match(/retained heap 100=\d+ 500=\d+ 1000=\d+; growth=-?\d+; elapsedMs=\d+/);
                if (heap) console.log(`${row.id}: ${heap[0]}`);
            }
            if (['NONZERO_NO_ARM', 'SIGNAL', 'TIMEOUT', 'INFRASTRUCTURE'].includes(result.status)) {
                console.error(result.out.slice(-4000));
            }
        } finally {
            restoreAndVerify(original);
            console.log(`${row.id}: all ${original.size} source/output SHA-256 hashes and bytes restored`);
        }
    }
    restored = true;
} finally {
    restoreAndVerify(original);
}
const verdict = verifyMutationResults(contract, 'wyrd-http', results, {
    full: only === undefined, restored
});
for (const note of verdict.notes) console.log(note);
if (verdict.problems.length) refuse(verdict.problems, 'HTTP mutation results');
console.log(`HTTP mutations: ${results.length} rows measured; all ${original.size} source and built-output files restored byte-for-byte.`);
