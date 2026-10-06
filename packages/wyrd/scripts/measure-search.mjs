import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { createFsGate, isRefusal } from 'wyrd-fence';
import { createSearchEngine } from '../dist/search.js';
import '../dist/main.js';
import { createServer, detectLayers } from '../dist/server.js';
import { RawMcpClient } from '../test/raw-stdio.mjs';
import { DEFAULT_COUNT, DEFAULT_OVERSIZED_BYTES, DEFAULT_SEED } from './search-fixture.mjs';

const args = process.argv.slice(2);
const value = flag => { const at = args.indexOf(flag); return at < 0 ? undefined : args[at + 1]; };
const number = (flag, fallback) => value(flag) === undefined ? fallback : Number(value(flag));
const vault = value('--vault');
const endToEnd = args.includes('--end-to-end');
if (!vault) throw new Error('usage: node measure-search.mjs --vault <new temp directory> [--count N] [--seed N] [--oversized-bytes N] [--ordinary-only] [--end-to-end]');
const absoluteVault = path.resolve(vault);
const relativeToTemp = path.relative(fs.realpathSync(os.tmpdir()), path.resolve(path.dirname(absoluteVault)));
if (relativeToTemp.startsWith('..') || path.isAbsolute(relativeToTemp) ||
    absoluteVault === path.resolve(os.tmpdir()))
    throw new Error('--vault must name a new directory beneath the process temp directory');

const queries = ['needle', 'needle', 'atlas', 'memory', 'café', 'absent_query_token'];
const timing = async (search, query) => {
    const start = performance.now();
    const result = await search(query);
    return { ms: performance.now() - start, hits: result.hits.length, state: result.state };
};
const verdict = (value, budget) => value < budget ? 'PASS' : 'MISS';
let peakRss = 0;
const observeRss = () => { peakRss = Math.max(peakRss, process.memoryUsage().rss); };
observeRss();
const sampler = setInterval(observeRss, 2);
let created = false;
let monitorPath, telemetryPath;
try {
    if (fs.existsSync(absoluteVault)) throw new Error('--vault already exists');
    created = true;
    const generator = fileURLToPath(new URL('./search-fixture.mjs', import.meta.url));
    const generated = spawnSync(process.execPath, [generator, '--out', absoluteVault,
        '--count', String(number('--count', DEFAULT_COUNT)),
        '--seed', String(number('--seed', DEFAULT_SEED)),
        '--oversized-bytes', String(number('--oversized-bytes', DEFAULT_OVERSIZED_BYTES)),
        ...(args.includes('--ordinary-only') ? ['--ordinary-only'] : [])],
    { encoding: 'utf8', maxBuffer: 1024 * 1024 });
    if (generated.status !== 0) throw new Error(`fixture generation failed: ${generated.stderr}`);
    const fixture = JSON.parse(generated.stdout);
    observeRss();
    let client;
    if (endToEnd) {
        monitorPath = absoluteVault + '.rss.cjs';
        telemetryPath = absoluteVault + '.rss.json';
        fs.writeFileSync(monitorPath, [
            "const fs = require('node:fs');",
            'let baseline = null, peak = 0;',
            "require('node:diagnostics_channel').channel('wyrd.search.pre-engine').subscribe(rss => { if (baseline === null) baseline = rss; });",
            'const tick = () => { peak = Math.max(peak, process.memoryUsage().rss); };',
            'const timer = setInterval(tick, 2); timer.unref(); tick();',
            "process.on('exit', () => { clearInterval(timer); tick(); peak = Math.max(peak, process.resourceUsage().maxRSS * 1024); fs.writeFileSync(process.env.WYRD_MEASURE_RSS_OUT, JSON.stringify({ baseline, peak })); });"
        ].join('\n'));
        const entrypoint = fileURLToPath(new URL('../dist/index.js', import.meta.url));
        client = new RawMcpClient({ entrypoint, entrypointLabel: 'dist/index.js',
            env: { ...process.env, WYRD_GRANT: absoluteVault,
                WYRD_MEASURE_RSS_OUT: telemetryPath,
                NODE_OPTIONS: '--require=' + monitorPath },
            clientInfo: { name: 'search-measure', version: '1' } });
        await client.connect();
    }
    const gate = endToEnd ? null : createFsGate({ rawGrant: absoluteVault });
    if (!endToEnd && isRefusal(gate)) throw new Error(`fixture grant refused: ${gate.reason}`);
    const layers = endToEnd ? null : await detectLayers(name => gate.probeInGrant(name));
    const reader = endToEnd ? null : createServer({ fsgate: gate, transport: 'stdio',
        layers: layers.layers, listingFailed: layers.listingFailed });
    const baselineRss = process.memoryUsage().rss;
    const search = endToEnd ? async query => {
        const call = await client.callTool({ name: 'search', arguments: { query } });
        if (call.isError) throw new Error(call.content?.[0]?.text ?? 'search refused');
        return call.structuredContent;
    } : createSearchEngine(gate);
    const cold = await timing(search, queries[0]);
    observeRss();
    const warm = [];
    for (const query of queries.slice(1)) {
        warm.push(await timing(search, query));
        observeRss();
    }
    const ordered = warm.map(item => item.ms).sort((a, b) => a - b);
    const median = ordered[Math.floor(ordered.length / 2)];
    const worst = ordered.at(-1);
    if (client) await client.close();
    const childRss = endToEnd ? JSON.parse(fs.readFileSync(telemetryPath, 'utf8')) : null;
    const osPeakKb = process.resourceUsage().maxRSS;
    const measuredPeakRss = endToEnd ? childRss.peak : (osPeakKb > 0 ? osPeakKb * 1024 : peakRss);
    const measuredBaselineRss = endToEnd ? childRss.baseline : baselineRss;
    const rssGrowth = Math.max(0, measuredPeakRss - measuredBaselineRss);
    const mib = bytes => (bytes / 1024 / 1024).toFixed(2);
    console.log(`Node ${process.version}; ${os.type()} ${os.release()} ${os.arch()}; ${os.cpus().length} logical CPUs; ${(os.totalmem() / 1024 ** 3).toFixed(2)} GiB RAM`);
    console.log(`Fixture disk inventory: ${fixture.count} Markdown files; configured seed ${fixture.seed}; median ${fixture.medianBytes} bytes, p95 ${fixture.p95Bytes} bytes; ordinary median ${fixture.ordinaryMedianBytes} bytes, ordinary p95 ${fixture.ordinaryP95Bytes} bytes, ordinary max ${fixture.ordinaryMaxBytes} bytes; oversized ${fixture.oversizedBytes ?? 'omitted'} bytes; temp path ${absoluteVault}`);
    console.log(`Configuration: ${endToEnd ? 'real MCP client over stdio; dispatch included' : 'core search engine; dispatch excluded'}; ${args.includes('--ordinary-only') ? 'time-budget fixture' : 'oversized-file memory proof'}.`);
    console.log(`Queries: ${JSON.stringify(queries)}; cold hits ${cold.hits}; warm hits ${JSON.stringify(warm.map(item => item.hits))}`);
    console.log(`Cold first query: ${cold.ms.toFixed(1)} ms | re-ruled < 5000 ms ${args.includes('--ordinary-only') ? '(judged)' : '(informational)'} | ${args.includes('--ordinary-only') ? verdict(cold.ms, 5000) : 'N/A'}`);
    console.log(`Warm median: ${median.toFixed(1)} ms | re-ruled < 500 ms ${args.includes('--ordinary-only') ? '(judged)' : '(informational)'} | ${args.includes('--ordinary-only') ? verdict(median, 500) : 'N/A'}`);
    console.log(`Warm worst: ${worst.toFixed(1)} ms | recorded, not budgeted`);
    console.log(`Observed server peak RSS: ${mib(measuredPeakRss)} MiB; pre-engine baseline: ${mib(measuredBaselineRss)} MiB; growth: ${mib(rssGrowth)} MiB | re-ruled < 100 MB | ${verdict(rssGrowth, 100_000_000)}`);
    console.log(`RSS observation: ${endToEnd ? 'server child high-water maxRSS and 2 ms sampler; diagnostic-channel baseline before engine construction' : (osPeakKb > 0 ? 'OS process high-water maxRSS' : '2 ms timer plus query checkpoints')}`);
    console.log(`Overall: ${rssGrowth < 100_000_000 && (!args.includes('--ordinary-only') || (cold.ms < 5000 && median < 500)) ? 'PASS' : 'MISS'}; process exit 0 means measurement completed, not that budgets passed.`);
} finally {
    clearInterval(sampler);
    if (created) fs.rmSync(absoluteVault, { recursive: true, force: true });
    for (const file of [monitorPath, telemetryPath]) if (file) fs.rmSync(file, { force: true });
}
