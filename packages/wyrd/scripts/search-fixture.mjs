import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const DEFAULT_COUNT = 2_000;
export const DEFAULT_SEED = 0x5eed2026;
export const DEFAULT_OVERSIZED_BYTES = 52 * 1024 * 1024;
export const SCAN_WINDOW_BYTES = 64 * 1024;
// Chosen quantile targets for the fixture's size distribution.
const ORDINARY_MEDIAN_LO = 6_804;
const ORDINARY_MEDIAN_HI = 6_805;
const ORDINARY_P95 = 51_517;
const ORDINARY_MAX = 286_434;

function ordinarySize(rank, count) {
    // Piecewise linear quantile fit. For the default 1,999 ordinary files the
    // middle pair is 6,804/6,805 B and nearest-rank p95 is 51,517 B.
    const middle = Math.floor((count - 1) / 2);
    const p95 = Math.ceil((count + 1) * 0.95) - 1;
    const interpolate = (a, b, at, end) => Math.round(a + (b - a) * at / Math.max(1, end));
    if (rank <= middle) return interpolate(350, ORDINARY_MEDIAN_LO, rank, middle);
    if (rank <= p95) return interpolate(ORDINARY_MEDIAN_HI, ORDINARY_P95, rank - middle - 1, p95 - middle - 1);
    return interpolate(ORDINARY_P95, ORDINARY_MAX, rank - p95, count - 1 - p95);
}

function nextRandom(seed) {
    let state = seed >>> 0;
    return () => {
        state ^= state << 13;
        state ^= state >>> 17;
        state ^= state << 5;
        return state >>> 0;
    };
}

function writeLargeFile(filename, bytes) {
    const line = Buffer.from('Archive continuity memory atlas. Résumé 東京 😀\n');
    const block = Buffer.alloc(SCAN_WINDOW_BYTES, 0x20);
    for (let offset = 0; offset + line.length <= block.length; offset += line.length)
        line.copy(block, offset);
    const fd = fs.openSync(filename, 'wx');
    try {
        const writeAll = buffer => {
            for (let offset = 0; offset < buffer.length;) {
                const written = fs.writeSync(fd, buffer, offset, buffer.length - offset);
                if (written <= 0) throw new Error('oversized fixture write made no progress');
                offset += written;
            }
        };
        for (let remaining = bytes; remaining > 0;) {
            const next = remaining >= block.length ? block : Buffer.alloc(remaining, 0x20);
            writeAll(next);
            remaining -= next.length;
        }
    } finally { fs.closeSync(fd); }
}

/** Generate only beneath a caller-owned, initially absent directory. */
export function generateSearchVault(root, { count = DEFAULT_COUNT, seed = DEFAULT_SEED,
    oversizedBytes = DEFAULT_OVERSIZED_BYTES, includeOversized = true } = {}) {
    if (!Number.isSafeInteger(count) || count < 4 || !Number.isSafeInteger(seed) ||
        !Number.isSafeInteger(oversizedBytes) || oversizedBytes <= SCAN_WINDOW_BYTES * 8)
        throw new Error('count, seed or oversizedBytes outside fixture bounds');
    fs.mkdirSync(root);
    const random = nextRandom(seed);
    const buckets = ['Arc/Sources', 'Arc/Record', 'Mage/Topics', 'Mage/Projects/Notes',
        'Mage/People', 'Forum/Antechamber', 'Forum/Threads/2024', 'Forum/Threads/2025'];
    const ordinaryCount = count - 1;
    const ranks = Array.from({ length: ordinaryCount }, (_, index) => index);
    for (let i = ranks.length - 1; i > 0; i--) {
        const j = random() % (i + 1);
        [ranks[i], ranks[j]] = [ranks[j], ranks[i]];
    }
    let frontmatterCount = 0;
    for (let i = 0; i < ordinaryCount; i++) {
        const bucket = buckets[random() % buckets.length];
        const filename = path.join(root, bucket, `${String(i).padStart(5, '0')}.md`);
        fs.mkdirSync(path.dirname(filename), { recursive: true });
        const target = ordinarySize(ranks[i], ordinaryCount);
        const frontmatter = i % 4 === 0 ? '---\ntype: note\nstatus: draft\n---\n' : '';
        if (frontmatter) frontmatterCount++;
        const head = Buffer.from(`${frontmatter}# Note ${i}\ncafé naïve 東京\n`);
        const line = Buffer.from(`needle atlas memory garden context source record ${i % 97}.\n`);
        const body = Buffer.alloc(target, 0x20);
        head.copy(body);
        for (let at = head.length; at < body.length; at += line.length)
            line.copy(body, at, 0, Math.min(line.length, body.length - at));
        fs.writeFileSync(filename, body, { flag: 'wx' });
    }
    const oversizedRelative = 'Forum/Threads/2025/oversized.md';
    if (includeOversized) writeLargeFile(path.join(root, ...oversizedRelative.split('/')), oversizedBytes);
    const sizes = [];
    const inspect = directory => {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
            const name = path.join(directory, entry.name);
            if (entry.isDirectory()) inspect(name);
            else if (entry.isFile() && /\.md$/i.test(entry.name)) sizes.push(fs.statSync(name).size);
            else throw new Error('fixture contains an unexpected entry');
        }
    };
    inspect(root);
    if (sizes.length !== ordinaryCount + Number(includeOversized)) throw new Error('fixture file count differs from requested count');
    const measuredOversizedBytes = includeOversized ? fs.statSync(path.join(root, ...oversizedRelative.split('/'))).size : null;
    if (includeOversized && measuredOversizedBytes !== oversizedBytes) throw new Error('oversized file length differs from requested length');
    sizes.sort((a, b) => a - b);
    const ordinary = includeOversized ? sizes.slice(0, -1) : sizes;
    const median = values => (values[Math.floor((values.length - 1) / 2)] + values[Math.ceil((values.length - 1) / 2)]) / 2;
    return { count: sizes.length, seed, oversizedRelative, oversizedBytes: measuredOversizedBytes, frontmatterCount,
        medianBytes: median(sizes), p95Bytes: sizes[Math.ceil(sizes.length * 0.95) - 1],
        ordinaryMedianBytes: median(ordinary), ordinaryP95Bytes: ordinary[Math.ceil(ordinary.length * 0.95) - 1],
        ordinaryMaxBytes: ordinary.at(-1) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const args = process.argv.slice(2);
    const value = flag => { const at = args.indexOf(flag); return at < 0 ? undefined : args[at + 1]; };
    const root = value('--out');
    if (!root) throw new Error('usage: node search-fixture.mjs --out <new temp directory> [--count N] [--seed N] [--oversized-bytes N]');
    const number = (flag, fallback) => value(flag) === undefined ? fallback : Number(value(flag));
    console.log(JSON.stringify(generateSearchVault(root, { count: number('--count', DEFAULT_COUNT),
        seed: number('--seed', DEFAULT_SEED),
        oversizedBytes: number('--oversized-bytes', DEFAULT_OVERSIZED_BYTES),
        includeOversized: !args.includes('--ordinary-only') })));
}
