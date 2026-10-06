import { createHash } from 'node:crypto';
import { isRefusal, type FileMetadata, type FsGate, type GrantWalk, type Slice } from 'wyrd-fence';

export const SCAN_BYTES = 64 * 1024;
const EXCERPT_BYTES = 1024;
const HIT_LIMIT = 10;
const HASH_WINDOW_LIMIT = 16;
const tokenCharacter = /[\p{L}\p{N}_]/u;
const markdownFile = (path: string): boolean => /\.(?:md|markdown)$/i.test(path);
const maySearch = (file: FileMetadata): boolean =>
    file.dehydrated === false || (file.dehydrated === null && process.platform !== 'win32');

export interface SearchCandidate {
    readonly path: string;
    readonly byte_offset: number;
    readonly excerpt_start: number;
    readonly version: { readonly kind: 'stat'; readonly value: string } |
        { readonly kind: 'sha256'; readonly value: string };
    /** Exclusive UTF-8 byte end of the passage starting at byte_offset. */
    readonly source_range_end?: number;
}

export interface SearchSnapshot {
    readonly files: readonly FileMetadata[];
}

/** The port can only read a named, bounded file slice from the current grant. */
export interface SearchReads {
    read(path: string, offset: number, bytes: number): Promise<Slice | null>;
    metadata(path: string): Promise<FileMetadata | null>;
}

export interface SearchBackend {
    search(snapshot: SearchSnapshot, query: string, reads: SearchReads): Promise<{
        readonly candidates: readonly SearchCandidate[];
        readonly hasMore: boolean;
        readonly typed_files: number;
        readonly searched_files: number | null;
    }>;
}

/** Startup contract for an operator-selected module, without grant paths or a fence. */
export interface SearchBackendHost {
    readonly contractVersion: 1;
    readonly grantId: string;
    readonly maxSliceBytes: number;
    readonly layers: readonly string[];
    readonly listingFailed: boolean;
    readonly lexical: SearchBackend;
}

export interface SearchBackendModuleResult {
    readonly backend: SearchBackend;
    readonly disclosure: readonly string[];
    readonly close?: () => void | Promise<void>;
}

export interface SearchBackendModule {
    createSearchBackend(host: SearchBackendHost): SearchBackendModuleResult | Promise<SearchBackendModuleResult>;
}

export interface SearchBackendDisclosure {
    readonly path: string;
    readonly lines: readonly string[];
}

const changeKey = (file: FileMetadata): string => `${file.mtimeMs}:${file.size}`;
const words = (input: string): string[] =>
    [...input.normalize('NFKC').toLowerCase().matchAll(/[\p{L}\p{N}_]+/gu)].map(match => match[0]);

interface CachedFile {
    readonly key: string;
    readonly terms: ReadonlyMap<string, { readonly byte_offset: number; readonly excerpt_start: number }>;
    readonly typed: boolean;
}

/** Lazy per-process scan cache. Values contain terms and numeric anchors, never source text. */
export class LexicalScanBackend implements SearchBackend {
    private readonly cache = new Map<string, CachedFile>();

    async search(snapshot: SearchSnapshot, query: string, reads: SearchReads) {
        const live = new Set(snapshot.files.map(file => file.rel));
        for (const path of this.cache.keys()) if (!live.has(path)) this.cache.delete(path);
        const queryWords = words(query);
        const candidates: SearchCandidate[] = [];
        let typedFiles = 0;
        let searchedFiles = 0;
        for (const file of snapshot.files) {
            if (!markdownFile(file.rel) || !maySearch(file)) continue;
            const key = changeKey(file);
            let cached: CachedFile | null | undefined = this.cache.get(file.rel);
            if (!cached || cached.key !== key) {
                cached = await this.scan(file, reads);
                if (cached) this.cache.set(file.rel, cached);
                else { this.cache.delete(file.rel); continue; }
            }
            if (cached.typed) typedFiles++;
            searchedFiles++;
            if (queryWords.length === 0 || !queryWords.every(word => cached!.terms.has(word))) continue;
            const anchor = cached.terms.get(queryWords[0]!)!;
            candidates.push({ path: file.rel, byte_offset: anchor.byte_offset,
                excerpt_start: anchor.excerpt_start, version: { kind: 'stat', value: key } });
        }
        candidates.sort((a, b) => a.path.localeCompare(b.path) || a.byte_offset - b.byte_offset);
        return { candidates, hasMore: false, typed_files: typedFiles,
            searched_files: searchedFiles };
    }

    private async scan(file: FileMetadata, reads: SearchReads): Promise<CachedFile | null> {
        const terms = new Map<string, { byte_offset: number; excerpt_start: number }>();
        // Keep 100 preceding codepoint offsets plus the longest recorded token.
        // Absolute indices avoid copying context at every token start.
        const recent = new Float64Array(356);
        let recentNext = 0;
        let position = 0;
        let token = '';
        let tokenStart = 0;
        let leadingEnd = 0;
        let leadingCount = 0;
        let tokenCodepoints = 0;
        let overflow = false;
        let prefix = '';
        const finishToken = () => {
            if (token && !overflow) {
                const normalized = token.normalize('NFKC').toLowerCase();
                const context = Math.min(leadingCount, Math.max(0, 200 - tokenCodepoints));
                const excerptStart = context ? recent[(leadingEnd - context) % recent.length]! : tokenStart;
                if (!terms.has(normalized)) terms.set(normalized, { byte_offset: tokenStart, excerpt_start: excerptStart });
            }
            token = '';
            tokenCodepoints = 0;
            overflow = false;
        };
        while (position < file.size) {
            const slice = await reads.read(file.rel, position, SCAN_BYTES);
            if (!slice || slice.size !== file.size || slice.nextOffset <= position) return null;
            const bytes = slice.bytes;
            let ascii = true;
            for (let i = 0; i < bytes.length; i++) if (bytes[i]! >= 128) { ascii = false; break; }
            let chunk = '';
            if (!ascii) {
                try { chunk = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
                catch { return null; }
            }
            if (position === 0) prefix = ascii ? Buffer.from(bytes.subarray(0, 4096)).toString('ascii') : chunk.slice(0, 4096);
            let offset = position;
            for (let i = 0; i < bytes.length;) {
                const code = bytes[i]!;
                const width = code < 128 ? 1 : code < 224 ? 2 : code < 240 ? 3 : 4;
                const scalar = width === 2 ? ((code & 31) << 6) | (bytes[i + 1]! & 63) :
                    width === 3 ? ((code & 15) << 12) | ((bytes[i + 1]! & 63) << 6) | (bytes[i + 2]! & 63) :
                    width === 4 ? ((code & 7) << 18) | ((bytes[i + 1]! & 63) << 12) | ((bytes[i + 2]! & 63) << 6) | (bytes[i + 3]! & 63) : code;
                const codepoint = String.fromCodePoint(scalar);
                const asciiToken = code >= 65 && code <= 90 || code >= 97 && code <= 122 ||
                    code >= 48 && code <= 57 || code === 95;
                if (code < 128 ? asciiToken : tokenCharacter.test(codepoint)) {
                    if (token === '' && !overflow) {
                        tokenStart = offset;
                        leadingEnd = recentNext;
                        leadingCount = Math.min(100, recentNext);
                    }
                    tokenCodepoints++;
                    if (token.length < 256) token += codepoint;
                    else overflow = true;
                } else finishToken();
                recent[recentNext % recent.length] = offset;
                recentNext++;
                offset += width;
                i += width;
            }
            position = slice.nextOffset;
        }
        finishToken();
        const after = await reads.metadata(file.rel);
        if (!after || changeKey(after) !== changeKey(file) || !maySearch(after)) return null;
        const frontmatter = prefix.startsWith('---\n') || prefix.startsWith('---\r\n');
        const closing = frontmatter ? prefix.indexOf('\n---', 4) : -1;
        const typed = closing > 0 && /^type\s*:/m.test(prefix.slice(4, closing));
        return { key: changeKey(file), terms, typed };
    }
}

export interface SearchHit {
    readonly path: string;
    readonly size: number;
    readonly layer: 'Arc' | 'Mage' | 'Forum' | 'unclassified' | 'none';
    readonly canonicity: 'immutable source' | 'agent-curated' | 'non-canonical' | 'pre-canon draft' | 'unknown';
    readonly excerpt: string;
    readonly byte_offset: number;
}

export interface SearchResult {
    readonly hits: readonly SearchHit[];
    readonly truncated: boolean;
    readonly placeholder_detection: 'available' | 'unavailable';
    readonly placeholder_count: number | null;
    readonly placeholder_fraction: number | null;
    readonly excluded_from_search: number | null;
    readonly files_in_scope: number | null;
    readonly searchable_files: number | null;
    readonly revalidation_dropped_count: number;
    readonly inaccessible_count: number;
    readonly mage_detection: 'arc_sibling' | 'frontmatter' | 'none';
    readonly state: 'zero_files_in_scope' | 'zero_searchable_files' | 'no_matches' | 'matches' |
        'scope_unavailable' | 'search_coverage_unavailable';
}

function classify(path: string, mage: boolean): Pick<SearchHit, 'layer' | 'canonicity'> {
    if (!mage) return { layer: 'none', canonicity: 'unknown' };
    const [layer, sublayer] = path.split('/');
    if (layer === 'Arc') return { layer, canonicity: 'immutable source' };
    if (layer === 'Mage') return { layer, canonicity: 'agent-curated' };
    if (layer === 'Forum') return { layer, canonicity: sublayer === 'Antechamber' ? 'pre-canon draft' : 'non-canonical' };
    return { layer: 'unclassified', canonicity: 'unknown' };
}

/** Internal slice-2 entry point; construction keeps the cache for later queries. */
export function createSearchEngine(fsgate: Pick<FsGate, 'walkGrant' | 'readFileInGrant' | 'fileMetadataInGrant' | 'probeInGrant'>,
    backend: SearchBackend = new LexicalScanBackend()): (query: string) => Promise<SearchResult> {
    return async query => {
        const walk = await fsgate.walkGrant();
        if (isRefusal(walk)) throw new Error(`grant walk refused: ${walk.reason}`);
        const privateFiles = walk.files.map(file => ({ ...file }));
        const snapshot: SearchSnapshot = { files: privateFiles.filter(file => markdownFile(file.rel) && maySearch(file)) };
        const allowed = new Set(snapshot.files.map(file => file.rel));
        const reads: SearchReads = {
            async read(path, offset, bytes) {
                if (!allowed.has(path) || !Number.isSafeInteger(offset) || offset < 0 ||
                    !Number.isSafeInteger(bytes) || bytes < 1 || bytes > SCAN_BYTES) return null;
                const result = await fsgate.readFileInGrant(path, offset, bytes);
                return isRefusal(result) ? null : result;
            },
            async metadata(path) {
                if (!allowed.has(path)) return null;
                const result = await fsgate.fileMetadataInGrant(path);
                return isRefusal(result) ? null : result;
            }
        };
        const backendSnapshot = Object.freeze({ files: Object.freeze(snapshot.files.map(file => Object.freeze({ ...file }))) });
        const backendReads = Object.freeze({
            read: (path: string, offset: number, bytes: number) => reads.read(path, offset, bytes),
            metadata: async (path: string) => {
                const file = await reads.metadata(path);
                return file === null ? null : Object.freeze({ ...file });
            }
        });
        const answer = await backend.search(backendSnapshot, query, backendReads);
        const response = { ...answer, candidates: answer.candidates.map(candidate => ({
            ...candidate, version: candidate.version && { ...candidate.version }
        })) };
        const arc = await fsgate.probeInGrant('Arc');
        const mage = await fsgate.probeInGrant('Mage');
        const arcSibling = !isRefusal(arc) && arc.kind === 'directory' && !isRefusal(mage) && mage.kind === 'directory';
        const mageDetection = arcSibling ? 'arc_sibling' : snapshot.files.length > 0 && response.typed_files / snapshot.files.length >= 0.3 ? 'frontmatter' : 'none';
        const filesByPath = new Map(privateFiles.map(file => [file.rel, file]));
        const validAnchors = (candidate: SearchCandidate, size: number): boolean =>
            Number.isSafeInteger(candidate.byte_offset) && Number.isSafeInteger(candidate.excerpt_start) &&
            0 <= candidate.excerpt_start && candidate.excerpt_start <= candidate.byte_offset &&
            0 <= candidate.byte_offset && candidate.byte_offset < size;
        // Each file keeps at most 16 distinct 1024-byte windows from its one hashing pass.
        const captured = new Map<string, Map<number, { bytes: Buffer; filled: number }>>();
        for (const candidate of response.candidates) {
            const file = filesByPath.get(candidate.path);
            if (!file || !allowed.has(candidate.path) || candidate.version?.kind !== 'sha256' ||
                !validAnchors(candidate, file.size)) continue;
            let windows = captured.get(candidate.path);
            if (!windows) { windows = new Map(); captured.set(candidate.path, windows); }
            if (!windows.has(candidate.excerpt_start) && windows.size < HASH_WINDOW_LIMIT)
                windows.set(candidate.excerpt_start, {
                    bytes: Buffer.alloc(Math.min(EXCERPT_BYTES, file.size - candidate.excerpt_start)), filled: 0
                });
        }
        const digests = new Map<string, string | null>();
        const hashFile = async (file: FileMetadata): Promise<string | null> => {
            const hash = createHash('sha256');
            let position = 0;
            while (position < file.size) {
                const window = await reads.read(file.rel, position, SCAN_BYTES);
                if (!window || window.size !== file.size || window.nextOffset <= position) return null;
                hash.update(window.bytes);
                for (const [start, excerpt] of captured.get(file.rel) ?? []) {
                    const from = Math.max(start, position);
                    const end = Math.min(start + excerpt.bytes.length, position + window.bytes.length);
                    if (end > from) {
                        excerpt.bytes.set(window.bytes.subarray(from - position, end - position), from - start);
                        excerpt.filled += end - from;
                    }
                }
                position = window.nextOffset;
            }
            const afterHash = await reads.metadata(file.rel);
            if (!afterHash || changeKey(afterHash) !== changeKey(file) || !maySearch(afterHash)) return null;
            return hash.digest('hex');
        };
        const hits: SearchHit[] = [];
        let truncated = response.hasMore;
        // Count only candidates examined before the result cap stops revalidation.
        let revalidationDropped = 0;
        for (const candidate of response.candidates) {
            if (hits.length === HIT_LIMIT && truncated) break;
            const file = filesByPath.get(candidate.path);
            const version = candidate.version;
            if (!version || (version.kind !== 'stat' && version.kind !== 'sha256') ||
                typeof version.value !== 'string') { revalidationDropped++; continue; }
            if (version.kind === 'sha256' && !/^[a-f0-9]{64}(?![\s\S])/.test(version.value)) { revalidationDropped++; continue; }
            if (!file) { revalidationDropped++; continue; }
            if (!validAnchors(candidate, file.size)) { revalidationDropped++; continue; }
            if (candidate.source_range_end !== undefined) {
                if (!Number.isSafeInteger(candidate.source_range_end)) { revalidationDropped++; continue; }
                if (!(candidate.byte_offset < candidate.source_range_end)) { revalidationDropped++; continue; }
                if (!(candidate.source_range_end <= file.size)) { revalidationDropped++; continue; }
            }
            const expectedKey = version.kind === 'stat' ? version.value : changeKey(file);
            if (changeKey(file) !== expectedKey) { revalidationDropped++; continue; }
            const before = await reads.metadata(candidate.path);
            if (!before || changeKey(before) !== expectedKey || !maySearch(before)) { revalidationDropped++; continue; }
            if (version.kind === 'sha256') {
                if (!digests.has(candidate.path)) digests.set(candidate.path, await hashFile(file));
                if (digests.get(candidate.path) !== version.value) { revalidationDropped++; continue; }
            }
            // Stat candidates retain their metadata-only truncation order.
            if (version.kind === 'stat' && hits.length === HIT_LIMIT) { truncated = true; break; }
            let excerptBytes: Uint8Array;
            if (version.kind === 'sha256') {
                const window = captured.get(candidate.path)?.get(candidate.excerpt_start);
                if (!window || window.filled !== window.bytes.length) { revalidationDropped++; continue; }
                let kept = window.bytes.length;
                if (candidate.excerpt_start + kept < file.size) {
                    // Trim an incomplete trailing codepoint, as a fenced slice does.
                    for (let back = 1; back <= 4 && back <= kept; back++) {
                        const byte = window.bytes[kept - back]!;
                        if ((byte & 0xc0) === 0x80) continue;
                        const width = byte < 128 ? 1 : (byte & 0xe0) === 0xc0 ? 2 :
                            (byte & 0xf0) === 0xe0 ? 3 : (byte & 0xf8) === 0xf0 ? 4 : 1;
                        if (width > back) kept -= back;
                        break;
                    }
                }
                excerptBytes = window.bytes.subarray(0, kept);
            } else {
                const slice = await reads.read(candidate.path, candidate.excerpt_start, EXCERPT_BYTES);
                if (!slice || slice.size !== file.size) { revalidationDropped++; continue; }
                excerptBytes = slice.bytes;
            }
            const after = await reads.metadata(candidate.path);
            if (!after || changeKey(after) !== expectedKey || !maySearch(after)) { revalidationDropped++; continue; }
            let excerpt: string;
            try { excerpt = new TextDecoder('utf-8', { fatal: true }).decode(excerptBytes); }
            catch { revalidationDropped++; continue; }
            // A withheld hash candidate must have a captured, decodable excerpt first.
            if (version.kind === 'sha256' && hits.length === HIT_LIMIT) { truncated = true; break; }
            excerpt = [...excerpt].slice(0, 200).join('');
            hits.push({ path: candidate.path, size: file.size, ...classify(candidate.path, mageDetection !== 'none'),
                excerpt, byte_offset: candidate.byte_offset });
        }
        const filesInScope = walk.inaccessible_count === 0 ? walk.files.length : null;
        const searchable = walk.inaccessible_count === 0 ? response.searched_files : null;
        return { hits, truncated,
            placeholder_detection: walk.placeholder_detection,
            placeholder_count: walk.placeholder_count,
            placeholder_fraction: walk.placeholder_count === null || filesInScope === null ? null :
                filesInScope === 0 ? 0 : walk.placeholder_count / filesInScope,
            excluded_from_search: walk.placeholder_count === null ? null : walk.placeholder_count,
            files_in_scope: filesInScope, searchable_files: searchable,
            revalidation_dropped_count: revalidationDropped,
            inaccessible_count: walk.inaccessible_count, mage_detection: mageDetection,
            state: filesInScope === 0 ? 'zero_files_in_scope' : filesInScope === null ? 'scope_unavailable' :
                searchable === 0 ? 'zero_searchable_files' :
                hits.length === 0 ? (revalidationDropped > 0 || searchable === null ? 'search_coverage_unavailable' : 'no_matches') : 'matches' };
    };
}
