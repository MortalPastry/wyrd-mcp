import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import nodePath from 'node:path';
import { isRefusal } from 'wyrd-fence';
import type { FenceRefusal, FsGate, OverwriteRefusal, Overwritten } from 'wyrd-fence';

import { loadConfig } from './config.js';
import { project, stampOverwrite } from './frontmatter.js';
import { checkLineSize, checkPagePath, checkRequestCounts, contentHash, hashText, identity,
    lineageSpan, LINEAGE_SCHEMA, serialiseRecord } from './lineage.js';
import type { LineageSource, OverwriteRecord } from './lineage.js';
import type { LedgerAppender } from './ledger.js';
import { scribeRefuse } from './refusal.js';
import type { ScribeRefusal } from './refusal.js';
import { readSource, SourceCache, toLedgerPath } from './source.js';
import { resolveSpan, spanShapeFault } from './span.js';
import type { SpanMembers, SpanRefusal, SpanRequest } from './span.js';
import type { DerivedFrom } from './stamp.js';

export interface OverwritePageRequest {
    readonly path: string;
    readonly content: string;
    readonly derivedFrom: readonly DerivedFrom[];
    readonly expectedSha256: string;
}

export interface OverwritePageOptions {
    readonly gate: FsGate;
    readonly appender: LedgerAppender;
    readonly version: string;
    readonly now?: () => Date;
    readonly newUuid?: () => string;
    readonly newEventId?: () => string;
    readonly cache?: SourceCache;
}

export interface OverwriteSuccess {
    readonly ok: true;
    readonly overwritten: Overwritten;
    readonly record: OverwriteRecord;
    readonly appended: number;
    readonly config_created: boolean;
}

export interface OverwriteLedgerFailed extends ScribeRefusal {
    readonly reason: 'OVERWRITE_LEDGER_FAILED';
    readonly overwritten: Overwritten;
    readonly cause: FenceRefusal | ScribeRefusal;
    readonly config_created: boolean;
}

export type OverwritePageResult = OverwriteSuccess | OverwriteLedgerFailed | OverwriteRefusal
    | FenceRefusal | ScribeRefusal | SpanRefusal | (ScribeRefusal & { readonly config_created: boolean });

const keys = (value: unknown, names: readonly string[]): boolean =>
    typeof value === 'object' && value !== null && !Array.isArray(value)
    && Reflect.ownKeys(value).length === names.length
    && names.every(name => Object.prototype.hasOwnProperty.call(value, name));

function firstComponent(request: string): string {
    const segments: string[] = [];
    for (const part of request.split('\\').join('/').replace(/^\/+/, '').split('/')) {
        if (part === '' || part === '.') continue;
        if (part === '..') { segments.pop(); continue; }
        segments.push(part);
    }
    const first = segments[0] ?? '';
    return process.platform === 'win32' ? first.replace(/[. ]+$/g, '') : first;
}

/** Resolve only after the fence has accepted the request. Its probe does not disclose
 * the resolved name, so inspect names only; no page bytes are opened here. */
async function protectedResolvedPath(gate: FsGate, request: string): Promise<FenceRefusal | 'arc' | 'internal' | null> {
    const root = gate.disclosedRoot();
    const classify = (canonical: string): 'arc' | 'internal' | null => {
        const first = firstComponent(nodePath.relative(root, canonical));
        if (/^arc$/i.test(first)) return 'arc';
        if (/^\.wyrd$/i.test(first)) return 'internal';
        return null;
    };
    const parentRequest = nodePath.dirname(request);
    if (parentRequest !== '.') {
        const parent = await gate.probeInGrant(parentRequest);
        if (isRefusal(parent)) return parent;
        try {
            const protectedParent = classify(fs.realpathSync.native(nodePath.resolve(root, parentRequest)));
            if (protectedParent) return protectedParent;
        } catch { /* Unresolvable now: hashing does NOT re-check the parent; only overwriteFileInGrant refuses an aliased parent (see the residual note at overwritePage). */ }
    }
    const probed = await gate.probeInGrant(request);
    if (isRefusal(probed)) return probed;
    try {
        const protectedLeaf = classify(fs.realpathSync.native(nodePath.resolve(root, request)));
        if (protectedLeaf) return protectedLeaf;
    } catch { /* Unresolvable now: hashing does NOT re-check it; overwriteFileInGrant's real-path comparison is the check that refuses. */ }
    return null;
}

function ownRefusal(refusal: ScribeRefusal, created: boolean): ScribeRefusal & { config_created: boolean } {
    return Object.freeze({ ...refusal, config_created: created });
}

function snapshotSpan(members: SpanMembers): SpanRequest {
    if (members.hasOffset && members.hasQuote) return Object.freeze({
        offset: members.offsetValue as number, length: members.lengthValue as number,
        quote: members.quoteValue as string
    });
    if (members.hasOffset) return Object.freeze({
        offset: members.offsetValue as number, length: members.lengthValue as number
    });
    return Object.freeze({ quote: members.quoteValue as string });
}

function ledgerFailure(overwritten: Overwritten, cause: FenceRefusal | ScribeRefusal,
    created: boolean): OverwriteLedgerFailed {
    return Object.freeze({
        ok: false as const, reason: 'OVERWRITE_LEDGER_FAILED' as const,
        detail: 'the page was replaced, but no lineage append was confirmed',
        overwritten, cause, config_created: created
    });
}

export async function overwritePage(request: OverwritePageRequest,
    options: OverwritePageOptions): Promise<OverwritePageResult> {
    if (!keys(request, ['path', 'content', 'derivedFrom', 'expectedSha256'])) {
        return scribeRefuse('BAD_INPUT', 'the request carries an unknown or missing key');
    }
    const { path, content, derivedFrom, expectedSha256 } = request;
    if (typeof path !== 'string' || path.length === 0 || typeof content !== 'string'
        || typeof expectedSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(expectedSha256)) {
        return scribeRefuse('BAD_INPUT', 'path, content or expectedSha256 has an invalid shape');
    }
    if (/^arc$/i.test(firstComponent(path))) {
        return scribeRefuse('ARC_IMMUTABLE', 'Arc/ is the provenance layer; this server refuses writes addressed into it');
    }
    if (/^\.wyrd$/i.test(firstComponent(path))) {
        return scribeRefuse('OVERWRITE_INTERNAL_PATH', 'overwrite_page refuses the .wyrd/ subtree');
    }
    if (!Array.isArray(derivedFrom)) return scribeRefuse('DERIVED_FROM_INVALID', 'derivedFrom must be an array');
    const entries: DerivedFrom[] = [];
    let spanCount = 0;
    for (const item of [...derivedFrom]) {
        if (!keys(item, ['source', 'spans'])) {
            return scribeRefuse('DERIVED_FROM_INVALID', 'a derived_from entry has an invalid shape');
        }
        const source = item.source;
        const rawSpans = item.spans;
        if (typeof source !== 'string' || source.length === 0
            || !Array.isArray(rawSpans) || rawSpans.length === 0) {
            return scribeRefuse('DERIVED_FROM_INVALID', 'a derived_from entry has an invalid shape');
        }
        const spans: SpanRequest[] = [];
        for (const requested of [...rawSpans]) {
            const checked = spanShapeFault(requested);
            if ('ok' in checked && checked.ok === false) return checked;
            spans.push(snapshotSpan(checked as SpanMembers));
            spanCount += 1;
        }
        entries.push(Object.freeze({ source, spans: Object.freeze(spans) }));
    }
    const countFault = checkRequestCounts(entries.length, spanCount);
    if (countFault) return countFault;
    const pathFault = checkPagePath(toLedgerPath(path));
    if (pathFault) return pathFault;

    const protectedPath = await protectedResolvedPath(options.gate, path);
    if (protectedPath === 'arc') {
        return scribeRefuse('ARC_IMMUTABLE', 'Arc/ is the provenance layer; this server refuses writes addressed into it');
    }
    if (protectedPath === 'internal') {
        return scribeRefuse('OVERWRITE_INTERNAL_PATH', 'overwrite_page refuses the .wyrd/ subtree');
    }
    if (protectedPath !== null) return protectedPath;

    // RESIDUAL: the screen above is a sample. A concurrent local writer that swaps a parent into
    // Arc/ or .wyrd/ after it can make the hash below read the protected target and loadConfig
    // mint .wyrd/scribe.json at its fixed path before overwriteFileInGrant refuses PARENT_ALIAS.
    // No request-derived byte lands in either; the fence README's rename race is the same writer
    // doing strictly more. Review gate wyrd-scribe-tier-b round 3.
    // These preconditions are knowable without minting the vault's config.
    const previous = await options.gate.hashInGrant(path);
    if (isRefusal(previous)) return previous;
    if (previous.digest !== expectedSha256) {
        return Object.freeze({ ok: false as const, reason: 'DIGEST_MISMATCH' as const,
            detail: 'target does not match expectedSha256', resolvedPath: '',
            effect: { target: 'not_replaced' as const, stage: { state: 'none' as const } } });
    }
    const loaded = await loadConfig(options.gate, options.newUuid ?? randomUUID);
    if (!('config' in loaded)) {
        return 'resolvedPath' in loaded ? loaded : ownRefusal(loaded, false);
    }
    const config = loaded.config;
    const configCreated = loaded.created;

    const sources: LineageSource[] = [];
    const cache = options.cache ?? new SourceCache();
    for (const entry of entries) {
        const source = await readSource(options.gate, entry.source, cache);
        if (!('bytes' in source)) {
            return 'resolvedPath' in source ? source : ownRefusal(source, configCreated);
        }
        const spans = [];
        for (const span of entry.spans) {
            const resolved = resolveSpan(source.bytes, span);
            if (!resolved.ok) return Object.freeze({ ...resolved, config_created: configCreated });
            spans.push(lineageSpan(resolved));
        }
        sources.push(Object.freeze({
            identity: identity(config.vault_id, source.rel),
            content: contentHash(source.digest, source.size),
            spans: Object.freeze(spans)
        }));
    }
    const eventId = (options.newEventId ?? randomUUID)();
    const recordedAt = (options.now ?? (() => new Date()))().toISOString();
    const makeRecord = (pagePath: string, digest: string, bytes: number): OverwriteRecord => Object.freeze({
        schema: LINEAGE_SCHEMA, event: 'page_overwritten' as const, event_id: eventId,
        recorded_at: recordedAt,
        writer: Object.freeze({ server: 'wyrd-scribe' as const, version: options.version,
            tool: 'overwrite_page' as const }),
        vault: Object.freeze({ kind: 'uuid' as const, id: config.vault_id }),
        previous: Object.freeze({ identity: identity(config.vault_id, pagePath),
            content: contentHash(expectedSha256, previous.size) }),
        page: Object.freeze({ identity: identity(config.vault_id, pagePath),
            content: contentHash(digest, bytes) }),
        sources: Object.freeze(sources)
    });
    const draft = makeRecord(toLedgerPath(path), '0'.repeat(64), Number.MAX_SAFE_INTEGER);
    const draftFault = checkLineSize(serialiseRecord(draft));
    if (draftFault) return ownRefusal(draftFault, configCreated);
    let pageText = content;
    if (config.write_frontmatter) {
        const stamped = stampOverwrite(content, project(draft));
        if (typeof stamped !== 'string') return ownRefusal(stamped, configCreated);
        pageText = stamped;
    }
    const pageBytes = Buffer.from(pageText, 'utf8');
    const overwritten = await options.gate.overwriteFileInGrant(path, expectedSha256, pageBytes);
    if (isRefusal(overwritten)) return overwritten;
    const record = makeRecord(toLedgerPath(overwritten.rel), hashText(pageBytes), pageBytes.length);
    const line = serialiseRecord(record);
    const finalFault = checkLineSize(line);
    if (finalFault) return ledgerFailure(overwritten, finalFault, configCreated);
    const appended = await options.appender.appendLine(line);
    if (isRefusal(appended)) return ledgerFailure(overwritten, appended, configCreated);
    return Object.freeze({ ok: true as const, overwritten, record,
        appended: appended.bytes, config_created: configCreated });
}
