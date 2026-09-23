import assert from 'node:assert/strict';

function readTag(bytes, offset, limit) {
    if (offset >= limit) throw new Error('DER ended before a tag');
    const first = bytes[offset];
    let tagNumber = first & 0x1f;
    let cursor = offset + 1;
    if (tagNumber === 0x1f) {
        tagNumber = 0;
        let octets = 0;
        while (true) {
            if (cursor >= limit) throw new Error('DER ended inside a high-tag-number identifier');
            const octet = bytes[cursor];
            cursor += 1;
            octets += 1;
            if (octets > 6 || tagNumber > Math.floor(Number.MAX_SAFE_INTEGER / 128)) {
                throw new Error('DER tag number is too large');
            }
            tagNumber = (tagNumber * 128) + (octet & 0x7f);
            if ((octet & 0x80) === 0) break;
        }
    }
    return {
        tagClass: first >>> 6,
        constructed: (first & 0x20) !== 0,
        tagNumber,
        cursor
    };
}

function readLength(bytes, offset, limit) {
    if (offset >= limit) throw new Error('DER ended before a length');
    const first = bytes[offset];
    if (first < 0x80) return { length: first, cursor: offset + 1 };
    const octets = first & 0x7f;
    if (octets === 0) throw new Error('DER indefinite lengths are not permitted');
    if (octets > 6 || offset + 1 + octets > limit) throw new Error('DER length is truncated or too large');
    let length = 0;
    for (let index = 0; index < octets; index += 1) {
        length = (length * 256) + bytes[offset + 1 + index];
    }
    if (!Number.isSafeInteger(length)) throw new Error('DER length exceeds the safe integer range');
    return { length, cursor: offset + 1 + octets };
}

function parseOne(bytes, offset, limit) {
    const tag = readTag(bytes, offset, limit);
    const encodedLength = readLength(bytes, tag.cursor, limit);
    const contentStart = encodedLength.cursor;
    const end = contentStart + encodedLength.length;
    if (end > limit) throw new Error('DER content extends beyond its container');
    const children = [];
    if (tag.constructed) {
        let childOffset = contentStart;
        while (childOffset < end) {
            const parsed = parseOne(bytes, childOffset, end);
            children.push(parsed.node);
            childOffset = parsed.end;
        }
        if (childOffset !== end) throw new Error('DER child does not end at its container boundary');
    }
    return {
        node: Object.freeze({
            tagClass: tag.tagClass,
            tagNumber: tag.tagNumber,
            constructed: tag.constructed,
            content: bytes.subarray(contentStart, end),
            children: Object.freeze(children)
        }),
        end
    };
}

function isPrimitiveUniversalInteger(node) {
    return node.tagClass === 0 && node.tagNumber === 2 && !node.constructed;
}

function collectIntegers(node, integers) {
    if (isPrimitiveUniversalInteger(node)) integers.push(node);
    for (const child of node.children) collectIntegers(child, integers);
}

function assertMinimalInteger(node) {
    assert.ok(isPrimitiveUniversalInteger(node), 'the node must be a primitive universal INTEGER');
    const content = node.content;
    assert.notEqual(content.length, 0, 'a DER INTEGER must not have empty content');
    if (content.length > 1) {
        assert.ok(
            content[0] !== 0x00 || (content[1] & 0x80) !== 0,
            'a positive DER INTEGER has a redundant leading 00 octet'
        );
        assert.ok(
            content[0] !== 0xff || (content[1] & 0x80) === 0,
            'a negative DER INTEGER has a redundant leading ff octet'
        );
    }
}

/** Parse exactly one DER value and assert every visible INTEGER uses its shortest encoding. */
export function assertMinimalDerIntegers(input) {
    const bytes = Buffer.from(input);
    const parsed = parseOne(bytes, 0, bytes.length);
    if (parsed.end !== bytes.length) throw new Error('DER has trailing data after its root value');
    const integers = [];
    collectIntegers(parsed.node, integers);
    for (const integer of integers) assertMinimalInteger(integer);
    return Object.freeze({ root: parsed.node, integers: Object.freeze(integers) });
}

/** Locate Certificate.tbsCertificate.serialNumber without using a certificate-library oracle. */
export function certificateSerialNumber(root) {
    assert.ok(
        root.tagClass === 0 && root.tagNumber === 16 && root.constructed,
        'Certificate must be a constructed universal SEQUENCE'
    );
    const tbsCertificate = root.children[0];
    assert.ok(
        tbsCertificate?.tagClass === 0
            && tbsCertificate.tagNumber === 16
            && tbsCertificate.constructed,
        'Certificate.tbsCertificate must be a constructed universal SEQUENCE'
    );
    const first = tbsCertificate.children[0];
    const serialIndex = first?.tagClass === 2 && first.tagNumber === 0 ? 1 : 0;
    const serial = tbsCertificate.children[serialIndex];
    assert.ok(isPrimitiveUniversalInteger(serial), 'tbsCertificate.serialNumber must be an INTEGER');
    return serial;
}

// Load-bearing oracle check: a walker that silently finds no INTEGER cannot pass the first case.
assert.throws(
    () => assertMinimalDerIntegers(Buffer.from('02020001', 'hex')),
    /redundant leading 00/u
);
assert.doesNotThrow(() => assertMinimalDerIntegers(Buffer.from('02020080', 'hex')));
