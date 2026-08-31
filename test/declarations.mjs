/**
 * THE SHIPPED DECLARATION SURFACE, NORMALISED.
 *
 * `tsconfig.json` sets `declaration: true` and `package.json`'s `files` ships all of `dist`, with
 * no `exports` map — so `dist/fsgate.d.ts` is a deep-importable, publicly consumable contract.
 * `E4-export-inventory` cannot see it: `E4` reads `Object.keys()` on the built JAVASCRIPT, and an
 * interface is erased at build. The runtime half was pinned, the declaration half never was, and
 * the pinned half passing read as the whole thing being pinned — *a check that validates one side
 * is half a check*.
 *
 * ⚠⚠ THE EXTRACTION IS DERIVED; THE EXPECTATION IS REVIEWED, AND COLLAPSING THE TWO IS THE WHOLE
 * FAILURE THIS FILE EXISTS TO AVOID. Deriving both the inventory AND its expected value from the
 * same `.d.ts` is tautological — it can only ever agree with itself, so drift silently becomes the
 * new expected result. The expectation lives in `test/fsgate.d.ts.baseline`, committed and
 * human-reviewed; a diff against it is a PROMPT TO REVIEW, which is the point.
 *
 * ⚠ AND IT IS SHAPES, NOT NAMES. Enumerating exported names pins nothing that matters here: a
 * missing type, an unintended one, or an unchanged-name-but-changed-SIGNATURE all enumerate
 * perfectly. Each declaration is emitted with its members, their optionality and every method
 * signature.
 */

/** Strips comments without being fooled by a string literal that contains a slash. */
function stripComments(source) {
    let out = '';
    let i = 0;
    let quote = null;
    while (i < source.length) {
        const c = source[i];
        const next = source[i + 1];
        if (quote !== null) {
            out += c;
            if (c === '\\') { out += next ?? ''; i += 2; continue; }
            if (c === quote) quote = null;
            i += 1;
            continue;
        }
        if (c === '"' || c === "'" || c === '`') { quote = c; out += c; i += 1; continue; }
        if (c === '/' && next === '*') {
            const end = source.indexOf('*/', i + 2);
            i = end === -1 ? source.length : end + 2;
            out += ' ';
            continue;
        }
        if (c === '/' && next === '/') {
            const end = source.indexOf('\n', i);
            i = end === -1 ? source.length : end;
            continue;
        }
        out += c;
        i += 1;
    }
    return out;
}

const collapse = text => text.replace(/\s+/g, ' ').trim();

/**
 * Splits the comment-stripped text into top-level statements. A statement ends at a `;` at depth 0,
 * or at the `}` that returns depth to 0 for a braced declaration.
 */
function topLevelStatements(source) {
    const statements = [];
    let depth = 0;
    let start = 0;
    let quote = null;
    for (let i = 0; i < source.length; i += 1) {
        const c = source[i];
        if (quote !== null) {
            if (c === '\\') { i += 1; continue; }
            if (c === quote) quote = null;
            continue;
        }
        if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
        if (c === '{' || c === '(' || c === '[') { depth += 1; continue; }
        if (c === '}' || c === ')' || c === ']') {
            depth -= 1;
            if (depth === 0 && c === '}') {
                statements.push(source.slice(start, i + 1));
                start = i + 1;
            }
            continue;
        }
        if (c === ';' && depth === 0) {
            statements.push(source.slice(start, i + 1));
            start = i + 1;
        }
    }
    const tail = source.slice(start).trim();
    if (tail.length > 0) statements.push(tail);
    return statements.map(s => s.trim()).filter(s => s.length > 0);
}

/** Splits a braced body into its members, on `;` and `,` at the body's own depth. */
function members(body) {
    const parts = [];
    let depth = 0;
    let start = 0;
    let quote = null;
    for (let i = 0; i < body.length; i += 1) {
        const c = body[i];
        if (quote !== null) {
            if (c === '\\') { i += 1; continue; }
            if (c === quote) quote = null;
            continue;
        }
        if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
        if (c === '{' || c === '(' || c === '[') { depth += 1; continue; }
        if (c === '}' || c === ')' || c === ']') { depth -= 1; continue; }
        if ((c === ';' || c === ',') && depth === 0) {
            parts.push(body.slice(start, i));
            start = i + 1;
        }
    }
    parts.push(body.slice(start));
    return parts.map(collapse).filter(p => p.length > 0);
}

/**
 * The normalised API of one `.d.ts` source, as a string. Deterministic, whitespace- and
 * comment-insensitive, and it preserves declaration and member ORDER — a reorder is a diff, which
 * is the correct outcome for a file whose job is to prompt a review.
 */
export function extractDeclarationApi(source) {
    const lines = [];
    for (const statement of topLevelStatements(stripComments(source))) {
        const open = statement.indexOf('{');
        // A statement whose first brace closes the whole body is a braced declaration; anything
        // else (an import, a type alias, a function declaration) is emitted as one collapsed line.
        if (open === -1 || !statement.trimEnd().endsWith('}')) {
            lines.push(collapse(statement));
            continue;
        }
        const header = collapse(statement.slice(0, open));
        const body = statement.slice(open + 1, statement.lastIndexOf('}'));
        lines.push(`${header} {`);
        for (const member of members(body)) lines.push(`    ${member};`);
        lines.push('}');
    }
    return `${lines.join('\n')}\n`;
}
