/**
 * A BOUNDED JSON Schema draft-07 validator, written rather than installed.
 *
 * ⚠⚠ THE DEPENDENCY WAS THE FORK, AND IT WAS DECIDED RATHER THAN AVOIDED. `ajv` is the obvious
 * answer and it is a real one: it is correct, it is maintained, and it would arrive as a
 * `devDependency`, which never reaches a consumer's `node_modules` because npm installs only
 * `dependencies` for a published package. So the cost is NOT a shipped edge.
 *
 * What it is instead: this package's manifest carries exactly two runtime edges and a comment
 * explaining why one of them is pinned exact rather than `workspace:*`; `scripts/release.mjs`
 * audits every file in the tree against a hand-maintained ship list three separate ways; the fence
 * was split out so its type surface could be versioned and reviewed. A project that has paid that
 * much attention to what it depends on does not add a transitive tree — ajv brings its own — to
 * validate ONE file against ONE vendored schema whose keyword set is closed and enumerated below.
 * The trade would be worth it for a validator run over arbitrary user input; it is not worth it
 * for a 1.7 KB manifest checked once per suite run.
 *
 * ⚠ THE COST OF THE HAND-ROLL IS THE OBVIOUS ONE AND IT IS PAID EXPLICITLY. A partial validator
 * that meets a keyword it does not implement and IGNORES it reports "valid" for a document nothing
 * checked — the exact silent-green class this suite exists to refuse. So `ASSERTION_KEYWORDS` and
 * `ANNOTATION_KEYWORDS` below are exhaustive over draft-07's vocabulary as this schema uses it, and
 * `unsupportedKeywords()` walks the SCHEMA and refuses on any keyword in neither set. A future
 * schema revision that introduces `oneOf`, `if`/`then`, `dependencies` or `patternProperties`
 * therefore fails loudly at the arm rather than passing quietly through a gap.
 *
 * ⚠ `format` IS DELIBERATELY NOT ASSERTED, which is draft-07's own default — `format` is an
 * annotation unless a validator opts in. The two uses here are `uri`, and asserting a URI grammar
 * by hand is the one thing in this file that would be worth a dependency. What guards those fields
 * instead is `type: string` plus the cross-reference arm's exact-equality checks against
 * `package.json`, which is a stronger constraint than "parses as a URI".
 */

/** Keywords that constrain an instance. Anything here is implemented in `validate()` below. */
const ASSERTION_KEYWORDS = new Set([
    '$ref', 'type', 'required', 'properties', 'additionalProperties', 'items',
    'enum', 'const', 'not', 'anyOf', 'allOf', 'pattern', 'minLength', 'maxLength'
]);

/**
 * Keywords that carry no constraint. `format` is here on purpose — see the header. `definitions`
 * is a container the walker descends into rather than a constraint on the instance.
 */
const ANNOTATION_KEYWORDS = new Set([
    '$schema', '$id', '$comment', 'definitions',
    'title', 'description', 'default', 'example', 'examples', 'format'
]);

/**
 * Every keyword appearing anywhere in `schema` that this validator neither asserts nor knowingly
 * ignores. A non-empty result means the validator's coverage no longer spans the schema, and the
 * caller must refuse — a validator narrower than its schema reports on a subset while claiming the
 * whole.
 *
 * ⚠ It descends through subschema POSITIONS, never blindly, so a property or definition literally
 * named `type` or `enum` is not mistaken for the keyword.
 */
export function unsupportedKeywords(schema) {
    const found = new Set();
    const seen = new Set();

    const walk = node => {
        if (node === null || typeof node !== 'object' || Array.isArray(node)) return;
        if (seen.has(node)) return;
        seen.add(node);

        for (const [key, value] of Object.entries(node)) {
            if (!ASSERTION_KEYWORDS.has(key) && !ANNOTATION_KEYWORDS.has(key)) found.add(key);

            /**
             * ⚠ TUPLE-FORM `items` IS A DIFFERENT KEYWORD WEARING THE SAME NAME. draft-07 lets
             * `items` be an ARRAY of subschemas, one per position. `validate()` below implements only
             * the single-schema form, and until 2026-09-02 an array here was walked as nothing (the
             * walker returns early on arrays) and then passed to `validate()` as if it were a schema
             * — which has no keywords, so every element validated against NOTHING and reported
             * clean. That is the silent-green class this file exists to refuse, arriving through the
             * coverage guard that was meant to refuse it. Reported under its own name so the arm's
             * message says which form is unsupported.
             */
            if (key === 'items' && Array.isArray(value)) {
                found.add('items (tuple form)');
                continue;
            }

            // Positions whose VALUE is a map of name -> subschema.
            if (key === 'properties' || key === 'definitions' || key === 'variables') {
                for (const sub of Object.values(value ?? {})) walk(sub);
            // Positions whose value is a single subschema (or, for additionalProperties, a boolean).
            } else if (key === 'items' || key === 'not' || key === 'additionalProperties') {
                walk(value);
            // Positions whose value is an array of subschemas.
            } else if (key === 'anyOf' || key === 'allOf' || key === 'oneOf') {
                for (const sub of value ?? []) walk(sub);
            }
        }
    };

    walk(schema);
    return [...found].sort();
}

/** Resolve a local `#/a/b` pointer against the root schema. Remote refs are refused, not fetched. */
function resolveRef(root, ref) {
    if (!ref.startsWith('#/')) throw new Error(`only local $ref is supported, got "${ref}"`);
    let node = root;
    for (const raw of ref.slice(2).split('/')) {
        const token = raw.replace(/~1/g, '/').replace(/~0/g, '~');
        node = node?.[token];
        if (node === undefined) throw new Error(`$ref "${ref}" resolves to nothing`);
    }
    return node;
}

function typeOf(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    if (Number.isInteger(value)) return 'integer';
    return typeof value;
}

function matchesType(value, expected) {
    const actual = typeOf(value);
    if (expected === 'number') return actual === 'number' || actual === 'integer';
    if (expected === 'integer') return actual === 'integer';
    return actual === expected;
}

/**
 * Validate `instance` against `schema`, resolving `$ref` against `root`.
 *
 * Returns an array of `{ path, message }`. An empty array is the only "valid" — there is no boolean
 * return, because a boolean invites `if (valid)` and loses the reason a manifest was rejected,
 * which is the whole value of running this before the registry does.
 */
export function validate(instance, schema, { root = schema, path = '' } = {}) {
    const errors = [];
    const at = suffix => `${path}${suffix}`;
    const fail = message => errors.push({ path: path || '(root)', message });

    if (schema === true || schema === undefined) return errors;
    if (schema === false) {
        fail('schema is `false` — nothing is valid here');
        return errors;
    }

    if (typeof schema.$ref === 'string') {
        errors.push(...validate(instance, resolveRef(root, schema.$ref), { root, path }));
        // draft-07: a sibling of `$ref` is ignored. This schema has none, but honouring the rule
        // keeps the validator's behaviour the one the `$schema` line names.
        return errors;
    }

    if (schema.type !== undefined) {
        const types = Array.isArray(schema.type) ? schema.type : [schema.type];
        if (!types.some(t => matchesType(instance, t))) {
            fail(`expected type ${types.join(' or ')}, got ${typeOf(instance)}`);
            // Every keyword below reads the instance as a specific type; continuing past a type
            // mismatch produces a cascade of errors describing one defect.
            return errors;
        }
    }

    if (schema.enum !== undefined) {
        const json = JSON.stringify(instance);
        if (!schema.enum.some(candidate => JSON.stringify(candidate) === json)) {
            fail(`value ${json} is not one of ${JSON.stringify(schema.enum)}`);
        }
    }

    /**
     * ⚠ `const` REQUIRES A MATCH. It reads as a prohibition here only because its one use in this
     * schema is inside a `not` — `{"not": {"const": "latest"}}`, the rejection of a floating package
     * version — and writing the negation into `const` itself passes that ONE case while inverting
     * every direct use. It was written that way first and `MF1` caught it on the real manifest: a
     * `packages[0].version` of `"0.1.3"` was reported as matching a schema it must not.
     */
    if (schema.const !== undefined && JSON.stringify(instance) !== JSON.stringify(schema.const)) {
        fail(`value ${JSON.stringify(instance)} is not the required constant ${JSON.stringify(schema.const)}`);
    }

    if (schema.not !== undefined) {
        // `not: { const: "latest" }` is how the schema forbids a floating package version.
        if (validate(instance, schema.not, { root, path }).length === 0) {
            fail(`value ${JSON.stringify(instance)} matches a schema it must not`);
        }
    }

    if (Array.isArray(schema.allOf)) {
        for (const sub of schema.allOf) errors.push(...validate(instance, sub, { root, path }));
    }

    if (Array.isArray(schema.anyOf)) {
        const branchErrors = schema.anyOf.map(sub => validate(instance, sub, { root, path }));
        if (branchErrors.every(branch => branch.length > 0)) {
            // ⚠ EVERY BRANCH'S REASON IS CARRIED, not just the first. An anyOf failure whose
            // message names one branch sends the reader to fix the wrong alternative.
            const detail = branchErrors
                .map((branch, i) => `  [${i}] ${branch.map(e => `${e.path}: ${e.message}`).join('; ')}`)
                .join('\n');
            fail(`matched none of the ${schema.anyOf.length} alternatives:\n${detail}`);
        }
    }

    if (typeof instance === 'string') {
        // draft-07 measures string length in CHARACTERS (code points), not UTF-16 units; an astral
        // character in a `description` counts once here and twice under `.length`.
        const length = Array.from(instance).length;
        if (typeof schema.minLength === 'number' && length < schema.minLength) {
            fail(`string length ${length} is below minLength ${schema.minLength}`);
        }
        if (typeof schema.maxLength === 'number' && length > schema.maxLength) {
            fail(`string length ${length} exceeds maxLength ${schema.maxLength}`);
        }
        if (typeof schema.pattern === 'string' && !new RegExp(schema.pattern, 'u').test(instance)) {
            fail(`string ${JSON.stringify(instance)} does not match pattern ${schema.pattern}`);
        }
    }

    if (instance !== null && typeof instance === 'object' && !Array.isArray(instance)) {
        for (const key of schema.required ?? []) {
            if (!Object.hasOwn(instance, key)) fail(`missing required property "${key}"`);
        }
        const properties = schema.properties ?? {};
        for (const [key, value] of Object.entries(instance)) {
            if (Object.hasOwn(properties, key)) {
                errors.push(...validate(value, properties[key], { root, path: at(`/${key}`) }));
            } else if (schema.additionalProperties === false) {
                errors.push({ path: at(`/${key}`), message: 'property is not allowed here' });
            } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
                errors.push(...validate(value, schema.additionalProperties, { root, path: at(`/${key}`) }));
            }
        }
    }

    if (Array.isArray(instance) && schema.items !== undefined) {
        // Belt to the walker's braces: a validator handed the tuple form must not quietly treat the
        // array as a schema. `unsupportedKeywords()` reports it first; this is what happens if a
        // caller skipped that check.
        if (Array.isArray(schema.items)) {
            throw new Error(`tuple-form \`items\` (an array of subschemas) at ${path || '(root)'} is not implemented — unsupportedKeywords() reports it as "items (tuple form)"`);
        }
        instance.forEach((element, i) => {
            errors.push(...validate(element, schema.items, { root, path: at(`/${i}`) }));
        });
    }

    return errors;
}
