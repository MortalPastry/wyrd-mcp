/**
 * THE DESIGN INVENTORY of the Scribe's test arms.
 *
 * ⚠ DECLARATIVE, AND DELIBERATELY SEPARATE FROM THE REGISTRATION PATH — the Reader's mechanism
 * (`packages/wyrd/test/arms.mjs`), copied rather than reinvented. A test that is deleted leaves its
 * row here and `scripts/run-tests.mjs` fails the run, because the union of executed ids no longer
 * equals this list. A test added without a row here fails it too.
 *
 * ⚠⚠ THIS IS WHAT MAKES "RAN NOTHING" A FAILING STATE FOREVER. `wyrd-scribe` had only a build
 * script until this slice, so a test file here would have read as covered while nothing executed
 * it. A runner that later enumerates zero files still exits 0 on its own; an inventory it must
 * equal does not.
 *
 * ⚠ HONEST LIMIT, inherited from the Reader's version: deleting a test AND its row still passes.
 * Nothing machine-checkable derives this list from `designs/2026-08-31-span-resolver-plan.md`. What
 * it buys is that the deletion is two edits in two files, one of which reads as an inventory.
 */

/** B1 span-resolver arms — `test/span.test.js`. */
export const SPAN_ARMS = {
    'B1-offsets-only': 'offsets recorded as given, the quote read from those bytes; past the end refuses',
    'B1-quote-unique': 'a quote occurring once locates and computes byte offsets',
    'B1-quote-ambiguous': 'a quote occurring twice REFUSES, paired with a unique quote in the same source',
    'B1-quote-overlapping': '"aaa"/"aa" — overlapping occurrences; kills a scan advancing by quote length',
    'B1-quote-absent': 'a quote occurring zero times is SPAN_NOT_FOUND',
    'B1-both-match': 'offsets plus a matching quote succeed',
    'B1-both-mismatch': 'offsets plus a non-matching quote refuse, preferring NEITHER side',
    'B1-range-fractional': 'a fractional offset and a fractional length each refuse',
    'B1-range-negative-offset': 'a negative offset refuses rather than being clamped',
    'B1-range-negative-length': 'a negative length refuses rather than being clamped',
    'B1-range-unsafe-integer': 'unsafe integers, NaN and Infinity refuse on both members',
    'B1-range-lone-offset': 'offset and length are required together, in both directions',
    'B1-range-zero-length': '{ offset: 1, length: 0 } refuses — distinct from a zero-length QUOTE',
    'B1-request-shape': 'a non-object, an empty object, an unknown key, an inherited key, a symbol key',
    'B1-source-not-buffer': 'a non-Buffer source THROWS — it is a caller contract, not a refusal',
    'B1-align-start': 'é as { offset: 1, length: 1 } — unaligned START, aligned end',
    'B1-align-end': 'é as { offset: 0, length: 1 } — aligned start, unaligned END',
    'B1-align-whole': 'é as { offset: 0, length: 2 } succeeds and the stored quote re-encodes exactly',
    'B1-source-lossy': 'an aligned span over a TRUNCATED sequence still refuses — alignment is not sufficient',
    'B1-quote-lone-surrogate': 'a lone-surrogate quote refuses BEFORE matching',
    'B1-quote-replacement': 'the pair — a source genuinely containing U+FFFD, which the surrogate must not match',
    'B1-quote-empty': 'an empty quote refuses, including against an empty source',
    'B1-quote-match-unaligned': 'a located match ending before a continuation byte refuses',
    'B1-multibyte-offsets': 'byte offsets, not character offsets, asserted numerically',
    'B1-exact-whitespace': 'a quote differing only by whitespace is NOT FOUND',
    'B1-exact-case': 'a quote differing only by case is NOT FOUND',
    'B1-exact-normalisation': 'a quote differing only by Unicode normalisation form is NOT FOUND',
    // Added at code-gate round 1 — both from findings, not from imagination.
    'B1-request-inherited': 'an inherited accessor is never invoked for a member not supplied',
    'B1-source-not-mutated': 'resolving never writes to the caller\'s buffer',
    // Added 2026-09-01. `Buffer.isBuffer` is an `instanceof` check, so the source contract ADMITS a
    // subclass; the arm pins that as the ruled behaviour rather than leaving it undecided, and
    // carries the purity claim across the same gap.
    'B1-source-subclass': 'a Buffer SUBCLASS is admitted, resolves identically, is left unmodified — and all THREE things a hostile one can still do'
};

/**
 * ⚠ WHY `B1-source-subclass` PINS ADMISSION RATHER THAN REFUSAL — the argument, in the inventory,
 * because this is the row a later session would otherwise "fix".
 *
 * `Buffer.isBuffer` is `instanceof`, so `class Evil extends Buffer` passes the source contract and
 * may then override `indexOf`, `subarray`, `toString` or `length` and steer the result. Tightening
 * the check — `Object.getPrototypeOf(bytes) === Buffer.prototype` — would refuse the subclass, and
 * it would buy nothing this module needs:
 *
 *   · THE SOURCE IS NOT THE ATTACKER-INFLUENCED INPUT. The REQUEST crosses the trust boundary; the
 *     bytes come from the fence's `readFileInGrant`, on the far side of it. Supplying a hostile
 *     subclass requires a hostile caller, and a hostile caller is already inside every property
 *     this module protects — it can simply supply different bytes.
 *   · IT DOES NOT CLOSE THE CLASS IT LOOKS LIKE IT CLOSES. A plain Buffer whose prototype has been
 *     poisoned passes any prototype-identity test, so the tightened check stops the polite half of
 *     the class and not the hostile half.
 *   · IT IS A BEHAVIOUR CHANGE TO A SECURITY-ADJACENT CONTRACT, and it would refuse the legitimate
 *     Buffer subclasses that ordinary Node code hands around.
 *
 * So the answer is a TEST, and the arm's job is to make the admission FALSIBLE: a future session
 * that tightens the check finds this arm red and has to rule on it deliberately.
 *
 * ⚠⚠ AND THE COST IS THREE MECHANISMS, NOT ONE — measured 2026-09-02, because the arm originally
 * pinned only the first and the other two are on paths it never reaches:
 *
 *   1. `indexOf` SUBSTITUTES on the quote-only path — mints a span for a quote absent from the
 *      source.
 *   2. `subarray` SUBSTITUTES on the offsets path — records a quote that is not the text at the
 *      range. ⚠ This is the OFFSETS-WITHOUT-QUOTE shape specifically: it is the only request shape
 *      with no cross-check, since the quote is read out of the slice rather than compared to
 *      anything. Supplying the quote catches it (`SPAN_MISMATCH`), and the arm pins both halves.
 *   3. `indexOf` SUPPRESSES rather than substitutes — answering the second scan call `-1` reports
 *      a genuinely ambiguous quote as unique, turning the module's governing refusal
 *      (`AMBIGUITY REFUSES; IT NEVER PICKS`) into a success whose returned values are all TRUE.
 *      A value-checking arm cannot see this one; only the plain-Buffer control beside it can.
 *
 * ⚠ The mechanisms are enumerated because "a hostile subclass can lie" is not a measurement, and a
 * later session weighing whether to tighten the contract needs the actual blast radius. It does
 * not change the ruling: all three still require a hostile caller on the near side of the trust
 * boundary, who can hand over different bytes anyway.
 */

/**
 * THE STAMP PATH's arms — `test/stamp.test.js`. `writePage` over a REAL temp directory granted
 * through `createFsGate`, never a fake gate.
 *
 * ⚠⚠ A FAKE GATE WOULD TEST THE WRONG THING, and this is the one design note that belongs in the
 * inventory rather than in the test file. D8's claim is that a `derived_from` source is fenced by
 * the IDENTICAL code path as the write target — so an arm that hands `writePage` a hand-written
 * stub proving "the Scribe calls something named readFileInGrant" proves nothing about the claim.
 * The grant is real, the escape targets are real files outside it, and the refusals come from the
 * fence itself. Only the PRIMITIVES are ever instrumented, at the fence's own injection seam, which
 * is the same discipline `packages/wyrd-fence/test/fixtures.mjs` uses.
 *
 * ⚠⚠ THE `ST-OWED-end-to-end` ROW IS GONE BECAUSE THE DEBT IS PAID, AND WHAT IT OWED IS WORTH
 * NAMING SO THE NEW ROWS ARE READ AS THE PAYMENT. It said: nothing here appends a real line to
 * `.wyrd/lineage.jsonl`, because the fence had no append primitive — only create-exclusive `wx` —
 * so three things were untested. (1) a line actually landing in the ledger file → `ST22`. (2) the
 * ledger accumulating across calls → `ST23`. (3) B4's atomicity claim, that concurrent writers do
 * not interleave → `ST25`. `ST24` was not owed and is the fourth: the failure direction over the
 * REAL appender rather than a refusing stub, which is where `PAGE_WRITTEN_LEDGER_FAILED` now
 * carries a genuine fence refusal instead of a hand-written one.
 *
 * ⚠ ALL FOUR RUN OVER A REAL GRANT AND THE PRODUCTION `gateAppender`, never a capturing stub. The
 * stub arms (`ST8`, `ST17`) still exist and still earn their place — they assert the SHAPE handed
 * over the seam, which a file read cannot see once the bytes are on disk — but a suite in which
 * every ledger arm holds the appender in memory is a suite that never proved the file exists.
 */
export const STAMP_ARMS = {
    'ST1-not-initialised': 'no .wyrd/ directory refuses SCRIBE_NOT_INITIALISED, names the directory, and creates nothing',
    'ST2-config-minted': '.wyrd/ present and no config mints a v4 UUID through the gate and ADOPTS it; a second call mints exactly once speculatively, DISCARDS that id and reads the same one back, leaving the file untouched; a throwing minter propagates over both a valid and a missing config',
    'ST3-config-invalid': 'an unknown key, a wrong schema, a non-UUID id and a non-boolean flag each refuse SCRIBE_CONFIG_INVALID, and each refusal carries config_created false — the config EXISTS, so the exclusive create refused EXISTS and this call minted nothing',
    'ST4-config-too-large': 'a config over the 16,384-byte read window refuses SCRIBE_CONFIG_TOO_LARGE carrying config_created false, and the one-byte-under pair refuses INVALID carrying it too, so the size branch is a SIZE branch',
    'ST5-arc-immutable-before-sources': 'an Arc/ target refuses ARC_IMMUTABLE with the primitive spy showing NO source was read — the oracle leg',
    'ST6-source-escape-reads-nothing-appends-nothing': 'a source resolving outside the grant refuses under the FENCE\'s reason; target not created, appender never called',
    'ST7-source-changed': 'primitives serving different bytes to the window loop and the hash refuse SOURCE_CHANGED_DURING_READ, creating no PAGE while reporting through config_created true the config step 4 minted before the loop ran — the invocation is not a no-op and the arm no longer says it is',
    'ST8-record-shape': 'a successful write: the appended line parses and matches the wire shape key-for-key, vault_id on every identity, forward-slash paths, quote.sha256 over the FULL quote',
    'ST9-quote-truncated': 'a 3,000-byte multibyte quote stores ≤1024 bytes cut on a UTF-8 boundary, truncated true, original_utf8_bytes 3000, sha256 still over the whole quote',
    'ST10-line-too-large': 'a record exceeding the line ceiling refuses LINEAGE_LINE_TOO_LARGE before any PAGE is created, and the refusal REPORTS the config the same call minted on the way past through config_created rather than leaving it to be inferred from disk',
    'ST11-frontmatter-off-bytes-untouched': 'with the opt-in false the page bytes are byte-identical to the content supplied',
    'ST12-frontmatter-on-prepended': 'content with no frontmatter gains a block carrying exactly one wyrd_lineage key, and the record projection omits page.content',
    'ST13-frontmatter-on-inserted': 'content opening with --- gains the key BEFORE the closing fence, with the existing keys untouched',
    'ST14-frontmatter-conflict': 'an existing top-level wyrd_lineage key refuses FRONTMATTER_CONFLICT; an INDENTED one does not',
    'ST15-frontmatter-invalid': 'an unclosed frontmatter block refuses FRONTMATTER_INVALID rather than being prepended to',
    'ST16-exists-is-tier-a': 'a target that already exists refuses the fence\'s EXISTS — tier A\'s rule arriving from the fence — with retained: null meaning the fence left nothing AT THE PAGE TARGET rather than that the invocation created nothing; the outcome is a fence PASS-THROUGH, the ONE documented exclusion from the config_created rule (D8), so it carries no such field — pinned as an assertion beside the disk proof that the config was in fact minted — and the appender is never called',
    'ST17-ledger-failed-after-create': 'a refusing appender yields PAGE_WRITTEN_LEDGER_FAILED carrying the Created, and the page IS on disk and is NOT removed',
    'ST18-no-outside-names': 'over every Scribe-originated refusal above, no absolute path and no outside path appears in any detail',
    'ST19-request-shape': 'an unknown key, a missing key, a non-array derivedFrom, an entry with no spans and an inherited key each refuse before anything is read',
    'ST20-span-refusal-passed-through': 'a SPAN_* refusal from step 5 keeps its own reason and where, not translated into a Scribe reason, in an envelope of exactly four own keys — the three span.ts returns plus the documented config_created the stamp path adds on the way out — while a step-3 SHAPE fault, decided before loadConfig runs, carries the original three and no summary at all',
    'ST21-source-cache-one-window-loop': 'two pages derived from one source run the window loop once; the second stamp still hashes, and the record is identical either way',
    // ---- the end-to-end ledger, over the production appender ----------------
    'ST22-ledger-line-lands': 'a real write through gateAppender puts exactly ONE LF-terminated line in <vault>/.wyrd/lineage.jsonl, parsing to the record ST8 pins, and the reported byte count is the file\'s own size',
    'ST23-ledger-accumulates': 'three writes leave three lines in call order, each intact and independently parseable, the file only ever growing and never truncated',
    'ST24-ledger-parent-missing-refuses-after-create': '.wyrd/ removed between the config load and the append yields PAGE_WRITTEN_LEDGER_FAILED carrying the FENCE\'s own MISSING refusal, with the page on disk and no directory made',
    'ST25-ledger-concurrent': 'eight concurrent writePage calls over ONE scribe leave eight intact lines, every one parsing, no torn or spliced record, and eight distinct pages',
    // ---- the cold-review round, 2026-09-02 ----------------------------------
    // ⚠ EVERY ROW BELOW IS A DEFECT THAT WAS LIVE IN THE BUILT PATH, not a hypothetical. Each names
    // the disagreement or the leak it pins, because an arm whose reason is "coverage" is one a
    // later session deletes without knowing what it was holding.
    'ST26-frontmatter-carries-no-page-identity': 'a write through a REAL in-grant junction refuses PARENT_ALIAS with no page created, and on a direct path the embedded projection has NO page key at all while the ledger carries the fence\'s canonical path — the two records can no longer disagree about which page this is',
    'ST27-line-limit-is-decided-before-create': 'a draft within 15 bytes of the ceiling with a large content byte-count refuses LINEAGE_LINE_TOO_LARGE and creates NO PAGE — the widest-placeholder rule, which the narrow placeholder let through into a created page and a fabricated PAGE_WRITTEN_LEDGER_FAILED — and the refusal reports through config_created the config the same call minted',
    'ST28-guaranteed-refusals-read-nothing': '65 derived_from entries, and a malformed span, each refuse with the primitive spy showing ZERO source opens — the oracle leg of the count caps and the span shapes, as ST5 is for Arc/',
    'ST29-event-id-unique': 'two writes under a PINNED clock produce lines differing in event_id and in nothing else that should not differ; the id is a v4 UUID, and the page\'s projection carries the SAME id as its ledger line',
    'ST30-horizontal-rule-is-not-frontmatter': 'a document opening with a horizontal rule over prose is PREPENDED to, never spliced — with a second rule inside the ceiling (the case that silently inserted a key into prose) and without one (the case that refused an ordinary file)',
    'ST31-crlf-preserved': 'a CRLF document gets a CRLF key line and stays single-ending; the LF document beside it stays LF',
    'ST32-quoted-key-is-the-same-key': 'a quoted `"wyrd_lineage":` or `\'wyrd_lineage\':` already in the page refuses as a conflict, because YAML says it is the same key — the spelling that used to write a SECOND one',
    'ST33-prepend-crlf-all-three-exits': 'all THREE prepend exits give a CRLF document a CRLF block — plain prose, rules around prose, and an unclosed rule; each exit is asserted separately so a fix applied to one is caught',
    'ST34-prepend-lf-introduces-no-cr': 'the same three shapes in LF get an LF block and no CR byte is introduced — the pair that stops an always-CRLF "fix"',
    'ST35-prepend-first-break-wins-on-mixed': 'a document already mixed keeps its own bytes exactly and the inserted block follows its FIRST break, in both directions — rejecting majority, last-ending and whole-file normalisation',
    'ST36-prepend-without-evidence-defaults-lf': 'an empty document and a single unterminated line have no ending to read; the block is LF and the original suffix survives byte-identical',
    'ST37-page-path-is-bounded': 'the page path — the only variable-width field in a bounded line with no bound of its own — refuses one byte over MAX_PAGE_PATH_BYTES before anything is created, and succeeds at the bound exactly, so the ceiling is a bound rather than a blanket refusal',
    'ST38-ledger-failed-carries-the-real-cause': 'PAGE_WRITTEN_LEDGER_FAILED carries the refusal that actually occurred — reason AND detail, verbatim — instead of a fabricated one, and the orphan page is asserted PRESENT so a green suite is never read as closing it; the post-create SIZE site is a different one and is held by ST41',
    'ST39-config-parent-alias-refused': 'a `.wyrd` junction to Arc/ refuses PARENT_ALIAS at the config load with the primitive spy showing ZERO source reads — before any source is read and before any page exists, with no config, no ledger and no page written — an EXISTING Arc/scribe.json does not hide it because the create-first order reaches PARENT_ALIAS ahead of EXISTS, and the ordinary vault beside it reports config_created true on its first stamp and false on its second',
    'ST40-planted-page-refused': 'the reproduced Arc/ escape driven end-to-end: a `Notes` junction to Arc/ with a page requested at Notes/planted.md refuses PARENT_ALIAS and nothing lands in Arc/, where the lexical Arc/ screen cannot see it at all; a DEEPER-ancestor request (Notes/sub/x.md) refuses the same way, and on EVERY refusing leg the detail is checked CASE-FOLDED to name the caller\'s own spelling and never the alias TARGET',
    'ST41-post-create-size-branch-is-reachable': 'the post-create line-size branch is REACHABLE — a fold-equal alias of different byte width (the Kelvin sign folds to a one-byte k) makes created.rel wider than the draft was sized against, so the branch fires PAGE_WRITTEN_LEDGER_FAILED with cause LINEAGE_LINE_TOO_LARGE over an orphan page asserted PRESENT; the band was RE-MEASURED by exact serialisation as 288-673 and all four edges are asserted — 287 succeeds and 674 refuses at the draft outside it, 288 and 673 reach the branch inside it — so the band is pinned rather than described',
    // ---- the validated snapshot, 2026-09-08 ---------------------------------
    // ⚠ BOTH ROWS ARE THE 09-03 CLOSE-REVIEW'S OWED ROW, PAID. `preflight` returned the caller's
    // own object, so `writePage` re-read `content`, `derivedFrom` and every span off it across two
    // awaits — the validated thing and the used thing were different reads of a mutable object.
    'ST42-request-mutation-after-validation-is-not-observed': 'a getter serving one value to its FIRST read and a substitute to every later read is not observed: content, derivedFrom and a SPAN inside it are each read EXACTLY ONCE, at validation, so the substitute is never fetched; the page bytes and the ledger record carry the validated content (asserted on both), and the ledger record carries the validated derivedFrom and span (asserted on the ledger; nothing on the page carries them). The option hooks mark the steps the second read WOULD have happened at; they mutate nothing',
    'ST43-refusal-discrimination-is-not-caller-supplied': 'a request whose PROTOTYPE carries { ok: false } is a request, not a refusal — it writes its page and appends its line, and the caller\'s forged reason never comes back; the own-property leg refuses BAD_INPUT at the strict key screen, which is a different reason and is asserted as one'
};

/**
 * ⚠⚠ THE TWO GUARDS BEHIND `ST43` ARE NOT INDEPENDENT, AND THAT WAS MEASURED RATHER THAN ARGUED.
 *
 * `M27` was first written as the discrimination alone — `checked instanceof Validated` restored to
 * the old `isRefusalLike(checked)` — and it SURVIVED. The reason is the snapshot: with `preflight`
 * returning an object of the module's own making, a `Validated` carries no `ok` on itself or on its
 * prototype, so nothing a caller supplies can make the `.ok === false` read answer true. The
 * snapshot subsumes the prototype-forgery defect.
 *
 * ⚠ THE `instanceof` STILL EARNS ITS PLACE, and the argument is about the future rather than about
 * today: it is the half that does not depend on the snapshot staying deep. A later change that let
 * any caller-derived value back out of `preflight` reopens the question, and this is what stands
 * there. `M27` therefore mutates BOTH halves — the previous shipped shape, which is what actually
 * ran — because a row that cannot fail certifies a guard nobody is measuring.
 */

/** The MCP server and tier-planning arms — `test/server.test.js`. */
export const SERVER_ARMS = {
    'SV1-default-a-handshake': 'an absent WYRD_SCRIBE_TIER completes a real stdio handshake with active tier A',
    'SV2-a-structural-list': 'production tier A lists exactly write_page; no overwrite, delete, rename or lineage-query registration exists, and every input object is strict',
    'SV3-b-positive-list': 'the test-only B fixture uses the real planner and server builder, lists A plus overwrite_page, and dispatches the inert B registration through the planned map',
    'SV4-c-positive-list': 'the test-only C fixture uses the same builder, lists all four cumulative registrations, and dispatches both inert C registrations through the planned map',
    'SV5-invalid-tier-no-open': 'empty, lowercase, unknown and four padded tier values each name their raw value verbatim and refuse before either the injected gate or transport factory runs',
    'SV6-known-tier-unavailable': 'production B and C each name the requested tier and refuse before opening a gate or transport rather than silently capping to A',
    'SV7-disclosure-as-received': 'initialize.instructions received by the SDK client names the canonical grant, active tier, exact tool set, conditioned parent-alias boundary, unconditional root-identity recheck, residual races/open interval, append retention and retained-page outcome',
    'SV8-description-as-received': 'every listed production tool names active tier A; write_page first sentence is exactly 86 characters and describes an immediate create attempt while carrying the tier, Arc/ and fence',
    'SV9-write-and-lineage': 'a real stdio write_page call creates the supplied page and exactly one LF-terminated lineage record naming it',
    'SV10-refusals-on-wire': 'Arc/, occupied target, escaped target and escaped source refusals carry their complete exact result envelopes over MCP; no refused target lands and the ledger stays byte-identical',
    'SV11-reader-unchanged': 'with both stdio servers configured and connected, the Reader lists exactly read while the Scribe lists exactly write_page',
    'SV12-schema-enforced-on-wire': 'over real stdio, an extra property, negative offset, empty spans, missing source and zero length in a three-key span each name the first schema violation and call the injected Scribe port zero times',
    'SV13-rich-results-on-wire': 'a first write carries config_created true and a ledger failure carries reason, nested cause and created with each JSON body byte-identical to the injected port result; the ledger-failure prefix says the page was created and directs the caller to cause.retained',
    'SV14-fence-claims-are-the-fences': 'initialize instructions and the write_page description carry the conditioned alias claim, unconditional root-identity recheck, residual races/open interval, append retention, the fence README limits heading verbatim and pointers to both write API contracts',
    'SV15-v1-raw-baseline': 'an SDK-free raw JSON-RPC corpus pins tier refusals, pre-initialize and duplicate-initialize behavior, non-empty client capabilities and list cursor, the v1 -32603 invalid-name characterization baseline, selected static stdout bytes, exact schemas/descriptions, deterministic write and ledger bytes, schema and fence refusals, fixture B/C registrations, per-stream line ordering and filesystem outcomes'
};

export const PACKAGE_ARMS = {
    'PK1-manifest-surface': 'the published 0.1.0 manifest has the exact binary, files, metadata and Fence dependency surface without publish material',
    'PK2-packed-files': 'npm pack derives package metadata, docs, the bin and every expected dist output while excluding source, scripts, tests and build metadata',
    'PK3-version-single-source': 'the generated runtime version equals package.json and server.ts owns no second literal',
    'PK4-readme-contract': 'the README states the Tier-A, configuration, input, lineage, recovery, security and privacy contracts and links to the Fence window'
};

export const ALL_ARMS = { ...SPAN_ARMS, ...STAMP_ARMS, ...SERVER_ARMS, ...PACKAGE_ARMS };

/**
 * ⚠ EVERY SCRIBE ARM IS STILL PORTABLE, AND THE REASON CHANGED WITH THIS SLICE. It used to be that
 * the package touched no filesystem at all. The stamp arms DO — they build a real grant in the OS
 * temp directory — but none of them creates a SYMLINK, which is the only thing the Windows
 * privilege gates. Escapes are exercised with an absolute outside path and a `..` traversal, both
 * of which the fence refuses without any reparse point existing. So `test` and `test:portable` run
 * the identical set, and the runner still prints the denominator rather than letting it be assumed.
 *
 * ⚠ ADDING A SYMLINK FIXTURE HERE WOULD BREAK PORTABLE MODE with no gate going red, because this
 * list is derived rather than declared — the equality the runner checks would still hold while the
 * fixture threw EPERM on an unprivileged machine. A symlink-needing arm must be named explicitly
 * and held out of this list, as the fence's `SYMLINK_PRIVILEGE_ARMS` does.
 */
export const PORTABLE_ARMS = Object.keys(ALL_ARMS);
