/**
 * THE DESIGN INVENTORY of test arms.
 *
 * ⚠ This file is DECLARATIVE and deliberately separate from the registration path. A test that
 * is deleted leaves its row here, and `scripts/run-tests.mjs` fails the run because the union
 * of executed IDs no longer equals this list. A test that is added without a row here fails it
 * too. Each row carries what the arm is FOR, so removing one is a visible, reviewable edit
 * rather than a silent deletion of two adjacent lines.
 *
 * ⚠⚠ THE FENCE'S ARMS LEFT ON 2026-09-01 AND THAT IS NOT A SHRUNKEN SUITE. 62 fence arms, the
 * three grant-shape arms (`S4`, `S8`, `S12`) and the three fence-surface arms (`E4`, `E9`, `E12`)
 * now live in `wyrd-fence`, which measures its own adequacy — see
 * `designs/2026-09-01-fence-test-relocation-plan.md`. What remains here is what this package is
 * FOR: product behaviour and integration coverage of the fence through the Reader's own paths.
 *
 * ⚠ THE HONEST LIMIT this file used to state — "deleting a test AND its row here still passes" —
 * IS NOW CLOSED FOR EVERY PRE-MOVE ID. `test/relocation-contract.json` is an outside referent with
 * no generator, and `scripts/run-tests.mjs` checks this inventory against it before it spawns
 * anything. The limit survives only for arms added after 2026-09-01 that nobody adds to the
 * contract's `armsAddedPostMove` list.
 */

/**
 * Startup and observer arms — `test/startup.test.js`.
 *
 * ⚠ `S2-missing` AND `S3-file-grant` ARE THE INTEGRATION HALF of refusals whose direct assertions
 * moved to the fence with `S4`/`S8`. They stay because what they assert is that `main()` surfaces
 * the reason and prints the resolved path, which is this package's disclosure behaviour and not
 * the gate's. Removing them because "the fence covers that now" would delete the only coverage of
 * the plumbing between them.
 */
export const STARTUP_ARMS = {
    'S1-no-grant': 'no grant: static message, non-zero exit, factory never runs',
    'S2-missing': 'non-existent absolute grant refuses AND prints the resolved path',
    'S3-file-grant': 'a grant that is a file refuses',
    'S5-precedence': 'the command line overrides the environment',
    'S6-arg-forms': '`--grant=value` and `--grant value`',
    'S7-valid': 'a valid grant starts and discloses the canonical root',
    'S9-import-touch': 'an import-time filesystem touch IS detected',
    'S10-bootstrap-order': 'the bootstrap arms the instrument before importing',
    'S11-child-no-grant': 'the child exits non-zero and names no candidate vault',
    'S13-grant-source-parity': '--grant X, --grant=X and WYRD_GRANT=X agree exactly',
    'S14-no-grant-claims': 'the no-grant refusal states both refusals, the outside-reaching hard link, and the scoped read-only',
    'S15-client-config-entrypoint': 'the example client config resolves to the real built entrypoint and its grant is still a placeholder',
    'S16-layer-probes': 'startup probes exactly Arc, Mage and Forum and never reads the grant-root listing'
};

/**
 * End-to-end arms — `test/handshake.test.js`.
 *
 * ⚠ `E3-read-and-refuse` AND `E5-disclosure` ARE WHAT THE PLAN ASKED THIS PACKAGE TO KEEP: the
 * fence exercised over the wire, through the Reader's normal server paths, rather than by direct
 * `createFsGate` calls. `E4`, `E9` and `E12` were the direct ones and went with the fence.
 *
 * ⚠ `E14-surface-claims` IS THE ONLY ARM HERE THAT OWNS A RELATIONSHIP RATHER THAN A STRING.
 * Every other surface arm — `S14`, `E13`, `E5` — validates ONE surface against ONE set of
 * patterns, which is why the disclosure surfaces disagreed three times on 2026-09-01 while the
 * battery stayed green. `E14` declares the claim set once and checks every surface against it, so
 * a new surface or a changed claim is one edit in one place. It lives in this file because the
 * runtime surfaces arrive over the wire. ⚠ Its surface LIST is derived as of 2026-09-02 — the
 * hand-written one was wrong four times running, which is the defect the arm exists to catch,
 * sitting inside the arm.
 *
 * ⚠⚠ `E15-refusal-vocabulary` IS THE ONE ARM HERE WHOSE TWO SIDES COME FROM DIFFERENT PLACES, and
 * that is the whole of it. `E14` compares prose to prose, so it makes the surfaces agree and cannot
 * make them true — it was found on 2026-09-02 pinning three false claims across every surface it
 * covers, green throughout. `E15` derives one side from the PROGRAM (the fence's enumerated refusal
 * unions plus the reason literals in this package's own build output) and requires the prose to
 * account for it. A new refusal class then forces a documentation decision rather than widening the
 * gap in silence.
 *
 * ⚠ `E6` AND `E10` STAYED, AND THE FENCE'S COPY OF THE SAME GUARD IS GRADED BY NEW IDS. Their
 * subject is `scripts/preflight.mjs`, suite infrastructure both packages need and neither can
 * import across the boundary. The contract forbids one id living in two inventories, so these two
 * keep grading this package's copy and `FP1`/`FP2` grade the fence's.
 */
export const E2E_ARMS = {
    'E1-handshake': 'initialize handshake over stdio',
    'E2-one-tool': 'exactly one tool, `read`, with a real description',
    'E3-read-and-refuse': 'serves in-grant, refuses an escape, end to end',
    'E5-disclosure': 'initialize.instructions discloses the CANONICAL grant, names no outside path, and qualifies the no-network claim as stdio-only',
    'E6-preflight': 'the suite preflight refuses on denied symlink privilege, and separates the probe stages',
    'E7-layers': 'Mage layers are named only when present, and a plain folder gets no vault paragraph',
    'E7-shadow': 'a present file is not a layer, a reparse-point layer is, and probe failures remain distinct from absence',
    'E8-not-text': 'a file that is not valid UTF-8 is refused NOT_TEXT, never returned altered',
    'E10-junction-preflight': 'the tier-1 preflight refuses when a junction cannot be created',
    'E11-read-only-hint': '`read` declares readOnlyHint, so the guarantee is machine-readable',
    'E13-read-description': 'the `read` description states both refusals and the outside-reaching hard link, as the model receives it',
    'E14-surface-claims': 'every DERIVED disclosure surface carries one declared claim set, every claim either carried or explicitly exempt per surface, and no retired wording anywhere',
    'E15-refusal-vocabulary': 'every refusal the program can return — the fence\'s enumerated unions plus the Reader\'s own — is stated on a surface or exempted with a written reason',
    'E16-claim-evidence': 'every disclosure claim declares one of three evidence grades and a substantive limit, claim ids are unique, and the exact set of unverified ids is pinned and printed in full on green. ⚠ Declaration and denominator only; it does not establish truth, that any grade is correct, or that any evidence ran',
    'E17-v1-raw-baseline': 'an SDK-free raw JSON-RPC corpus pins no-grant exit and stderr, grant precedence, pre-initialize and duplicate-initialize behavior, non-empty client capabilities and list cursor, the v1 -32603 invalid-name characterization baseline, selected static stdout bytes, the exact tool declaration, normal, paged, non-text and error reads, per-stream line ordering and unchanged fixture bytes',
    'E18-recapture-refused': 'the recapture guard refuses to overwrite an existing v1 golden and permits a first capture where none exists, and the real corpus file is byte-identical after a refused attempt; it pins THIS entry point only and does not prove no other code can write that file',
    'E19-transport-network-accounting': 'every transport derived by path from the Reader\'s built ServerTransport declaration is represented exactly once in a two-way accounting table and has network behaviour stated on a loaded surface or substantively exempted. ⚠ Set accounting only; it does not establish that a stated sentence is true'
};

/** Streamable HTTP arms — `test/http.test.js`. */
export const HTTP_ARMS = {
    'H1-transport-selection': 'no flag selects stdio, --http selects HTTP, loopback spellings are accepted, and a non-loopback address without --http-public is refused before listen while both transports receive a configured-server factory. ⚠ SAMPLED, not exhaustive: H22 owns the complete new refusal table',
    'H2-factory-local-roundtrip': 'an injected Server factory completes a real Streamable HTTP server/discover POST over an OS-assigned localhost port, returning the injected identity and the negotiated revision, and the factory runs once for that one request — NOT that a fresh server is built per exchange, which no arm yet proves',
    'H3-route-method': 'the Reader owns /mcp routing: one other path is 404 and GET /mcp is 405 with Allow POST before auth or server construction. ⚠ TWO PROBES, not a POST-only proof: no other method and no other path is exercised',
    'H4-invalid-origin-order': 'an Origin differing by scheme and one differing by port are each 403 before the auth seam or configured-server factory runs. ⚠ Two mismatches, not a proof of exact equality in general, and a zero counter is evidence about the APPLICATION callback only — it cannot show Node never parsed the header',
    'H5-allowed-origin-order': 'EVERY derived allow-list entry is not rejected on Origin and reaches the auth seam, once per request. ⚠ Occurrence, not ordering: no arm records an ordered auth-then-handler trace',
    'H6-absent-origin-order': 'an absent Origin is not rejected on that basis and reaches the auth seam once. ⚠ Occurrence, not ordering, as with H5',
    'H7-stateless-per-exchange': 'two exchanges against one listener build two distinct Server instances and neither response issues nor requires a session header, discharging criterion 2\'s no-protocol-session-state clause that H2\'s single factory call cannot',
    'H8-partial-body-shutdown': 'a 10-of-200-byte raw POST is destroyed during admission, close settles within 750 ms, and a late attempt to send the rest never reaches the configured-server factory',
    'H9-auth-race-shutdown': 'a full raw POST held at readAuthInfo cannot reach the configured-server factory or tool after shutdown begins, even when auth is then released',
    'H10-graceful-execution-shutdown': 'a real tool handler already executing when close begins is drained, and the raw client receives its complete successful response before shutdown settles; a second close() during the drain returns the IDENTICAL promise, which is the only proof the ordered close is memoized',
    'H11-disconnect-propagation': 'destroying the raw client socket while a tool is held aborts that exchange\'s exact Fetch Request signal, and the abort event fires once',
    'H12-concurrent-signal-shutdown': 'a child with a partial raw client receives SIGINT then SIGTERM, shares one shutdown path without a duplicate-close error, and exits orderly without process.exit()',
    'H13-security-ordering': 'a slow invalid-Origin raw POST is refused before auth or factory, while an authorized partial POST reaches auth before body collection but not the configured-server factory until its body completes',
    'H14-request-body-cap': 'a chunked raw request exceeding MAX_HTTP_REQUEST_BYTES answers 413 and never reaches the configured-server factory',
    'H15-auth-401-no-tool': 'real listener, real verifier and real tool counter: missing, malformed and wrong bearer values receive one identical 401 before body collection or tool execution, while the valid token reaches the tool',
    'H16-verifier-injection-real-socket': 'main() with a stub verifier factory and the real startHttp: only the sentinel token gets 200, and unavailable maps to 503 without transport changes',
    'H17-no-query-token-or-leak': 'POST /mcp?access_token=<sentinel> without a header is refused before the verifier, and the sentinel appears in no exercised disclosure or diagnostic sink',
    'H18-no-token-refuses-before-listen': 'across both loopback and consented network bind modes, absent, ambiguous, malformed, unreadable and insecure POSIX token sources refuse before startHttp is ever called; token generation prints fresh canonical output and writes nothing',
    'H19-response-stream': 'a real maximum-window read starts reaching the localhost client before a controlled Response stream reaches EOF, while every whole-body Response materializer is a throwing sentinel. ⚠ STRUCTURAL AND BOUNDED: a tee that forwards while retaining a copy would still pass, so this does not prove comparative HTTP/stdio heap parity or a resident-copy count',
    'H20-localhost-read-budget': 'a real 1 MiB ASCII file, requested with an explicit 262,144-byte limit, is returned byte-exactly over localhost in four measured fence calls under 400 ms. ⚠ FIXED CASE: not the 32,768-byte default, multi-byte content, other sizes, remote hosts or sustained throughput',
    'H21-origin-serialization': 'real assigned-interface network and [::1] binds on default port 80 omit :80 from URL-serialized Origins; the network bind derives exactly one Origin, while --http 0 derives both IPv4 loopback Origins. ⚠ SAMPLED: equivalent IPv6 spellings and hostname Origins remain outside this arm',
    'H22-consent-and-guards': 'the full network refusal table including malformed/out-of-range ports and 127.0.0.2 plus --http-public; main never calls startHttp without consent; direct host/kind mismatches refuse before handler construction; a forced kernel-reported address mismatch refuses after closing handler and listener. ⚠ Cannot prove device, firewall, or route reachability',
    'H23-network-disclosure-honesty': 'a fixed-port real network start prints every does-not-know, checked-once, clear-text and hard-link line exactly, while a fixed-port loopback start prints the complete loopback form and omits every network-only line. ⚠ Pins Wyrd\'s stated ignorance, not facts about the machine',
    'H24-network-plain-http-auth': 'a fixed-port real assigned-interface listener starts over http, accepts the configured bearer token, and returns 401 for missing and wrong tokens. ⚠ Does not capture packets, prove reachability from another device, or rule out token leaks on unexercised paths',
    'H25-cert-host-grammar': 'the exact cert --host command shape accepts IDNA-canonical hostnames, IPv4 and raw IPv6 while a table refuses wildcards, URLs, ports, brackets, scopes, wildcard/multicast/broadcast/mapped addresses and malformed IP-looking values. ⚠ Sampled grammar; no DNS or interface-membership claim',
    'H26-cert-exclusive-write': 'both fixed destinations are lstat-checked before generation, an existing file or dangling symlink leaves the other untouched, two barrier-synchronized writers produce one winner through exclusive creation, POSIX key mode has no group/world bits, and a raced key causes identity-checked rollback of only the created cert. ⚠ No two-entry transactional-atomicity claim',
    'H27-cert-content-and-freshness': 'two real CLI runs produce matching RSA-2048/SHA-256 pairs with CA path length 0, server-auth-only EKU, exact typed SANs, 397-day skewed validity, certificate-matching printed facts and four platform instruction headings; serial and public key differ. ⚠ Two differences do not prove unpredictability, and instruction correctness remains prose',
    'H28-generated-cert-trust-control': 'criterion 15: a real TLS listener completes an authorized handshake when the generated cert is supplied as CA, while the same listener without that CA rejects DEPTH_ZERO_SELF_SIGNED_CERT. ⚠ H27 owns freshness; this arm does not prove HTTP/MCP or platform instruction correctness',
    'H29-tls-startup-validation': 'both-or-neither TLS argument forms plus malformed certificate/key, match and time checks; mismatched material through main refuses before startHttp, and injected times prove not-yet-valid and expired refusal. ⚠ Does not validate chain structure, EKU/SAN suitability, multi-PEM selection or encrypted-key handling',
    'H30-tls-disclosure': 'a real fixed-port network HTTPS start derives https metadata, Origins, fingerprint and expiry from its validated certificate, retains the does-not-know block, omits both clear-text-warning phrases, and warns for a sampled under-30-day expiry. ⚠ Pins output and correlation for this start, not routing facts or certificate reloads',
    'H31-tls-handshake-shutdown': 'a raw TCP client stalled before TLS handshake completion is tracked and destroyed so ordered close settles within 750 ms. ⚠ A shorter platform handshake timeout could also pass, and admitted encrypted-request draining is not exercised here',
    'H32-network-instructions-truth': 'the production main HTTP path on loopback, using the default Reader factory, returns authenticated server/discover instructions that say the server is listening, deny outbound connections, retain the client-forwarding locality caveat, and omit the retired transport-neutral no-network sentence',
    'H33-certificate-der-minimal-integers': 'directed serial-boundary entropy produces a certificate whose non-zero positive serial and every DER INTEGER use the shortest signed representation. ⚠ INTEGER canonicality only; new entropy-derived DER fields need directed boundary inputs of their own'
};

/**
 * Registry-manifest arms — `test/manifest-schema.test.js`.
 *
 * ⚠ `server.json` DECLARED ITS OWN CONTRACT AND NOTHING READ THE DECLARATION. Its first line is a
 * `$schema` URL; until 2026-09-02 no schema was vendored and no arm validated the file against one,
 * so a malformed manifest was caught by the MCP Registry at SUBMISSION rather than here. That is
 * the worst place for it: the npm publish has already happened by then.
 *
 * ⚠ THE TWO ARMS ANSWER DIFFERENT QUESTIONS AND NEITHER SUBSUMES THE OTHER. `MF1` asks whether the
 * file is WELL-FORMED against the schema it names. `MF2` asks whether it is TRUE — a manifest can
 * satisfy every schema constraint and still advertise a version that is not what shipped, or a
 * `name` that `package.json`'s `mcpName` does not match, which is the pair the registry reads out
 * of the published tarball to prove ownership. Nothing cross-referenced them before.
 */
export const MANIFEST_ARMS = {
    'MF1-manifest-schema': 'the vendored MCP registry schema still spans the bounded validator, and server.json conforms to it',
    'MF2-manifest-cross-reference': 'server.json\'s declared $schema is the vendored copy\'s $id, its name, version and npm identifier agree with package.json and the built program, and it advertises stdio and nothing else — EVERY packages[] entry declares transport stdio with no url, no argument of either shape (named or positional) carries --http, and remotes[] is absent or empty',
    'MF3-version-single-source': 'the generated runtime version equals package.json, server.ts imports it, and the source owns no second version literal'
};

export const ALL_ARMS = { ...STARTUP_ARMS, ...E2E_ARMS, ...HTTP_ARMS, ...MANIFEST_ARMS };

/**
 * TIER 2 — the arms that cannot run without the Windows symlink privilege.
 *
 * ⚠ READ OFF THE FIXTURES, NOT OFF THE ARM NAMES. An arm is tier 2 if the fixture it reads was
 * built with `fs.symlinkSync` in a mode the OS gates. Junctions and hard links are NOT gated and
 * do not put an arm here — `A28-symlinked-root`, now the fence's, was the standing example of that
 * mistake: its name says symlinked and its fixture is a junction.
 *
 * ⚠ MEMBERSHIP IS MACHINE-CHECKED, NOT TRUSTED. `scripts/run-tests.mjs --portable` asserts that
 * the skipped set equals this set EXACTLY — no more, no fewer. A misclassification in either
 * direction fails the run rather than quietly shrinking what got tested.
 *
 * ⚠ IT IS DOWN TO ONE ENTRY AND THAT IS NOT A WEAKENED GATE. Every other tier-2 arm was
 * fence-owned and moved; `S8-link-grants` moved with them. What is left is the one arm in this
 * package whose fixture is a symlink. The set is still asserted by identity, so a second arm that
 * quietly starts needing the privilege fails the portable run rather than joining it.
 */
export const SYMLINK_PRIVILEGE_ARMS = new Set([
    'E5-disclosure',        // the canonical-root arm reaches the grant through a dir symlink
    'H26-cert-exclusive-write' // the lstat arm distinguishes a dangling file symlink from absence
]);

/** TIER 1 — everything else. Derived, never hand-listed, so the two can never drift apart. */
export const PORTABLE_ARMS = Object.keys(ALL_ARMS).filter(id => !SYMLINK_PRIVILEGE_ARMS.has(id));
