/**
 * Mutation rows author anchors and replacement text with LF. Detect the target's
 * uniform ending once, before any mutation, and preserve it in each applied row.
 */
export function lineEndingOf(source, label = 'mutation target') {
    const crlf = (source.match(/\r\n/g) ?? []).length;
    const bareLf = (source.match(/(?<!\r)\n/g) ?? []).length;
    const bareCr = (source.match(/\r(?!\n)/g) ?? []).length;
    if ((crlf > 0 && bareLf > 0) || bareCr > 0) {
        throw new Error(`${label} has mixed or unsupported line endings: ${crlf} CRLF, ${bareLf} LF, ${bareCr} bare CR`);
    }
    return crlf > 0 ? '\r\n' : '\n';
}

export function withLineEnding(lfText, ending) {
    if (lfText.includes('\r')) throw new Error('mutation text must be LF-authored');
    return lfText.replace(/\n/g, ending);
}
