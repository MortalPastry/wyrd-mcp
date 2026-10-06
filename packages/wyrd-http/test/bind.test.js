import assert from 'node:assert/strict';
import test from 'node:test';
import { readHttpArg } from '../dist/bind.js';
import { readHttpArg as readerReadHttpArg } from '../../wyrd/dist/main.js';
import { declare } from './manifest.mjs';

test('HB1-bind-parser-parity', () => {
    declare('HB1-bind-parser-parity');
    assert.strictEqual(readerReadHttpArg, readHttpArg, 'Reader must export the shared parser');
    const assertBoth = (argv, expected) => {
        const actual = readHttpArg(argv);
        assert.deepEqual(actual, expected, argv.join(' '));
        return actual;
    };
    const valid = [
        [['--http', '0'], { kind: 'loopback', host: '127.0.0.1', port: 0 }],
        [['--http', 'localhost:8080'], { kind: 'loopback', host: 'localhost', port: 8080 }],
        [['--http', '127.12.0.1:65535'], { kind: 'loopback', host: '127.12.0.1', port: 65535 }],
        [['--http', '[::1]:80'], { kind: 'loopback', host: '[::1]', port: 80 }],
        [['--http', '192.0.2.1:443', '--http-public'], { kind: 'network', host: '192.0.2.1', port: 443 }],
        [['--http-public', '--http', '[2001:db8::1]:443'], { kind: 'network', host: '[2001:db8::1]', port: 443 }]
    ];
    for (const [argv, bind] of valid) {
        assertBoth(argv, { present: true, bind, detail: null });
        assert.ok(Object.isFrozen(readHttpArg(argv).bind));
    }
    assertBoth([], { present: false });

    const invalid = [
        [['--http-public'], '--http-public requires one --http address'],
        [['--http-public=yes'], '--http-public is value-less; use the flag by itself'],
        [['--http', '--other'], '--http requires a port or host:port'],
        [['--http', '80', '--http', '81'], '--http may be specified only once'],
        [['--http', '80', '--http-public', '--http-public'], '--http-public may be specified only once'],
        [['--http', 'localhost:80', '--http-public'], '--http-public is redundant or misplaced for a loopback address'],
        [['--http', 'example.com:80'], 'HTTP host must be a concrete numeric interface address: example.com'],
        [['--http', 'localhost'], 'HTTP address is missing its port: localhost'],
        [['--http', '::1:80'], 'HTTP IPv6 address must be bracketed: ::1:80'],
        [['--http', '[::1]'], 'HTTP IPv6 address must use [address]:port: [::1]'],
        [['--http', '127.0.0.1:x'], 'HTTP port must be decimal: x'],
        [['--http', '65536'], 'HTTP port is outside 0..65535: 65536'],
        [['--http', '[fe80::1%eth0]:80', '--http-public'], 'scoped IPv6 cannot be serialized into a valid Origin'],
        [['--http', '0.0.0.0:80', '--http-public'], 'HTTP wildcard 0.0.0.0 names every interface'],
        [['--http', '224.0.0.1:80', '--http-public'], 'HTTP multicast is not a unicast interface endpoint'],
        [['--http', '255.1.1.1:80', '--http-public'], 'HTTP broadcast is not a unicast interface endpoint'],
        [['--http', '[::]:80', '--http-public'], 'HTTP wildcard :: names every interface'],
        [['--http', '[ff02::1]:80', '--http-public'], 'HTTP multicast is not a unicast interface endpoint'],
        [['--http', '[::ffff:192.0.2.1]:80', '--http-public'], 'HTTP IPv4-mapped IPv6 is not an interface endpoint'],
        [['--http', '192.0.2.1:80'], 'a non-loopback HTTP address requires --http-public'],
        [['--http', '[192.0.2.1]:80', '--http-public'], 'HTTP IPv4 addresses must not be bracketed']
    ];
    for (const [argv, detail] of invalid) {
        assertBoth(argv, { present: true, bind: null, detail });
    }
});
