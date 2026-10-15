#!/usr/bin/env node
'use strict';

// Plan task 22 fixture: a minimal harness that drives the *real* GitHub
// Actions toolkit cache client (`@actions/cache` v3, fully v1) against a
// cachette server.
//
// It is deliberately tiny: no protocol logic lives here, only the public
// `saveCache` / `restoreCache` calls the actions ecosystem actually makes.
// Everything the test asserts about the server is observed from the toolkit's
// own behaviour (return value + captured warnings), never re-implemented.
//
// Usage (cwd = a scratch workspace, ACTIONS_CACHE_URL / ACTIONS_RUNTIME_TOKEN
// set by the caller):
//
//   node toolkit.js miss    <key>
//   node toolkit.js lookup  <key> [payload-relative-path]
//   node toolkit.js save    <key> <payload-relative-path>
//   node toolkit.js restore <key> <payload-relative-path>
//
// `lookup` calls `restoreCache(..., { lookupOnly: true })`, which stops right
// after the GET /_apis/artifactcache/cache find (no download), so it isolates
// the lookup half of the protocol from the archive transfer.
//
// The last stdout line is a machine-readable marker the Rust test parses:
//   __CACHETTE_JSON__{"command":...,"key":...,"result":...}

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const cache = require('@actions/cache');
const core = require('@actions/core');

// `@actions/cache` swallows non-validation cache errors and only surfaces them
// through `core.warning`. Capture those so the harness can report *why* a
// restore failed instead of silently returning `undefined`.
const warnings = [];
const originalWarning = core.warning.bind(core);
core.warning = (message) => {
    warnings.push(String(message));
    originalWarning(message);
};

function sha256File(file) {
    return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function emit(payload) {
    process.stdout.write(`__CACHETTE_JSON__${JSON.stringify(payload)}\n`);
}

function fail(payload, error) {
    emit({ ...payload, result: 'error', error: String(error && error.stack ? error.stack : error) });
    process.exitCode = 1;
}

async function main() {
    const [command, key, target] = process.argv.slice(2);
    if (!command || !key) {
        fail({ command }, 'usage: toolkit.js <miss|lookup|save|restore> <key> [path]');
        return;
    }
    switch (command) {
        case 'miss': {
            // A restore for a key that was never saved must be a clean miss:
            // `restoreCache` returns `undefined` (no throw, no panic on the
            // server). Any warning here is itself the failure signal.
            const restored = await cache.restoreCache([target || 'payload.bin'], key);
            emit({ command, key, result: restored === undefined ? 'miss' : 'hit', restored, warnings });
            return;
        }
        case 'lookup': {
            // `lookupOnly` stops after find: it proves the server returned a
            // hit without exercising the archive download at all.
            const found = await cache.restoreCache([target || 'payload.bin'], key, [], { lookupOnly: true });
            emit({ command, key, result: found === undefined ? 'miss' : 'hit', restored: found, warnings });
            return;
        }
        case 'save': {
            if (!target) {
                fail({ command, key }, 'save requires a payload path');
                return;
            }
            if (!fs.existsSync(target)) {
                fail({ command, key }, `payload not found: ${target}`);
                return;
            }
            const before = sha256File(target);
            const cacheId = await cache.saveCache([target], key);
            emit({ command, key, result: 'saved', cacheId, sha256: before, warnings });
            return;
        }
        case 'restore': {
            if (!target) {
                fail({ command, key }, 'restore requires a payload path');
                return;
            }
            // Remove the payload first so a successful restore must recreate it.
            // (The archive stores the path relative to the workspace root.)
            const workspace = process.cwd();
            const absolute = path.resolve(workspace, target);
            fs.rmSync(absolute, { force: true });
            const restored = await cache.restoreCache([target], key);
            if (restored === undefined) {
                emit({ command, key, result: 'miss', warnings });
                return;
            }
            if (!fs.existsSync(absolute)) {
                emit({ command, key, result: 'error', error: 'restored but payload missing', warnings });
                process.exitCode = 1;
                return;
            }
            emit({ command, key, result: 'restored', restored, sha256: sha256File(absolute), warnings });
            return;
        }
        default:
            fail({ command, key }, `unknown command: ${command}`);
    }
}

main().catch((error) => fail({ command: process.argv[2], key: process.argv[3] }, error));
