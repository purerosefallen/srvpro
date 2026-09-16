'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { deleteDeckFile } = require('./deck-delete.js');

const waitForTurn = () => new Promise((resolve) => setImmediate(resolve));

async function deleteWithCallCount(deckPath, deckName) {
  let callCount = 0;
  const error = await new Promise((resolve) => {
    deleteDeckFile(deckPath, deckName, (err) => {
      callCount += 1;
      resolve(err || null);
    });
  });
  await waitForTurn();
  await waitForTurn();
  return { callCount, error };
}

async function assertInvalid(deckPath, deckName) {
  const result = await deleteWithCallCount(deckPath, deckName);
  assert.strictEqual(result.callCount, 1, `callback count for ${String(deckName)}`);
  assert.ok(result.error instanceof Error, `expected an error for ${String(deckName)}`);
  assert.strictEqual(result.error.message, 'Invalid deck');
  assert.strictEqual(result.error.code, 'EINVAL');
}

async function main() {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'srvpro-deck-delete-'));
  const deckPath = path.join(fixtureRoot, 'decks');
  const siblingPath = path.join(fixtureRoot, 'decks-evil');
  const outsidePath = path.join(fixtureRoot, 'outside');
  fs.mkdirSync(deckPath);
  fs.mkdirSync(siblingPath);
  fs.mkdirSync(outsidePath);

  try {
    for (const name of ['normal.ydk', '中文 卡组.ydk', 'metadata.txt']) {
      const target = path.join(deckPath, name);
      fs.writeFileSync(target, name);
      const result = await deleteWithCallCount(deckPath, name);
      assert.strictEqual(result.error, null);
      assert.strictEqual(result.callCount, 1);
      assert.strictEqual(fs.existsSync(target), false);
    }

    const missing = await deleteWithCallCount(`${deckPath}${path.sep}`, 'missing.ydk');
    assert.strictEqual(missing.callCount, 1);
    assert.strictEqual(missing.error.code, 'ENOENT');

    const outsideFile = path.join(fixtureRoot, 'outside.ydk');
    const siblingFile = path.join(siblingPath, 'sibling.ydk');
    const symlinkTarget = path.join(outsidePath, 'symlink-target.ydk');
    fs.writeFileSync(outsideFile, 'outside sentinel');
    fs.writeFileSync(siblingFile, 'sibling sentinel');
    fs.writeFileSync(symlinkTarget, 'symlink sentinel');
    fs.symlinkSync(outsidePath, path.join(deckPath, 'outside-link'), 'dir');

    const decodedTraversal = new URL('http://localhost/?msg=%2e%2e%2foutside.ydk').searchParams.get('msg');
    const attacks = [
      '',
      null,
      undefined,
      '.',
      '..',
      '../outside.ydk',
      'subdir/../../outside.ydk',
      '../decks-evil/sibling.ydk',
      '/etc/passwd',
      '\\etc\\passwd',
      '..\\outside.ydk',
      'subdir\\..\\outside.ydk',
      'C:\\Windows\\win.ini',
      'C:relative.ydk',
      '\\\\server\\share\\deck.ydk',
      'outside-link/symlink-target.ydk',
      'outside-link\\symlink-target.ydk',
      `nul\0byte.ydk`,
      decodedTraversal,
    ];

    for (const attack of attacks) {
      await assertInvalid(deckPath, attack);
      assert.strictEqual(fs.readFileSync(outsideFile, 'utf8'), 'outside sentinel');
      assert.strictEqual(fs.readFileSync(siblingFile, 'utf8'), 'sibling sentinel');
      assert.strictEqual(fs.readFileSync(symlinkTarget, 'utf8'), 'symlink sentinel');
    }

    const directLink = path.join(deckPath, 'direct-link.ydk');
    fs.symlinkSync(symlinkTarget, directLink, 'file');
    const directLinkResult = await deleteWithCallCount(deckPath, 'direct-link.ydk');
    assert.strictEqual(directLinkResult.error, null);
    assert.strictEqual(directLinkResult.callCount, 1);
    assert.strictEqual(fs.existsSync(directLink), false);
    assert.strictEqual(fs.readFileSync(symlinkTarget, 'utf8'), 'symlink sentinel');

    process.stdout.write('deck delete security tests passed\n');
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
