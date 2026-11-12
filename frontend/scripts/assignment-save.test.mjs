import assert from 'node:assert/strict';
import test from 'node:test';

globalThis.window = {}; // api.ts normally loads inside the Wails window
const { cleanSettings } = await import('../src/api.ts');

test('saving as the main changes B → C → B preserves literal assignments', () => {
  let settings = {
    rules: [
      { name: 'Inherited', action: 'tunnel', fallback: ['C', 'D'] },
      { name: 'Pinned', action: 'tunnel', profile: 'B', fallback: ['', 'B', 'C', 'C'] },
    ],
    defaultAction: 'tunnel',
    defaultFallback: ['C', 'D'],
  };
  for (const main of ['B', 'C', 'B']) {
    settings = JSON.parse(JSON.stringify(cleanSettings(settings, main)));
    assert.equal(settings.rules[0].profile, undefined);
    assert.deepEqual(settings.rules[0].fallback, ['C', 'D']);
    assert.equal(settings.rules[1].profile, 'B');
    assert.deepEqual(settings.rules[1].fallback, ['', 'C']);
    assert.deepEqual(settings.defaultFallback, ['C', 'D']);
  }
});
