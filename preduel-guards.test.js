'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const coffee = require('coffeescript');
const YGOProMsg = require('ygopro-msg-encode');

const source = fs.readFileSync(require.resolve('./ygopro-server.coffee'), 'utf8');
function definition(prefix) {
  const start = source.indexOf(prefix);
  assert.notEqual(start, -1, prefix);
  const tail = source.slice(start);
  return tail.split(/\n(?=[a-z#])/i, 1)[0];
}

const ctos = new Map();
const stoc = new Map();
const sent = [];
const notices = [];
const DUEL_STAGE = { BEGIN: 0, FINGER: 1, FIRSTGO: 2, SIDING: 3 };
const context = {
  ROOM_all: [],
  YGOProMsg,
  ygopro: {
    constants: { DUEL_STAGE, COLORS: {} },
    ctos_follow(proto, waits, callback) {
      assert.equal(waits, true, proto);
      ctos.set(proto, callback);
    },
    stoc_follow: (proto, _waits, callback) => stoc.set(proto, callback),
    stoc_send: (_client, proto) => sent.push(proto),
    ctos_send: (_server, proto, info) => sent.push([proto, info.res]),
    stoc_send_chat() {},
    stoc_send_chat_to_room: (_room, msg) => notices.push(msg),
  },
  settings: { modules: { challonge: { enabled: false } } },
};
context.global = context;
vm.createContext(context);
vm.runInContext(
  coffee.compile(
    [
      'import_datas =',
      'CLIENT_import_data =',
      'CLIENT_send_reconnect_info =',
      "ygopro.ctos_follow 'HAND_RESULT'",
      "ygopro.ctos_follow 'TP_RESULT'",
      "ygopro.ctos_follow 'HS_KICK'",
      "ygopro.stoc_follow 'SELECT_HAND'",
      "ygopro.stoc_follow 'SELECT_TP'",
    ].map(definition).join('\n\n'),
    { bare: true },
  ),
  context,
);

async function verify() {
  const first = { pos: 0, rid: 0, is_host: true };
  const second = { pos: 1, rid: 0, is_host: false };
  const room = {
    duel_stage: DUEL_STAGE.FINGER,
    random_type: 'S',
    hostinfo: { mode: 0 },
    players: [first, second],
    dueling_players: [first, second],
    activeUpdates: 0,
    refreshLastActiveTime() { this.activeUpdates++; },
  };
  context.ROOM_all[0] = room;
  const hand = { res: YGOProMsg.HandResult.PAPER };
  const tp = { res: YGOProMsg.TurnPlayerResult.SECOND };
  const request = (name, client) => stoc.get(name)(null, {}, client, {});
  const respond = (name, info, client) => ctos.get(name)(null, info, client, {});

  assert.equal(await respond('HAND_RESULT', hand, first), true);
  assert.equal(room.activeUpdates, 0);
  await request('SELECT_HAND', first);
  await request('SELECT_HAND', second);
  assert.equal(await respond('HAND_RESULT', {}, first), true);
  assert.equal(room.activeUpdates, 2);
  assert.equal(first.selected_preduel, false);
  assert.equal(await respond('HAND_RESULT', hand, first), false);
  assert.equal(await respond('HAND_RESULT', hand, second), false);
  assert.equal(await respond('HAND_RESULT', hand, first), true);
  assert.equal(room.activeUpdates, 4);

  await request('SELECT_HAND', first);
  assert.equal(await respond('HAND_RESULT', hand, first), false);
  room.hostinfo.mode = 2;
  assert.equal(await respond('HAND_RESULT', hand, second), true);
  const tagCaptain = { pos: 2, rid: 0 };
  room.players.push(tagCaptain);
  await request('SELECT_HAND', tagCaptain);
  assert.equal(await respond('HAND_RESULT', hand, tagCaptain), false);

  await request('SELECT_TP', first);
  const replacement = {};
  context.CLIENT_import_data(replacement, first, room);
  await context.CLIENT_send_reconnect_info(replacement, {}, room);
  assert.deepEqual(sent.splice(0), ['DUEL_START', 'SELECT_TP']);
  assert.equal(await respond('TP_RESULT', tp, first), true);
  assert.equal(await respond('TP_RESULT', tp, replacement), false);
  assert.equal(await respond('TP_RESULT', tp, replacement), true);
  await context.CLIENT_send_reconnect_info(replacement, {}, room);
  assert.deepEqual(sent.splice(0), ['DUEL_START']);

  room.determine_firstgo = replacement;
  assert.equal(await request('SELECT_HAND', replacement), true);
  assert.equal(await request('SELECT_TP', replacement), true);
  assert.deepEqual(sent.splice(0), [
    ['HAND_RESULT', YGOProMsg.HandResult.SCISSORS],
    ['TP_RESULT', YGOProMsg.TurnPlayerResult.FIRST],
  ]);
  assert.equal(replacement.pending_preduel, undefined);

  assert.equal(await respond('HS_KICK', { pos: 1 }, replacement), true);
  room.duel_stage = DUEL_STAGE.BEGIN;
  assert.equal(await respond('HS_KICK', { pos: 0 }, second), true);
  assert.equal(await respond('HS_KICK', { pos: 0 }, replacement), true);
  assert.equal(await respond('HS_KICK', { pos: 3 }, replacement), true);
  room.hostinfo.mode = 0;
  assert.equal(await respond('HS_KICK', { pos: 2 }, replacement), true);
  assert.equal(notices.length, 0);
  assert.equal(replacement.kick_count, undefined);
  assert.equal(await respond('HS_KICK', { pos: 1 }, replacement), false);
  assert.equal(notices.length, 1);
  assert.equal(replacement.kick_count, 1);
}

verify().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
