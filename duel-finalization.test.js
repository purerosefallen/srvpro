'use strict';

const assert = require('assert');
const {
  DuelFinalization,
  getRoomSide,
  getWinnerSide,
  inferSwapped,
  isDuelPlayer,
} = require('./duel-finalization.js');

const STAGE = {
  BEGIN: 0,
  DUELING: 1,
  END: 2,
  SIDING: 3,
};

const OPTIONS = {
  duelingStage: STAGE.DUELING,
  endStage: STAGE.END,
  heartbeatDetection: true,
  quickDeathRule: 0,
};

function player(pos, name, isFirst) {
  return {
    pos,
    name,
    name_vpass: name,
    is_first: isFirst,
    heartbeat_protected: true,
  };
}

function room(mode = 1) {
  const players = mode === 2
    ? [
      player(0, 'p0', true),
      player(1, 'p1', true),
      player(2, 'p2', false),
      player(3, 'p3', false),
    ]
    : [player(0, 'p0', true), player(1, 'p1', false)];
  const scores = {};
  players.forEach((entry) => {
    scores[entry.name_vpass] = 0;
  });
  const value = {
    hostinfo: { mode },
    players,
    dueling_players: players,
    scores,
    replays: [],
    duel_count: 0,
    duel_stage: STAGE.BEGIN,
    turn: 0,
    death: 0,
  };
  value.duel_finalization = new DuelFinalization(value);
  return value;
}

function begin(value, source) {
  return value.duel_finalization.beginIfNeeded(source, STAGE.DUELING, STAGE.END);
}

function win(value, source, msgWinner) {
  return value.duel_finalization.handleWin(source, msgWinner, OPTIONS);
}

function applyGframeStart(value, swapped) {
  const isFirstByPos = value.hostinfo.mode === 2
    ? (swapped ? [false, false, true, true] : [true, true, false, false])
    : (swapped ? [false, true] : [true, false]);
  value.players.forEach((entry, pos) => {
    entry.is_first = isFirstByPos[pos];
  });
}

function persistOnce(value, counter, allowWithoutWin = false) {
  const replay = value.duel_finalization.takeReplayForPersistence(allowWithoutWin);
  if (replay) {
    counter.count += 1;
  }
  return replay;
}

async function testPos1TakesOverThirdDuel() {
  const value = room();
  value.duel_count = 2;
  value.duel_stage = STAGE.END;
  value.scores.p0 = 1;
  value.scores.p1 = 1;

  assert.strictEqual(begin(value, value.players[1]), true);
  assert.strictEqual(value.duel_count, 3);
  const result = win(value, value.players[1], 1);
  assert.deepStrictEqual(result, { handled: true, recovering: false, winner: 1 });
  assert.strictEqual(value.scores.p1, 2);
  assert.deepStrictEqual(value.wins, ['p1']);

  const replay = Buffer.from('third-duel');
  assert.strictEqual(value.duel_finalization.captureReplay(value.players[1], replay), true);
  assert.strictEqual(value.replays[2], replay);
  const counter = { count: 0 };
  assert.strictEqual(persistOnce(value, counter), replay);
  assert.strictEqual(persistOnce(value, counter), null);
  assert.strictEqual(counter.count, 1);

  const startedAt = Date.now();
  assert.strictEqual(await value.duel_finalization.waitForReplay(5000), true);
  assert.ok(Date.now() - startedAt < 100, 'captured replay should not wait for pos0');
}

function testSwappedInferenceMatchesGframeStart() {
  for (const mode of [1, 2]) {
    for (const swapped of [false, true]) {
      const value = room(mode);
      applyGframeStart(value, swapped);
      value.players.forEach((entry) => {
        assert.strictEqual(inferSwapped(entry, mode), swapped);
      });
      if (mode === 2) {
        assert.strictEqual(value.players[0].is_first, value.players[1].is_first);
        assert.strictEqual(value.players[2].is_first, value.players[3].is_first);
        assert.notStrictEqual(value.players[0].is_first, value.players[2].is_first);
      }
    }
  }
}

function testWinnerMappingForEveryGframeReceiver() {
  for (const mode of [1, 2]) {
    const positions = mode === 2 ? [0, 1, 2, 3] : [0, 1];
    for (const swapped of [false, true]) {
      for (const sourcePos of positions) {
        for (const msgWinner of [0, 1]) {
          const value = room(mode);
          applyGframeStart(value, swapped);
          begin(value, value.players[sourcePos]);

          const winnerSide = swapped ? 1 - msgWinner : msgWinner;
          const winnerPos = mode === 2 ? winnerSide * 2 : winnerSide;
          const expectedRoomSides = mode === 2 ? [0, 0, 1, 1] : [0, 1];
          assert.strictEqual(getRoomSide(value.players[sourcePos], mode), expectedRoomSides[sourcePos]);
          assert.strictEqual(value.duel_finalization.swapped, swapped);
          assert.strictEqual(getWinnerSide(msgWinner, swapped), winnerSide);

          const first = win(value, value.players[sourcePos], msgWinner);
          const duplicatePos = positions.find((pos) => pos !== sourcePos);
          const duplicate = win(value, value.players[duplicatePos], msgWinner);
          assert.strictEqual(first.handled, true);
          assert.strictEqual(first.winner, winnerPos);
          assert.strictEqual(duplicate.handled, false);
          assert.strictEqual(value.scores[`p${winnerPos}`], 1);
          assert.deepStrictEqual(value.wins, [`p${winnerPos}`]);
        }
      }
    }
  }
}

function testLateDuplicateStartDoesNotCreateAnotherDuel() {
  const value = room();
  assert.strictEqual(begin(value, value.players[0]), true);
  win(value, value.players[0], 0);
  assert.strictEqual(value.duel_stage, STAGE.END);
  assert.strictEqual(begin(value, value.players[1]), false);
  assert.strictEqual(value.duel_count, 1);
}

function testNormalThreeDuelMatch() {
  const value = room();
  const persistence = { count: 0 };

  assert.strictEqual(begin(value, value.players[0]), true);
  win(value, value.players[0], 0);
  value.duel_finalization.captureReplay(value.players[0], Buffer.from('duel-1'));
  persistOnce(value, persistence);

  value.duel_stage = STAGE.SIDING;
  applyGframeStart(value, true);
  assert.strictEqual(begin(value, value.players[1]), true);
  win(value, value.players[1], 0);
  value.duel_finalization.captureReplay(value.players[1], Buffer.from('duel-2'));
  persistOnce(value, persistence);

  value.duel_stage = STAGE.SIDING;
  applyGframeStart(value, false);
  assert.strictEqual(begin(value, value.players[0]), true);
  win(value, value.players[0], 0);
  value.duel_finalization.captureReplay(value.players[0], Buffer.from('duel-3'));
  persistOnce(value, persistence);

  assert.strictEqual(value.duel_count, 3);
  assert.deepStrictEqual(value.scores, { p0: 2, p1: 1 });
  assert.deepStrictEqual(value.wins, ['p0', 'p1', 'p0']);
  assert.strictEqual(value.replays.length, 3);
  assert.strictEqual(persistence.count, 3);
}

function testReplayBeforeWinDefersPersistence() {
  const value = room();
  begin(value, value.players[1]);
  const replay = Buffer.from('early-replay');
  assert.strictEqual(value.duel_finalization.captureReplay(value.players[1], replay), true);
  assert.strictEqual(value.duel_finalization.takeReplayForPersistence(), null);
  win(value, value.players[1], 0);
  assert.strictEqual(value.duel_finalization.takeReplayForPersistence(), replay);
}

function testDrawIsRecordedOnce() {
  const value = room();
  begin(value, value.players[1]);
  assert.strictEqual(win(value, value.players[1], 2).winner, 2);
  assert.deepStrictEqual(value.wins, ['']);
  assert.strictEqual(win(value, value.players[0], 2).handled, false);
  assert.deepStrictEqual(value.scores, { p0: 0, p1: 0 });
}

function testMatchKillCanBeObservedByPos1() {
  const value = room();
  begin(value, value.players[1]);
  assert.strictEqual(value.duel_finalization.handleMatchKill(value.players[1]), true);
  win(value, value.players[1], 1);
  assert.strictEqual(value.scores.p1, 99);
  assert.strictEqual(value.match_kill, false);
}

function testFinishedPenaltyIsPreserved() {
  const value = room();
  begin(value, value.players[1]);
  value.finished = true;
  value.scores.p0 = -9;
  const result = win(value, value.players[1], 1);
  assert.strictEqual(result.handled, true);
  assert.strictEqual(value.winner, 1);
  assert.deepStrictEqual(value.scores, { p0: -9, p1: 0 });
  assert.strictEqual(value.wins, undefined);
}

function testCrashReplayCanPersistWithoutWin() {
  const value = room();
  begin(value, value.players[0]);
  value.has_ygopro_error = true;
  const replay = Buffer.from('crash-replay');
  assert.strictEqual(value.duel_finalization.captureReplay(value.players[1], replay), true);
  assert.strictEqual(value.duel_finalization.takeReplayForPersistence(true), replay);
  assert.strictEqual(value.duel_finalization.takeReplayForPersistence(true), null);
}

function testRecoveryFailureIsHandledOnce() {
  const value = room();
  let recoveryFailures = 0;
  value.recovering = true;
  value.finish_recover = (failed) => {
    assert.strictEqual(failed, true);
    recoveryFailures += 1;
  };
  begin(value, value.players[1]);
  const first = win(value, value.players[1], 1);
  const duplicate = win(value, value.players[0], 1);
  assert.deepStrictEqual(first, { handled: true, recovering: true, winner: 1 });
  assert.strictEqual(duplicate.handled, false);
  assert.strictEqual(recoveryFailures, 1);
}

function testStartAndReplaySourcesAreRestricted() {
  const value = room();
  const observer = player(7, 'observer', false);
  assert.strictEqual(isDuelPlayer(observer), false);
  assert.strictEqual(begin(value, observer), false);
  assert.strictEqual(value.duel_count, 0);
  assert.strictEqual(begin(value, value.players[1]), true);
  assert.strictEqual(begin(value, value.players[0]), false);
  assert.strictEqual(value.duel_count, 1);
  assert.strictEqual(value.duel_finalization.captureReplay(observer, Buffer.from('observer')), false);
}

async function testMissingReplayTimesOut() {
  const value = room();
  begin(value, value.players[0]);
  assert.strictEqual(await value.duel_finalization.waitForReplay(10), false);
  assert.deepStrictEqual(value.duel_finalization.snapshot(), {
    duelCount: 1,
    swapped: false,
    winHandled: false,
    replayCaptured: false,
    replayPersisted: false,
  });
}

async function main() {
  await testPos1TakesOverThirdDuel();
  testSwappedInferenceMatchesGframeStart();
  testWinnerMappingForEveryGframeReceiver();
  testLateDuplicateStartDoesNotCreateAnotherDuel();
  testNormalThreeDuelMatch();
  testReplayBeforeWinDefersPersistence();
  testDrawIsRecordedOnce();
  testMatchKillCanBeObservedByPos1();
  testFinishedPenaltyIsPreserved();
  testCrashReplayCanPersistWithoutWin();
  testRecoveryFailureIsHandledOnce();
  testStartAndReplaySourcesAreRestricted();
  await testMissingReplayTimesOut();
  process.stdout.write('duel finalization tests passed\n');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
