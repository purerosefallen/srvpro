isDuelPlayer = (client) ->
  return !!(client and Number.isInteger(client.pos) and client.pos >= 0 and client.pos <= 3)

getRoomSide = (client, mode) ->
  return if mode == 2 then (client.pos & 0x2) >> 1 else client.pos

inferSwapped = (client, mode) ->
  # client.pos is the fixed lobby side; is_first identifies game side 0.
  roomSide = getRoomSide(client, mode)
  gameSide = if client.is_first then 0 else 1
  return roomSide != gameSide

getWinnerSide = (msgPlayer, swapped) ->
  return msgPlayer unless msgPlayer == 0 or msgPlayer == 1
  return if swapped then 1 - msgPlayer else msgPlayer

class DuelFinalization
  constructor: (@room) ->
    @reset(0)

  reset: (duelCount) ->
    @duelCount = duelCount
    @swapped = null
    @winHandled = false
    @replayBuffer = null
    @replayPersisted = false
    @replayReady = new Promise (resolve) =>
      @resolveReplay = resolve
    return

  beginIfNeeded: (client, duelingStage, endStage) ->
    return false unless isDuelPlayer(client)
    return false if @room.duel_stage == duelingStage
    # A slow duplicate START may arrive after another client already handled WIN.
    # A real next duel passes through a pre-duel stage such as SIDING first.
    return false if @winHandled and @room.duel_stage == endStage
    @room.duel_stage = duelingStage
    @room.turn = 0
    @room.duel_count++
    @reset(@room.duel_count)
    @swapped = inferSwapped(client, @room.hostinfo.mode)
    return true

  handleWin: (client, msgPlayer, options) ->
    return {handled: false} unless isDuelPlayer(client)
    return {handled: false} unless @duelCount > 0 and @duelCount == @room.duel_count
    return {handled: false} if @winHandled

    pos = if @room.duel_stage == options.duelingStage and @swapped?
      getWinnerSide(msgPlayer, @swapped)
    else
      msgPlayer
    pos = pos * 2 if pos >= 0 and @room.hostinfo.mode == 2

    # Claim before invoking callbacks so another client cannot apply the same win.
    @winHandled = true
    @winner = pos

    if @room.recovering
      @room.finish_recover(true)
      return {handled: true, recovering: true, winner: pos}

    @room.winner = pos
    @room.turn = 0
    @room.duel_stage = options.endStage
    if options.heartbeatDetection
      for player in @room.players when player
        player.heartbeat_protected = false
      delete @room.long_resolve_card
      delete @room.long_resolve_chain

    if !@room.finished and @room.dueling_players[pos]
      @room.winner_name = @room.dueling_players[pos].name_vpass
      @room.scores[@room.winner_name] = @room.scores[@room.winner_name] + 1
      @room.wins = [] unless @room.wins
      @room.wins.push @room.winner_name
      if @room.match_kill
        @room.match_kill = false
        @room.scores[@room.winner_name] = 99
    else if !@room.finished and pos == 2
      @room.wins = [] unless @room.wins
      @room.wins.push ''

    if @room.death
      if options.quickDeathRule == 1 or options.quickDeathRule == 3
        @room.death = -1
      else
        @room.death = 5

    return {handled: true, recovering: false, winner: pos}

  handleMatchKill: (client) ->
    return false unless isDuelPlayer(client)
    return false unless @duelCount > 0 and @duelCount == @room.duel_count
    @room.match_kill = true
    return true

  captureReplay: (client, buffer) ->
    return false unless isDuelPlayer(client)
    return false unless @duelCount > 0 and @duelCount == @room.duel_count
    return false if @replayBuffer or @room.replays[@duelCount - 1]
    @replayBuffer = buffer
    @room.replays[@duelCount - 1] = buffer
    @resolveReplay?(true)
    return true

  takeReplayForPersistence: (allowWithoutWin = false) ->
    return null if @replayPersisted or !@replayBuffer
    return null unless @winHandled or allowWithoutWin
    @replayPersisted = true
    return @replayBuffer

  waitForReplay: (timeoutMs) ->
    return Promise.resolve(true) if @replayBuffer
    return new Promise (resolve) =>
      settled = false
      finish = (captured) ->
        return if settled
        settled = true
        clearTimeout(timer)
        resolve(captured)
      timer = setTimeout((-> finish(false)), timeoutMs)
      @replayReady.then(-> finish(true))

  snapshot: ->
    return {
      duelCount: @duelCount
      swapped: @swapped
      winHandled: @winHandled
      replayCaptured: !!@replayBuffer
      replayPersisted: @replayPersisted
    }

module.exports = {
  DuelFinalization
  isDuelPlayer
  getRoomSide
  inferSwapped
  getWinnerSide
}
