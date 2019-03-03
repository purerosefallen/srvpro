# 标准库
net = require 'net'
http = require 'http'
url = require 'url'
path = require 'path'
fs = require 'fs'
os = require 'os'
crypto = require 'crypto'
exec = require('child_process').exec
execFile = require('child_process').execFile
spawn = require('child_process').spawn
spawnSync = require('child_process').spawnSync

# 三方库
_ = require 'underscore'
_.str = require 'underscore.string'
_.mixin(_.str.exports())

request = require 'request'

bunyan = require 'bunyan'
log = bunyan.createLogger name: "mycard"

moment = require 'moment'
moment.locale('zh-cn', {
  relativeTime: {
    future: '%s内',
    past: '%s前',
    s: '%d秒',
    m: '1分钟',
    mm: '%d分钟',
    h: '1小时',
    hh: '%d小时',
    d: '1天',
    dd: '%d天',
    M: '1个月',
    MM: '%d个月',
    y: '1年',
    yy: '%d年'
  }
})

import_datas = [
  "abuse_count",
  "ban_mc",
  "vip",
  "is_using_pre_release",
  "vpass",
  "rag",
  "rid",
  "is_post_watcher",
  "retry_count",
  "name",
  "pass",
  "name_vpass",
  "is_first",
  "lp",
  "card_count",
  "is_host",
  "pos",
  "surrend_confirm",
  "kick_count",
  "deck_saved",
  "main",
  "side",
  "side_interval",
  "side_tcount",
  "selected_preduel",
  "last_game_msg",
  "last_game_msg_title",
  "last_hint_msg",
  "start_deckbuf",
  "challonge_info",
  "ready_trap",
  "replays_sent"
]

merge = require 'deepmerge'

loadJSON = require('load-json-file').sync

#heapdump = require 'heapdump'

# 配置
# 导入旧配置
if not fs.existsSync('./config')
  fs.mkdirSync('./config')
try
  oldconfig=loadJSON('./config.user.json')
  if oldconfig.tips
    oldtips = {}
    oldtips.file = './config/tips.json'
    oldtips.tips = oldconfig.tips
    oldtips.tips_zh = []
    fs.writeFileSync(oldtips.file, JSON.stringify(oldtips, null, 2))
    delete oldconfig.tips
  if oldconfig.words
    oldwords = {}
    oldwords.file = './config/words.json'
    oldwords.words = oldconfig.words
    fs.writeFileSync(oldwords.file, JSON.stringify(oldwords, null, 2))
    delete oldconfig.words
  if oldconfig.dialogues
    olddialogues = {}
    olddialogues.file = './config/dialogues.json'
    olddialogues.dialogues = oldconfig.dialogues
    olddialogues.dialogues_custom = {}
    fs.writeFileSync(olddialogues.file, JSON.stringify(olddialogues, null, 2))
    delete oldconfig.dialogues
  if oldconfig.modules
    if oldconfig.modules.tournament_mode and oldconfig.modules.tournament_mode.duel_log
      oldduellog = {}
      oldduellog.file = './config/duel_log.json'
      oldduellog.duel_log = oldconfig.modules.tournament_mode.duel_log
      fs.writeFileSync(oldduellog.file, JSON.stringify(oldduellog, null, 2))
      delete oldconfig.oldduellog
  oldbadwords={}
  if oldconfig.ban
    if oldconfig.ban.badword_level0
      oldbadwords.level0 = oldconfig.ban.badword_level0
    if oldconfig.ban.badword_level1
      oldbadwords.level1 = oldconfig.ban.badword_level1
    if oldconfig.ban.badword_level2
      oldbadwords.level2 = oldconfig.ban.badword_level2
    if oldconfig.ban.badword_level3
      oldbadwords.level3 = oldconfig.ban.badword_level3
  if not _.isEmpty(oldbadwords)
    oldbadwords.file = './config/badwords.json'
    fs.writeFileSync(oldbadwords.file, JSON.stringify(oldbadwords, null, 2))
    delete oldconfig.ban.badword_level0
    delete oldconfig.ban.badword_level1
    delete oldconfig.ban.badword_level2
    delete oldconfig.ban.badword_level3
  if not _.isEmpty(oldconfig)
    # log.info oldconfig
    fs.writeFileSync('./config/config.json', JSON.stringify(oldconfig, null, 2))
    log.info 'imported old config from config.user.json'
  fs.renameSync('./config.user.json', './config.user.bak')
catch e
  log.info e unless e.code == 'ENOENT'

setting_save = (settings) ->
  fs.writeFileSync(settings.file, JSON.stringify(settings, null, 2))
  return

setting_change = (settings, path, val) ->
  # path should be like "modules:welcome"
  log.info("setting changed", path, val) if _.isString(val)
  path=path.split(':')
  if path.length == 0
    settings[path[0]]=val
  else
    target=settings
    while path.length > 1
      key=path.shift()
      target=target[key]
    key = path.shift()
    target[key] = val
  setting_save(settings)
  return

VIP_generate_cdkeys = (key_type, count) ->
  return false unless settings.modules.vip.enabled and vip_info.cdkeys[key_type]
  for i in [0...count]
    key = Math.floor(Math.random() * 10000000000000000).toString()
    vip_info.cdkeys[key_type].push(key)
  setting_save(vip_info)
  log.info("keys generated", key_type, count, vip_info.cdkeys[key_type].length)
  return true

CLIENT_use_cdkey = (client, pkey) ->
  return 0 unless settings.modules.vip.enabled and pkey
  found_type = null
  for type,keys of vip_info.cdkeys
    for key in keys when pkey == key or pkey == (type + "D" + settings.port + ":" + key) # support web given format
      found_type = parseInt(type)
      index = _.indexOf(keys, key)
      keys.splice(index, 1) unless index == -1
      break
    if found_type
      break
  if !found_type
    return 0
  if !vip_info.cdkeys[found_type].length
    VIP_generate_cdkeys(found_type, settings.modules.vip.generate_count)
  client.vip = true
  new_vip = false
  if vip_info.players[client.name]
    current_date = moment()
    if current_date.isSameOrBefore(vip_info.players[client.name].expire_date)
      current_date = moment(vip_info.players[client.name].expire_date, 'YYYY-MM-DD HH:mm:ss')
    vip_info.players[client.name].expire_date = current_date.add(found_type, 'd').format('YYYY-MM-DD HH:mm:ss')
  else
    if !client.vpass
      client.vpass = Math.floor(Math.random() * 100000).toString()
    vip_info.players[client.name] = {
      password: client.vpass,
      expire_date: moment().add(found_type, 'd').format('YYYY-MM-DD HH:mm:ss'),
      dialogues: {}
    }
    new_vip = true
  setting_save(vip_info)
  return (if new_vip then 1 else 2)

CLIENT_check_vip = (client) ->
  if !settings.modules.vip.enabled
    return false
  if !vip_info.players[client.name]
    return false
   if vip_info.players[client.name].password != client.vpass
    return false
  return moment().isSameOrBefore(vip_info.players[client.name].expire_date)

CLIENT_send_vip_status = (client, display) ->
  if !settings.modules.vip.enabled
    return false
  if client.vip
    if display
      ygopro.stoc_send_chat(client, "${vip_remain_part1}" + vip_info.players[client.name].expire_date + "${vip_remain_part2}", ygopro.constants.COLORS.BABYBLUE)
    else
      ygopro.stoc_send_chat(client,"${vip_remain}" , ygopro.constants.COLORS.BABYBLUE)
  else if !vip_info.players[client.name] or vip_info.players[client.name].password != client.vpass
    ygopro.stoc_send_chat(client,"${vip_not_bought}" , ygopro.constants.COLORS.RED)
  else
    ygopro.stoc_send_chat(client, "${vip_expired_part1}" + vip_info.players[client.name].expire_date + "${vip_expired_part2}", ygopro.constants.COLORS.RED)

concat_name = (name, num) ->
  if !name[num]
    return null
  res = name[num]
  temp = null
  count = num + 1
  while true
    temp = name[count]
    if !temp
      break
    res = res + " " + temp
    count++
  return res

# 读取配置
default_config = loadJSON('./data/default_config.json')
try
  config = loadJSON('./config/config.json')
catch
  config = {}
settings = global.settings = merge(default_config, config, { arrayMerge: (destination, source) -> source })

auth = require './ygopro-auth.js'

#import old configs
imported = false
#reset http.quick_death_rule from true to 1
if settings.modules.http.quick_death_rule == true
  settings.modules.http.quick_death_rule = 1
  imported = true
#import the old redis port
if settings.modules.cloud_replay.redis_port
  settings.modules.cloud_replay.redis.port = settings.modules.cloud_replay.redis_port
  delete settings.modules.cloud_replay.redis_port
  imported = true
#import the old passwords to new admin user system
if settings.modules.http.password
  auth.add_user("olduser", settings.modules.http.password, true, {
        "get_rooms": true,
        "shout": true,
        "stop": true,
        "change_settings": true,
        "ban_user": true,
        "kick_user": true,
        "start_death": true
  })
  delete settings.modules.http.password
  imported = true
if settings.modules.tournament_mode.password
  auth.add_user("tournament", settings.modules.tournament_mode.password, true, {
        "duel_log": true,
        "download_replay": true,
        "clear_duel_log": true,
        "deck_dashboard_read": true,
        "deck_dashboard_write": true,
  })
  delete settings.modules.tournament_mode.password
  imported = true
if settings.modules.pre_util.password
  auth.add_user("pre", settings.modules.pre_util.password, true, {
        "pre_dashboard": true
  })
  delete settings.modules.pre_util.password
  imported = true
if settings.modules.update_util.password
  auth.add_user("update", settings.modules.update_util.password, true, {
        "update_dashboard": true
  })
  delete settings.modules.update_util.password
  imported = true
#finish
if imported
  setting_save(settings)

# 读取数据
default_data = loadJSON('./data/default_data.json')
try
  tips = loadJSON('./config/tips.json')
  if !tips.tips_zh
    tips.tips_zh = []
    setting_save(tips);
catch
  tips = default_data.tips
  setting_save(tips)
try
  words = loadJSON('./config/words.json')
catch
  words = default_data.words
  setting_save(words)
try
  dialogues = loadJSON('./config/dialogues.json')
  if !dialogues.dialogues_custom
    dialogues.dialogues_custom = {}
    setting_save(dialogues);
catch
  dialogues = default_data.dialogues
  setting_save(dialogues)
try
  badwords = loadJSON('./config/badwords.json')
catch
  badwords = default_data.badwords
  setting_save(badwords)
try
  duel_log = loadJSON('./config/duel_log.json')
catch
  duel_log = default_data.duel_log
  setting_save(duel_log)
try
  chat_color = loadJSON('./config/chat_color.json')
catch
  chat_color = default_data.chat_color
  setting_save(chat_color)
try
  vip_info = loadJSON('./config/vip_info.json')
catch
  vip_info = default_data.vip_info
  setting_save(vip_info)

try
  cppversion = parseInt(fs.readFileSync('ygopro/gframe/game.cpp', 'utf8').match(/PRO_VERSION = ([x\dABCDEF]+)/)[1], '16')
  setting_change(settings, "version", cppversion)
  log.info "ygopro version 0x"+settings.version.toString(16), "(from source code)"
catch
  #settings.version = settings.version_default
  log.info "ygopro version 0x"+settings.version.toString(16), "(from config)"
# load the lflist of current date
lflists = []
# expansions/lflist
try
  for list in fs.readFileSync('ygopro/expansions/lflist.conf', 'utf8').match(/!.*/g)
    date=list.match(/!([\d\.]+)/)
    continue unless date
    lflists.push({date: moment(list.match(/!([\d\.]+)/)[1], 'YYYY.MM.DD').utcOffset("-08:00"), tcg: list.indexOf('TCG') != -1})
catch
# lflist
try
  for list in fs.readFileSync('ygopro/lflist.conf', 'utf8').match(/!.*/g)
    date=list.match(/!([\d\.]+)/)
    continue unless date
    lflists.push({date: moment(list.match(/!([\d\.]+)/)[1], 'YYYY.MM.DD').utcOffset("-08:00"), tcg: list.indexOf('TCG') != -1})
catch

if settings.modules.cloud_replay.enabled
  redis = require 'redis'
  zlib = require 'zlib'
  redisdb = redis.createClient(settings.modules.cloud_replay.redis)
  redisdb.on 'error', (err)->
    log.warn err
    return

if settings.modules.windbot.enabled
  windbots = loadJSON(settings.modules.windbot.botlist).windbots

if settings.modules.heartbeat_detection.enabled
  long_resolve_cards = loadJSON('./data/long_resolve_cards.json')

if settings.modules.pre_release_compat.enabled
  sqlite3 = require('sqlite3').verbose()

# 组件
ygopro = require './ygopro.js'
roomlist = require './roomlist.js' if settings.modules.http.websocket_roomlist

if settings.modules.i18n.auto_pick
  geoip = require('geoip-country-lite')

# cache users of mycard login
users_cache = {}

if settings.modules.mycard.enabled
  pgClient = require('pg').Client
  pg_client = new pgClient(settings.modules.mycard.auth_database)
  pg_client.on 'error', (err) ->
    log.warn "PostgreSQL ERROR: ", err
    return
  pg_query = pg_client.query('SELECT username, id from users')
  pg_query.on 'error', (err) ->
    log.warn "PostgreSQL Query ERROR: ", err
    return
  pg_query.on 'row', (row) ->
    #log.info "load user", row.username, row.id
    users_cache[row.username] = row.id
    return
  pg_query.on 'end', (result) ->
    log.info "users loaded", result.rowCount
    return
  pg_client.on 'drain', pg_client.end.bind(pg_client)
  log.info "loading mycard user..."
  pg_client.connect()

if settings.modules.challonge.enabled
  challonge_module_name = 'challonge'
  if settings.modules.challonge.use_custom_module
    challonge_module_name = settings.modules.challonge.use_custom_module
  challonge = require(challonge_module_name).createClient({
    apiKey: settings.modules.challonge.api_key
  })
  if settings.modules.challonge.cache_ttl
    challonge_cache = []
  challonge_queue_callbacks = [[], []]
  is_requesting = [null, null]
  get_callback = (challonge_type, _callback) ->
    return ((err, data) ->
      if settings.modules.challonge.cache_ttl and !err and data
        challonge_cache[challonge_type] = data
      is_requesting[challonge_type] =null
      _callback(err, data)
      while challonge_queue_callbacks[challonge_type].length
        cur_callback = challonge_queue_callbacks[challonge_type].splice(0, 1)[0]
        cur_callback(err, data)
      return
    )
  challonge.participants._index = (_data) ->
    if settings.modules.challonge.cache_ttl and challonge_cache[0]
      _data.callback(null, challonge_cache[0])
    else if is_requesting[0] and moment() - is_requesting[0] <= 5000
      challonge_queue_callbacks[0].push(_data.callback)
    else
      _data.callback = get_callback(0, _data.callback)
      is_requesting[0] = moment()
      try
        challonge.participants.index(_data)
      catch err
        _data.callback(err, null)
    return 
  challonge.matches._index = (_data) ->
    if settings.modules.challonge.cache_ttl and challonge_cache[1]
      _data.callback(null, challonge_cache[1])
    else if is_requesting[1] and moment() - is_requesting[1] <= 5000
      challonge_queue_callbacks[1].push(_data.callback)
    else
      _data.callback = get_callback(1, _data.callback)
      is_requesting[1] = moment()
      try
        challonge.matches.index(_data)
      catch err
        _data.callback(err, null)
    return
  challonge.matches._update = (_data) ->
    try
      challonge.matches.update(_data)
    catch err
      log.warn("Errored pushing scores to Challonge.", err)
    return
  refresh_challonge_cache = () ->
    if settings.modules.challonge.cache_ttl
      challonge_cache[0] = null
      challonge_cache[1] = null
    return
  refresh_challonge_cache()
  # challonge.participants._index({
  #   id: settings.modules.challonge.tournament_id,
  #   callback: (() ->
  #     challonge.matches._index({
  #       id: settings.modules.challonge.tournament_id,
  #       callback: (() ->
  #         return
  #       )
  #     })
  #     return
  #   )
  # })
  if settings.modules.challonge.cache_ttl
    setInterval(refresh_challonge_cache, settings.modules.challonge.cache_ttl)

if settings.modules.vip.enabled
  for k,v of vip_info.cdkeys when v.length == 0
    VIP_generate_cdkeys(k, settings.modules.vip.generate_count)

# 获取可用内存
memory_usage = 0
get_memory_usage = ()->
  prc_free = exec("free")
  prc_free.stdout.on 'data', (data)->
    lines = data.toString().split(/\n/g)
    line = lines[0].split(/\s+/)
    new_free = if line[6] == 'available' then true else false
    line = lines[1].split(/\s+/)
    total = parseInt(line[1], 10)
    free = parseInt(line[3], 10)
    buffers = parseInt(line[5], 10)
    if new_free
      actualFree = parseInt(line[6], 10)
    else
      cached = parseInt(line[6], 10)
      actualFree = free + buffers + cached
    percentUsed = parseFloat(((1 - (actualFree / total)) * 100).toFixed(2))
    memory_usage = percentUsed
    return
  return
get_memory_usage()
setInterval(get_memory_usage, 3000)

Cloud_replay_ids = []

ROOM_all = []
ROOM_players_oppentlist = {}
ROOM_players_banned = []
ROOM_players_scores = {}
ROOM_connected_ip = {}
ROOM_bad_ip = {}

# ban a user manually and permanently
ban_user = (name) ->
  settings.ban.banned_user.push(name)
  setting_save(settings)
  bad_ip=0
  for room in ROOM_all when room and room.established
    for player in room.players
      if player and (player.name == name or player.ip == bad_ip)
        bad_ip = player.ip
        ROOM_bad_ip[bad_ip]=99
        settings.ban.banned_ip.push(player.ip)
        ygopro.stoc_send_chat_to_room(room, "#{player.name} ${kicked_by_system}", ygopro.constants.COLORS.RED)
        CLIENT_send_replays(player, room)
        CLIENT_kick(player)
        continue
  return

# automatically ban user to use random duel
ROOM_ban_player = (name, ip, reason, countadd = 1)->
  return if settings.modules.test_mode.no_ban_player
  bannedplayer = _.find ROOM_players_banned, (bannedplayer)->
    ip == bannedplayer.ip
  if bannedplayer
    bannedplayer.count = bannedplayer.count + countadd
    bantime = if bannedplayer.count > 3 then Math.pow(2, bannedplayer.count - 3) * 2 else 0
    bannedplayer.time = if moment() < bannedplayer.time then moment(bannedplayer.time).add(bantime, 'm') else moment().add(bantime, 'm')
    bannedplayer.reasons.push(reason) if not _.find bannedplayer.reasons, (bannedreason)->
      bannedreason == reason
    bannedplayer.need_tip = true
  else
    bannedplayer = {"ip": ip, "time": moment(), "count": countadd, "reasons": [reason], "need_tip": true}
    ROOM_players_banned.push(bannedplayer)
  #log.info("banned", name, ip, reason, bannedplayer.count)
  return

ROOM_player_win = (name)->
  if !ROOM_players_scores[name]
    ROOM_players_scores[name]={win:0, lose:0, flee:0, combo:0}
  ROOM_players_scores[name].win = ROOM_players_scores[name].win + 1
  ROOM_players_scores[name].combo = ROOM_players_scores[name].combo + 1
  return

ROOM_player_lose = (name)->
  if !ROOM_players_scores[name]
    ROOM_players_scores[name]={win:0, lose:0, flee:0, combo:0}
  ROOM_players_scores[name].lose = ROOM_players_scores[name].lose + 1
  ROOM_players_scores[name].combo = 0
  return

ROOM_player_flee = (name)->
  if !ROOM_players_scores[name]
    ROOM_players_scores[name]={win:0, lose:0, flee:0, combo:0}
  ROOM_players_scores[name].flee = ROOM_players_scores[name].flee + 1
  ROOM_players_scores[name].combo = 0
  return

ROOM_player_get_score = (player)->
  name = player.name_vpass
  score = ROOM_players_scores[name] 
  if !score
    return "#{player.name} ${random_score_blank}"
  total = score.win + score.lose
  if score.win < 2 and total < 3
    return "#{player.name} ${random_score_not_enough}"
  if score.combo >= 2
    return "${random_score_part1}#{player.name} ${random_score_part2} #{Math.ceil(score.win/total*100)}${random_score_part3} #{Math.ceil(score.flee/total*100)}${random_score_part4_combo}#{score.combo}${random_score_part5_combo}"
    #return player.name + " 的今日战绩：胜率" + Math.ceil(score.win/total*100) + "%，逃跑率" + Math.ceil(score.flee/total*100) + "%，" + score.combo + "连胜中！"
  else
    return "${random_score_part1}#{player.name} ${random_score_part2} #{Math.ceil(score.win/total*100)}${random_score_part3} #{Math.ceil(score.flee/total*100)}${random_score_part4}"
  return

if settings.modules.random_duel.post_match_scores
  setInterval(()->
    scores_pair = _.pairs ROOM_players_scores
    scores_by_lose = _.sortBy(scores_pair, (score)-> return score[1].lose).reverse() # 败场由高到低
    scores_by_win = _.sortBy(scores_by_lose, (score)-> return score[1].win).reverse() # 然后胜场由低到高，再逆转，就是先排胜场再排败场
    scores = _.first(scores_by_win, 10)
    #log.info scores
    request.post { url : settings.modules.random_duel.post_match_scores , form : {
      accesskey: settings.modules.random_duel.post_match_accesskey,
      rank: JSON.stringify(scores)
    }}, (error, response, body)=>
      if error
        log.warn 'RANDOM SCORE POST ERROR', error
      else
        if response.statusCode != 204 and response.statusCode != 200
          log.warn 'RANDOM SCORE POST FAIL', response.statusCode, response.statusMessage, body
        #else
        #  log.info 'RANDOM SCORE POST OK', response.statusCode, response.statusMessage
      return
    return
  , 60000)

ROOM_find_or_create_by_name = (name, player_ip)->
  uname=name.toUpperCase()
  if settings.modules.windbot.enabled and (uname[0...2] == 'AI' or (!settings.modules.random_duel.enabled and uname == '') or settings.modules.windbot.doom_bots)
    return ROOM_find_or_create_ai(name)
  if settings.modules.random_duel.enabled and (uname == '' or uname == 'S' or uname == 'M' or uname == 'T')
    return ROOM_find_or_create_random(uname, player_ip)
  if room = ROOM_find_by_name(name)
    return room
  else if memory_usage >= 90
    return null
  else
    return new Room(name)

ROOM_find_or_create_random = (type, player_ip)->
  bannedplayer = _.find ROOM_players_banned, (bannedplayer)->
    return player_ip == bannedplayer.ip
  if bannedplayer
    if bannedplayer.count > 6 and moment() < bannedplayer.time
      return {"error": "${random_banned_part1}#{bannedplayer.reasons.join('${random_ban_reason_separator}')}${random_banned_part2}#{moment(bannedplayer.time).fromNow(true)}${random_banned_part3}"}
    if bannedplayer.count > 3 and moment() < bannedplayer.time and bannedplayer.need_tip and type != 'T'
      bannedplayer.need_tip = false
      return {"error": "${random_deprecated_part1}#{bannedplayer.reasons.join('${random_ban_reason_separator}')}${random_deprecated_part2}#{moment(bannedplayer.time).fromNow(true)}${random_deprecated_part3}"}
    else if bannedplayer.need_tip
      bannedplayer.need_tip = false
      return {"error": "${random_warn_part1}#{bannedplayer.reasons.join('${random_ban_reason_separator}')}${random_warn_part2}"}
    else if bannedplayer.count > 2
      bannedplayer.need_tip = true
  max_player = if type == 'T' then 4 else 2
  playerbanned = (bannedplayer and bannedplayer.count > 3 and moment() < bannedplayer.time)
  result = _.find ROOM_all, (room)->
    return room and room.random_type != '' and !room.started and
    ((type == '' and (room.random_type == 'S' or (settings.modules.random_duel.blank_pass_match and room.random_type != 'T'))) or room.random_type == type) and
    room.get_playing_player().length < max_player and
    (settings.modules.random_duel.no_rematch_check or room.get_host() == null or
    room.get_host().ip != ROOM_players_oppentlist[player_ip]) and
    (playerbanned == room.deprecated or type == 'T')
  if result
    result.welcome = '${random_duel_enter_room_waiting}'
    #log.info 'found room', player_name
  else if memory_usage < 90
    type = if type then type else 'S'
    name = type + ',RANDOM#' + Math.floor(Math.random() * 100000)
    result = new Room(name)
    result.random_type = type
    result.max_player = max_player
    result.welcome = '${random_duel_enter_room_new}'
    result.deprecated = playerbanned
    #log.info 'create room', player_name, name
  else
    return null
  if result.random_type=='M' then result.welcome = result.welcome + '\n${random_duel_enter_room_match}'
  return result

ROOM_find_or_create_ai = (name)->
  if name == ''
    name = 'AI'
  namea = name.split('#')
  uname = name.toUpperCase()
  if room = ROOM_find_by_name(name)
    return room
  else if uname == 'AI'
    windbot = _.sample windbots
    name = 'AI#' + Math.floor(Math.random() * 100000)
  else if namea.length>1
    ainame = namea[namea.length-1]
    windbot = _.sample _.filter windbots, (w)->
      w.name == ainame or w.deck == ainame
    if !windbot
      return { "error": "${windbot_deck_not_found}" }
    name = name + ',' + Math.floor(Math.random() * 100000)
  else
    windbot = _.sample windbots
    name = name + '#' + Math.floor(Math.random() * 100000)
  if name.replace(/[^\x00-\xff]/g,"00").length>20
    log.info "long ai name", name
    return { "error": "${windbot_name_too_long}" }
  result = new Room(name)
  result.windbot = windbot
  result.private = true
  return result

ROOM_find_by_name = (name)->
  result = _.find ROOM_all, (room)->
    return room and room.name == name
  return result

ROOM_find_by_title = (title)->
  result = _.find ROOM_all, (room)->
    return room and room.title == title
  return result

ROOM_find_by_port = (port)->
  _.find ROOM_all, (room)->
    return room and room.port == port

ROOM_validate = (name)->
  client_name_and_pass = name.split('$', 2)
  client_name = client_name_and_pass[0]
  client_pass = client_name_and_pass[1]
  return true if !client_pass
  !_.find ROOM_all, (room)->
    return false unless room
    room_name_and_pass = room.name.split('$', 2)
    room_name = room_name_and_pass[0]
    room_pass = room_name_and_pass[1]
    client_name == room_name and client_pass != room_pass

ROOM_unwelcome = (room, bad_player, reason)->
  return unless room
  for player in room.players
    if player and player == bad_player
      ygopro.stoc_send_chat(player, "${unwelcome_warn_part1}#{reason}${unwelcome_warn_part2}", ygopro.constants.COLORS.RED)
    else if player and player.pos!=7 and player != bad_player
      player.flee_free=true
      ygopro.stoc_send_chat(player, "${unwelcome_tip_part1}#{reason}${unwelcome_tip_part2}", ygopro.constants.COLORS.BABYBLUE)
  return

CLIENT_kick = (client) ->
  if !client
    return false
  client.system_kicked = true
  if settings.modules.reconnect.enabled and client.closed
    if client.server and !client.had_new_reconnection
      client.server.destroy()
  else
    client.destroy()
  return true

release_disconnect = (dinfo, reconnected) ->
  if dinfo.old_client and !reconnected
    dinfo.old_client.destroy()
  if dinfo.old_server and !reconnected
    dinfo.old_server.destroy()
  clearTimeout(dinfo.timeout)
  return

CLIENT_get_authorize_key = (client) ->
  if !settings.modules.mycard.enabled and client.vpass
    return client.name_vpass
  else if settings.modules.mycard.enabled or settings.modules.tournament_mode.enabled or settings.modules.challonge.enabled or client.is_local
    return client.name
  else
    return client.ip + ":" + client.name

CLIENT_reconnect_unregister = (client, reconnected, exact) ->
  if !settings.modules.reconnect.enabled
    return false
  if disconnect_list[CLIENT_get_authorize_key(client)]
    if exact and disconnect_list[CLIENT_get_authorize_key(client)].old_client != client
      return false
    release_disconnect(disconnect_list[CLIENT_get_authorize_key(client)], reconnected)
    delete disconnect_list[CLIENT_get_authorize_key(client)]
    return true
  return false

CLIENT_reconnect_register = (client, room_id, error) ->
  room = ROOM_all[room_id]
  if client.had_new_reconnection
    return false
  if !settings.modules.reconnect.enabled or !room or client.system_kicked or client.flee_free or disconnect_list[CLIENT_get_authorize_key(client)] or client.is_post_watcher or !CLIENT_is_player(client, room) or !room.started or room.windbot or (settings.modules.reconnect.auto_surrender_after_disconnect and room.hostinfo.mode != 1) or (room.random_type and room.get_disconnected_count() > 1)
    return false
  # for player in room.players
  #   if player != client and CLIENT_get_authorize_key(player) == CLIENT_get_authorize_key(client)
  #     return false # some issues may occur in this case, so return false
  dinfo = {
    room_id: room_id,
    old_client: client,
    old_server: client.server,
    deckbuf: client.start_deckbuf
  }
  tmot = setTimeout(() ->
    room.disconnect(client, error)
    dinfo.old_server.destroy()
    return
  , settings.modules.reconnect.wait_time)
  dinfo.timeout = tmot
  disconnect_list[CLIENT_get_authorize_key(client)] = dinfo
  #console.log("#{client.name} ${disconnect_from_game}")
  ygopro.stoc_send_chat_to_room(room, "#{client.name} ${disconnect_from_game}" + if error then ": #{error}" else '')
  if client.time_confirm_required
    client.time_confirm_required = false
    ygopro.ctos_send(client.server, 'TIME_CONFIRM')
  if settings.modules.reconnect.auto_surrender_after_disconnect and room.turn and room.turn > 0
    ygopro.ctos_send(client.server, 'SURRENDER')
  return true

CLIENT_import_data = (client, old_client, room) ->
  for player,index in room.players
    if player == old_client
      room.players[index] = client
      break
  room.dueling_players[old_client.pos] = client
  if room.waiting_for_player == old_client
    room.waiting_for_player = client
  if room.waiting_for_player2 == old_client
    room.waiting_for_player2 = client
  if room.selecting_tp == old_client
    room.selecting_tp = client
  for key in import_datas
    client[key] = old_client[key]
  old_client.had_new_reconnection = true
  return

SERVER_clear_disconnect = (server) ->
  return false unless settings.modules.reconnect.enabled
  for k,v of disconnect_list
    if v and server == v.old_server
      release_disconnect(v)
      delete disconnect_list[k]
      return true
  return false

ROOM_clear_disconnect = (room_id) ->
  return false unless settings.modules.reconnect.enabled
  for k,v of disconnect_list
    if v and room_id == v.room_id
      release_disconnect(v)
      delete disconnect_list[k]
      return true
  return false

CLIENT_is_player = (client, room) ->
  is_player = false
  for player in room.players
    if client == player
      is_player = true
      break
  return is_player and client.pos <= 3

CLIENT_is_able_to_reconnect = (client, deckbuf) ->
  unless settings.modules.reconnect.enabled
    return false
  if client.system_kicked
    return false
  disconnect_info = disconnect_list[CLIENT_get_authorize_key(client)]
  unless disconnect_info
    return false
  room = ROOM_all[disconnect_info.room_id]
  if !room
    CLIENT_reconnect_unregister(client)
    return false
  if deckbuf and !_.isEqual(deckbuf, disconnect_info.deckbuf)
    return false
  return true

CLIENT_get_kick_reconnect_target = (client, deckbuf) ->
  for room in ROOM_all when room and room.started and !room.windbot
    for player in room.get_playing_player() when !player.closed and player.name == client.name and (settings.modules.challonge.enabled or player.pass == client.pass) and (settings.modules.mycard.enabled or settings.modules.tournament_mode.enabled or player.ip == client.ip or (client.vpass and client.vpass == player.vpass)) and (!deckbuf or _.isEqual(player.start_deckbuf, deckbuf))
      return player
  return null

CLIENT_is_able_to_kick_reconnect = (client, deckbuf) ->
  unless settings.modules.reconnect.enabled and settings.modules.reconnect.allow_kick_reconnect
    return false
  if !CLIENT_get_kick_reconnect_target(client, deckbuf)
    return false
  return true

CLIENT_send_pre_reconnect_info = (client, room, old_client) ->
  ygopro.stoc_send_chat(client, "${pre_reconnecting_to_room}", ygopro.constants.COLORS.BABYBLUE)
  ygopro.stoc_send(client, 'JOIN_GAME', room.join_game_buffer)
  req_pos = old_client.pos
  if old_client.is_host
    req_pos += 0x10
  ygopro.stoc_send(client, 'TYPE_CHANGE', {
    type: req_pos
  })
  for player in room.players
    ygopro.stoc_send(client, 'HS_PLAYER_ENTER', {
      name: player.name,
      pos: player.pos,
    })
  return

CLIENT_send_reconnect_info = (client, server, room) ->
  client.reconnecting = true
  ygopro.stoc_send_chat(client, "${reconnecting_to_room}", ygopro.constants.COLORS.BABYBLUE)
  if room.turn and room.turn > 0
    ygopro.ctos_send(server, 'REQUEST_FIELD')
  else if room.changing_side
    ygopro.stoc_send(client, 'DUEL_START')
    if !client.selected_preduel
      ygopro.stoc_send(client, 'CHANGE_SIDE')
    client.reconnecting = false
  else if room.selecting_hand
    ygopro.stoc_send(client, 'DUEL_START')
    if (room.hostinfo.mode != 2 or client.pos == 0 or client.pos == 2) and !client.selected_preduel
      ygopro.stoc_send(client, 'SELECT_HAND')
    client.reconnecting = false
  else if room.selecting_tp
    ygopro.stoc_send(client, 'DUEL_START')
    if client == room.selecting_tp # and !client.selected_preduel
      ygopro.stoc_send(client, 'SELECT_TP')
    client.reconnecting = false
  else
    ygopro.ctos_send(server, 'REQUEST_FIELD')
  return

CLIENT_pre_reconnect = (client) ->
  if CLIENT_is_able_to_reconnect(client)
    dinfo = disconnect_list[CLIENT_get_authorize_key(client)]
    client.pre_reconnecting = true
    client.pos = dinfo.old_client.pos
    client.setTimeout(300000)
    CLIENT_send_pre_reconnect_info(client, ROOM_all[dinfo.room_id], dinfo.old_client)
  else if CLIENT_is_able_to_kick_reconnect(client)
    player = CLIENT_get_kick_reconnect_target(client)
    client.pre_reconnecting = true
    client.pos = player.pos
    client.setTimeout(300000)
    CLIENT_send_pre_reconnect_info(client, ROOM_all[player.rid], player)
  return

CLIENT_reconnect = (client) ->
  if !CLIENT_is_able_to_reconnect(client)
    ygopro.stoc_send_chat(client, "${reconnect_failed}", ygopro.constants.COLORS.RED)
    CLIENT_kick(client)
    return
  client.pre_reconnecting = false
  dinfo = disconnect_list[CLIENT_get_authorize_key(client)]
  room = ROOM_all[dinfo.room_id]
  current_old_server = client.server
  client.server = dinfo.old_server
  client.server.client = client
  dinfo.old_client.server = null
  current_old_server.client = null
  current_old_server.had_new_reconnection = true
  current_old_server.destroy()
  client.established = true
  client.pre_establish_buffers = []
  if room.random_type or room.arena
    room.last_active_time = moment()
  CLIENT_import_data(client, dinfo.old_client, room)
  CLIENT_send_reconnect_info(client, client.server, room)
  #console.log("#{client.name} ${reconnect_to_game}")
  ygopro.stoc_send_chat_to_room(room, "#{client.name} ${reconnect_to_game}")
  CLIENT_reconnect_unregister(client, true)
  return

CLIENT_kick_reconnect = (client, deckbuf) ->
  if !CLIENT_is_able_to_kick_reconnect(client)
    ygopro.stoc_send_chat(client, "${reconnect_failed}", ygopro.constants.COLORS.RED)
    CLIENT_kick(client)
    return
  client.pre_reconnecting = false
  player = CLIENT_get_kick_reconnect_target(client, deckbuf)
  room = ROOM_all[player.rid]
  current_old_server = client.server
  client.server = player.server
  client.server.client = client
  ygopro.stoc_send_chat(player, "${reconnect_kicked}", ygopro.constants.COLORS.RED)
  player.server = null
  player.had_new_reconnection = true
  CLIENT_kick(player)
  current_old_server.client = null
  current_old_server.had_new_reconnection = true
  current_old_server.destroy()
  client.established = true
  client.pre_establish_buffers = []
  if room.random_type or room.arena
    room.last_active_time = moment()
  CLIENT_import_data(client, player, room)
  CLIENT_send_reconnect_info(client, client.server, room)
  #console.log("#{client.name} ${reconnect_to_game}")
  ygopro.stoc_send_chat_to_room(room, "#{client.name} ${reconnect_to_game}")
  CLIENT_reconnect_unregister(client, true)
  return

if settings.modules.reconnect.enabled
  disconnect_list = {} # {old_client, old_server, room_id, timeout, deckbuf}

CLIENT_heartbeat_unregister = (client) ->
  if !settings.modules.heartbeat_detection.enabled or !client.heartbeat_timeout
    return false
  clearTimeout(client.heartbeat_timeout)
  delete client.heartbeat_timeout
  #log.info(2, client.name)
  return true

CLIENT_heartbeat_register = (client, send) ->
  if !settings.modules.heartbeat_detection.enabled or client.closed or client.is_post_watcher or client.pre_reconnecting or client.reconnecting or client.waiting_for_last or client.pos > 3 or client.heartbeat_protected
    return false
  if client.heartbeat_timeout
    CLIENT_heartbeat_unregister(client)
  client.heartbeat_responsed = false
  if send
    ygopro.stoc_send(client, "TIME_LIMIT", {
      player: 0,
      left_time: 0
    })
    ygopro.stoc_send(client, "TIME_LIMIT", {
      player: 1,
      left_time: 0
    })
  client.heartbeat_timeout = setTimeout(() ->
    CLIENT_heartbeat_unregister(client)
    client.destroy() unless client.closed or client.heartbeat_responsed
    return
  , settings.modules.heartbeat_detection.wait_time)
  #log.info(1, client.name)
  return true

CLIENT_is_banned_by_mc = (client) ->
  return client.ban_mc and client.ban_mc.banned and moment().isBefore(client.ban_mc.until)

CLIENT_get_absolute_pos = (client) ->
  room = ROOM_all[client.rid]
  if room.hostinfo.mode != 2 or client.pos > 3
    return client.pos
  else if client.pos < 2
    return 0
  else
    return 1

CLIENT_get_partner = (client) ->
  room = ROOM_all[client.rid]
  if room.hostinfo.mode != 2 or client.pos > 3
    return client
  if client.pos < 2
    return room.dueling_players[1 - client.pos]
  else
    return room.dueling_players[5 - client.pos]

CLIENT_send_replays = (client, room) ->
  return false unless settings.modules.replay_delay and room.replays.length and room.hostinfo.mode == 1 and !client.replays_sent and !client.closed
  client.replays_sent = true
  i = 0
  for buffer in room.replays
    ++i
    if buffer
      ygopro.stoc_send_chat(client, "${replay_hint_part1}" + i + "${replay_hint_part2}", ygopro.constants.COLORS.BABYBLUE)
      ygopro.stoc_send(client, "REPLAY", buffer)
  return true

SOCKET_flush_data = (sk, datas) ->
  if !sk or sk.closed
    return false
  for buffer in datas
    sk.write(buffer)
  datas.splice(0, datas.length)
  return true

replace_buffer = (buffer, list, start_pos) ->
  found = 0
  len = buffer.length
  if len < 4 + start_pos
    return 0
  for i in [start_pos...len - 3]
    code = buffer.readInt32LE(i)
    if list[code]
      code = list[code]
      buffer.writeInt32LE(code, i)
      found++
      i += 3
      if i >= len - 4
        break
  return found

class Room
  constructor: (name, @hostinfo) ->
    @name = name
    @alive = true
    @players = []
    @player_datas = []
    @status = 'starting'
    @started = false
    @established = false
    @watcher_buffers = []
    @recorder_buffers = []
    @cloud_replay_id = Math.floor(Math.random()*100000000)
    @watchers = []
    @random_type = ''
    @welcome = ''
    @scores = {}
    @decks = {}
    @duel_count = 0
    @death = 0
    @turn = 0
    if settings.modules.replay_delay
      @replays = []
    ROOM_all.push this

    if settings.modules.pre_release_compat.enabled
      list_official_to_pre = {}
      list_pre_to_official = {}
      @list_official_to_pre = list_official_to_pre
      @list_pre_to_official = list_pre_to_official
      temp_list = {}
      try
        official_database = new sqlite3.Database(settings.modules.pre_release_compat.official_database)
        pre_release_database = new sqlite3.Database(settings.modules.pre_release_compat.pre_release_database)
        pre_release_database.each("select id,name from texts", (err, result) ->
          if err
            log.warn("Error loading pre-release database.", err)
          else
            temp_list[result.name] = result.id
          return
        , (err) ->
          if err
            log.warn("Error loaded pre-release database.", err)
          else
            official_database.each("select id,name from texts", (err, result) ->
              if err
                log.warn("Error loading official database.", err)
              else if temp_list[result.name] and temp_list[result.name] != result.id
                official_code = result.id
                pre_release_code = temp_list[result.name]
                list_official_to_pre[official_code] = pre_release_code
                list_pre_to_official[pre_release_code] = official_code
              return
            , (err) ->
              if err
                log.warn("Error loaded official database.", err)
              return
            )
          return
        )
      catch error
        log.warn("Error loading databases", error)

    @hostinfo ||= JSON.parse(JSON.stringify(settings.hostinfo))
    delete @hostinfo.comment
    if lflists.length
      if @hostinfo.rule == 1 and @hostinfo.lflist == 0
        @hostinfo.lflist = _.findIndex lflists, (list)-> list.tcg
    else
      @hostinfo.lflist =  -1

    if name[0...2] == 'M#'
      @hostinfo.mode = 1
    else if name[0...2] == 'T#'
      @hostinfo.mode = 2
      @hostinfo.start_lp = 16000
    else if name[0...3] == 'AI#' or settings.modules.windbot.doom_bots
      @hostinfo.rule = 2
      @hostinfo.lflist = -1
      if !settings.modules.windbot.doom_bots
        @hostinfo.time_limit = 0
        @hostinfo.no_check_deck = true

    else if (param = name.match /^(\d)(\d)(T|F)(T|F)(T|F)(\d+),(\d+),(\d+)/i)
      @hostinfo.rule = parseInt(param[1])
      @hostinfo.mode = parseInt(param[2])
      @hostinfo.enable_priority = param[3] == 'T'
      @hostinfo.no_check_deck = param[4] == 'T'
      @hostinfo.no_shuffle_deck = param[5] == 'T'
      @hostinfo.start_lp = parseInt(param[6])
      @hostinfo.start_hand = parseInt(param[7])
      @hostinfo.draw_count = parseInt(param[8])

    else if ((param = name.match /(.+)#/) != null)
      rule = param[1].toUpperCase()

      if (rule.match /(^|，|,)(M|MATCH)(，|,|$)/)
        @hostinfo.mode = 1

      if (rule.match /(^|，|,)(T|TAG)(，|,|$)/)
        @hostinfo.mode = 2
        @hostinfo.start_lp = 16000

      if (rule.match /(^|，|,)(TCGONLY|TO)(，|,|$)/)
        @hostinfo.rule = 1
        @hostinfo.lflist = _.findIndex lflists, (list)-> list.tcg

      if (rule.match /(^|，|,)(OCGONLY|OO)(，|,|$)/)
        @hostinfo.rule = 0
        @hostinfo.lflist = 0

      if (rule.match /(^|，|,)(OT|TCG)(，|,|$)/)
        @hostinfo.rule = 2

      if (param = rule.match /(^|，|,)LP(\d+)(，|,|$)/)
        start_lp = parseInt(param[2])
        if (start_lp <= 0) then start_lp = 1
        if (start_lp >= 99999) then start_lp = 99999
        @hostinfo.start_lp = start_lp

      if (param = rule.match /(^|，|,)(TIME|TM|TI)(\d+)(，|,|$)/)
        time_limit = parseInt(param[3])
        if (time_limit < 0) then time_limit = 180
        if (time_limit >= 1 and time_limit <= 60) then time_limit = time_limit * 60
        if (time_limit >= 999) then time_limit = 999
        @hostinfo.time_limit = time_limit

      if (param = rule.match /(^|，|,)(START|ST)(\d+)(，|,|$)/)
        start_hand = parseInt(param[3])
        if (start_hand <= 0) then start_hand = 1
        if (start_hand >= 40) then start_hand = 40
        @hostinfo.start_hand = start_hand

      if (param = rule.match /(^|，|,)(DRAW|DR)(\d+)(，|,|$)/)
        draw_count = parseInt(param[3])
        if (draw_count >= 35) then draw_count = 35
        @hostinfo.draw_count = draw_count

      if (param = rule.match /(^|，|,)(LFLIST|LF)(\d+)(，|,|$)/)
        lflist = parseInt(param[3]) - 1
        @hostinfo.lflist = lflist

      if (rule.match /(^|，|,)(NOLFLIST|NF)(，|,|$)/)
        @hostinfo.lflist = -1

      if (rule.match /(^|，|,)(NOUNIQUE|NU)(，|,|$)/)
        @hostinfo.rule = 3

      if (rule.match /(^|，|,)(NOCHECK|NC)(，|,|$)/)
        @hostinfo.no_check_deck = true

      if (rule.match /(^|，|,)(NOSHUFFLE|NS)(，|,|$)/)
        @hostinfo.no_shuffle_deck = true

      if (rule.match /(^|，|,)(IGPRIORITY|PR)(，|,|$)/)
        @hostinfo.enable_priority = true

      if (rule.match /(^|，|,)(NOWATCH|NW)(，|,|$)/)
        @no_watch = true

    @hostinfo.replay_mode = if settings.modules.tournament_mode.enabled and settings.modules.tournament_mode.replay_safe or @hostinfo.mode == 1 and settings.modules.replay_delay then 1 else 0

    param = [0, @hostinfo.lflist, @hostinfo.rule, @hostinfo.mode, (if @hostinfo.enable_priority then 'T' else 'F'),
      (if @hostinfo.no_check_deck then 'T' else 'F'), (if @hostinfo.no_shuffle_deck then 'T' else 'F'),
      @hostinfo.start_lp, @hostinfo.start_hand, @hostinfo.draw_count, @hostinfo.time_limit, @hostinfo.replay_mode]

    try
      @process = spawn './ygopro', param, {cwd: 'ygopro'}
      @process_pid = @process.pid
      @process.on 'error', (err)=>
        _.each @players, (player)->
          ygopro.stoc_die(player, "${create_room_failed}")
        this.delete()
        return
      @process.on 'exit', (code)=>
        @disconnector = 'server' unless @disconnector
        this.delete()
        return
      @process.stdout.setEncoding('utf8')
      @process.stdout.once 'data', (data)=>
        @established = true
        roomlist.create(this) if !@windbot and settings.modules.http.websocket_roomlist
        @port = parseInt data
        _.each @players, (player)=>
          player.server.connect @port, '127.0.0.1', ->
            player.server.write buffer for buffer in player.pre_establish_buffers
            player.established = true
            player.pre_establish_buffers = []
            return
          return
        if @windbot
          setTimeout ()=>
            @add_windbot(@windbot)
          , 200
        return
      @process.stderr.on 'data', (data)=>
        data = "Debug: " + data
        data = data.replace(/\n$/, "")
        log.info "YGOPRO " + data
        ygopro.stoc_send_chat_to_room this, data, ygopro.constants.COLORS.RED
        @has_ygopro_error = true
        @ygopro_error_length = if @ygopro_error_length then @ygopro_error_length + data.length else data.length
        if @ygopro_error_length > 10000
          @send_replays()
          @process.kill()
        return
    catch
      @error = "${create_room_failed}"
  delete: ->
    return if @deleted
    #log.info 'room-delete', this.name, ROOM_all.length
    score_array=[]
    for name, score of @scores
      score_form = { name: name.split('$')[0], score: score, deck: null, name_vpass: name }
      if @decks[name]
        score_form.deck = @decks[name]
      score_array.push score_form
    if settings.modules.random_duel.record_match_scores and @random_type == 'M'
      if score_array.length == 2
        if score_array[0].score != score_array[1].score
          if score_array[0].score > score_array[1].score
            ROOM_player_win(score_array[0].name_vpass)
            ROOM_player_lose(score_array[1].name_vpass)
          else
            ROOM_player_win(score_array[1].name_vpass)
            ROOM_player_lose(score_array[0].name_vpass)
      if score_array.length == 1 # same name
          #log.info score_array[0].name
          ROOM_player_win(score_array[0].name_vpass)
          ROOM_player_lose(score_array[0].name_vpass)
    if settings.modules.arena_mode.enabled and @arena
      #log.info 'SCORE', score_array, @start_time
      end_time = moment().format()
      if !@start_time
        @start_time = end_time
      if score_array.length != 2
        if !score_array[0]
          score_array[0] = { name: null, score: -5, deck: null }
        if !score_array[1]
          score_array[1] = { name: null, score: -5, deck: null }
        score_array[0].score = -5
        score_array[1].score = -5
      request.post { url : settings.modules.arena_mode.post_score , form : {
        accesskey: settings.modules.arena_mode.accesskey,
        usernameA: score_array[0].name,
        usernameB: score_array[1].name,
        userscoreA: score_array[0].score,
        userscoreB: score_array[1].score,
        userdeckA: score_array[0].deck,
        userdeckB: score_array[1].deck,
        start: @start_time,
        end: end_time,
        arena: @arena
      }}, (error, response, body)=>
        if error
          log.warn 'SCORE POST ERROR', error
        else
          if response.statusCode != 204 and response.statusCode != 200
            log.warn 'SCORE POST FAIL', response.statusCode, response.statusMessage, @name, body
          #else
          #  log.info 'SCORE POST OK', response.statusCode, response.statusMessage, @name, body
        return

    if settings.modules.challonge.enabled and @started and @hostinfo.mode != 2 and !@kicked
      room_name = @name
      challonge.matches._update({
        id: settings.modules.challonge.tournament_id,
        matchId: @challonge_info.id,
        match: @get_challonge_score(),
        callback: (err, data) ->
          if err
            log.warn("Errored pushing scores to Challonge.", room_name, err)
          else
            refresh_challonge_cache()
          return
      })
    if @player_datas.length and settings.modules.cloud_replay.enabled
      replay_id = @cloud_replay_id
      if @has_ygopro_error
        log_rep_id = true
      player_names=@player_datas[0].name + (if @player_datas[2] then "+" + @player_datas[2].name else "") +
                    " VS " +
                   (if @player_datas[1] then @player_datas[1].name else "AI") +
                   (if @player_datas[3] then "+" + @player_datas[3].name else "")
      player_ips=[]
      _.each @player_datas, (player)->
        player_ips.push(player.ip)
        return
      recorder_buffer=Buffer.concat(@recorder_buffers)
      zlib.deflate recorder_buffer, (err, replay_buffer) ->
        replay_buffer=replay_buffer.toString('binary')
        #log.info err, replay_buffer
        date_time=moment().format('YYYY-MM-DD HH:mm:ss')
        #replay_id=Math.floor(Math.random()*100000000)
        redisdb.hmset("replay:"+replay_id,
                      "replay_id", replay_id,
                      "replay_buffer", replay_buffer,
                      "player_names", player_names,
                      "date_time", date_time)
        if !log_rep_id
          redisdb.expire("replay:"+replay_id, 60*60*24)
        recorded_ip=[]
        _.each player_ips, (player_ip)->
          return if _.contains(recorded_ip, player_ip)
          recorded_ip.push player_ip
          redisdb.lpush(player_ip+":replays", replay_id)
          return
        if log_rep_id
          log.info "error replay: R#" + replay_id
        return
    @watcher_buffers = []
    @recorder_buffers = []
    @players = []
    @watcher.destroy() if @watcher
    @recorder.destroy() if @recorder
    @deleted = true
    index = _.indexOf(ROOM_all, this)
    if settings.modules.reconnect.enabled
      ROOM_clear_disconnect(index)
    ROOM_all[index] = null unless index == -1
    #ROOM_all.splice(index, 1) unless index == -1
    roomlist.delete this if !@windbot and @established and settings.modules.http.websocket_roomlist
    return

  get_playing_player: ->
    playing_player = []
    _.each @players, (player)->
      if player.pos < 4 then playing_player.push player
      return
    return playing_player

  get_host: ->
    host_player = null
    _.each @players, (player)->
      if player.is_host then host_player = player
      return
    return host_player

  get_disconnected_count: ->
    if !settings.modules.reconnect.enabled
      return 0
    found = 0
    for player in @get_playing_player() when player.closed
      found++
    return found

  get_challonge_score: ->
    if !settings.modules.challonge.enabled or !@started or @hostinfo.mode == 2
      return null
    challonge_duel_log = {}
    if @scores[@dueling_players[0].name_vpass] > @scores[@dueling_players[1].name_vpass]
      challonge_duel_log.winnerId = @dueling_players[0].challonge_info.id
    else if @scores[@dueling_players[0].name_vpass] < @scores[@dueling_players[1].name_vpass]
      challonge_duel_log.winnerId = @dueling_players[1].challonge_info.id
    else
      challonge_duel_log.winnerId = "tie"
    if settings.modules.challonge.post_detailed_score
      if @dueling_players[0].challonge_info.id == @challonge_info.player1Id and @dueling_players[1].challonge_info.id == @challonge_info.player2Id
        challonge_duel_log.scoresCsv = @scores[@dueling_players[0].name_vpass] + "-" + @scores[@dueling_players[1].name_vpass]
      else if @dueling_players[1].challonge_info.id == @challonge_info.player1Id and @dueling_players[0].challonge_info.id == @challonge_info.player2Id
        challonge_duel_log.scoresCsv = @scores[@dueling_players[1].name_vpass] + "-" + @scores[@dueling_players[0].name_vpass]
      else
        challonge_duel_log.scoresCsv = "0-0"
        log.warn("Score mismatch.", @name)
    else
      if challonge_duel_log.winnerId == @challonge_info.player1Id
        challonge_duel_log.scoresCsv = "1-0"
      else if challonge_duel_log.winnerId == @challonge_info.player2Id
        challonge_duel_log.scoresCsv = "0-1"
      else
        challonge_duel_log.scoresCsv = "0-0"
    return challonge_duel_log

  send_replays: () ->
    return false unless settings.modules.replay_delay and @replays.length and @hostinfo.mode == 1
    for player in @players
      CLIENT_send_replays(player, this)
    for player in @watchers
      CLIENT_send_replays(player, this)
    return true

  add_windbot: (botdata)->
    @windbot = botdata
    request
      url: "http://#{settings.modules.windbot.server_ip}:#{settings.modules.windbot.port}/?name=#{encodeURIComponent(botdata.name)}&deck=#{encodeURIComponent(botdata.deck)}&host=#{settings.modules.windbot.my_ip}&port=#{settings.port}&dialog=#{encodeURIComponent(botdata.dialog)}&version=#{settings.version}&password=#{encodeURIComponent(@name)}"
    , (error, response, body)=>
      if error
        log.warn 'windbot add error', error, this.name
        ygopro.stoc_send_chat_to_room(this, "${add_windbot_failed}", ygopro.constants.COLORS.RED)
      #else
        #log.info "windbot added"
      return
    return

  connect: (client)->
    @players.push client
    if @random_type
      client.abuse_count = 0
      host_player = @get_host()
      if host_player && (host_player != client)
        # 进来时已经有人在等待了，互相记录为匹配过
        ROOM_players_oppentlist[host_player.ip] = client.ip
        ROOM_players_oppentlist[client.ip] = host_player.ip
      else
        # 第一个玩家刚进来，还没就位
        ROOM_players_oppentlist[client.ip] = null

    if @established
      roomlist.update(this) if !@windbot and !@started and settings.modules.http.websocket_roomlist
      client.server.connect @port, '127.0.0.1', ->
        client.server.write buffer for buffer in client.pre_establish_buffers
        client.established = true
        client.pre_establish_buffers = []
        return
    return

  disconnect: (client, error)->
    if client.had_new_reconnection
      return
    if client.is_post_watcher
      ygopro.stoc_send_chat_to_room this, "#{client.name} ${quit_watch}" + if error then ": #{error}" else ''
      index = _.indexOf(@watchers, client)
      @watchers.splice(index, 1) unless index == -1
      #client.room = null
      client.server.destroy()
    else
      #log.info(client.name, @started, @disconnector, @random_type, @players.length)
      if @arena and !@started and @disconnector != 'server' and !@arena_score_handled
        for player in @players when player.pos != 7
          @scores[player.name_vpass] = 0
        if @players.length == 2
          @scores[client.name_vpass] = -9
        @arena_score_handled = true
      index = _.indexOf(@players, client)
      @players.splice(index, 1) unless index == -1
      if @started and @disconnector != 'server' and client.pos < 4
        @finished = true
        if !@finished_by_death
          @scores[client.name_vpass] = -9
          if @random_type and not client.flee_free and (!settings.modules.reconnect.enabled or @get_disconnected_count() == 0)
            ROOM_ban_player(client.name, client.ip, "${random_ban_reason_flee}")
            if settings.modules.random_duel.record_match_scores and @random_type == 'M'
              ROOM_player_flee(client.name_vpass)
      if @players.length and !(@windbot and client.is_host) and !(@arena and !@started and client.pos <= 3)
        ygopro.stoc_send_chat_to_room this, "#{client.name} ${left_game}" + if error then ": #{error}" else ''
        roomlist.update(this) if !@windbot and !@started and settings.modules.http.websocket_roomlist
        #client.room = null
      else
        @send_replays()
        @process.kill()
        #client.room = null
        this.delete()
      if !CLIENT_reconnect_unregister(client, false, true)
        client.server.destroy()
    return


# 网络连接
net.createServer (client) ->
  client.ip = client.remoteAddress
  client.is_local = client.ip and (client.ip.includes('127.0.0.1') or client.ip.includes(settings.modules.windbot.server_ip))

  connect_count = ROOM_connected_ip[client.ip] or 0
  if !settings.modules.test_mode.no_connect_count_limit and !client.is_local
    connect_count++
  ROOM_connected_ip[client.ip] = connect_count
  #log.info "connect", client.ip, ROOM_connected_ip[client.ip]

  # server stand for the connection to ygopro server process
  server = new net.Socket()
  client.server = server
  server.client = client

  client.setTimeout(2000) #连接前超时2秒

  # 释放处理
  client.on 'close', (had_error) ->
    #log.info "client closed", client.name, had_error
    room=ROOM_all[client.rid]
    connect_count = ROOM_connected_ip[client.ip]
    if connect_count > 0
      connect_count--
    ROOM_connected_ip[client.ip] = connect_count
    #log.info "disconnect", client.ip, ROOM_connected_ip[client.ip]
    unless client.closed
      client.closed = true
      if settings.modules.heartbeat_detection.enabled
        CLIENT_heartbeat_unregister(client)
      if room
        if !CLIENT_reconnect_register(client, client.rid)
          room.disconnect(client)
      else if !client.had_new_reconnection
        client.server.destroy()
    return

  client.on 'error', (error)->
    #log.info "client error", client.name, error
    room=ROOM_all[client.rid]
    connect_count = ROOM_connected_ip[client.ip]
    if connect_count > 0
      connect_count--
    ROOM_connected_ip[client.ip] = connect_count
    #log.info "err disconnect", client.ip, ROOM_connected_ip[client.ip]
    unless client.closed
      client.closed = true
      if room
        if !CLIENT_reconnect_register(client, client.rid, error)
          room.disconnect(client, error)
      else if !client.had_new_reconnection
        client.server.destroy()
    return

  client.on 'timeout', ()->
    unless settings.modules.reconnect.enabled and (disconnect_list[CLIENT_get_authorize_key(client)] or client.had_new_reconnection)
      client.destroy()
    return

  server.on 'close', (had_error) ->
    #log.info "server closed", server.client.name, had_error
    room=ROOM_all[server.client.rid]
    #log.info "server close", server.client.ip, ROOM_connected_ip[server.client.ip]
    room.disconnector = 'server' if room
    server.closed = true unless server.closed
    if !server.client
      return
    unless server.client.closed
      ygopro.stoc_send_chat(server.client, "${server_closed}", ygopro.constants.COLORS.RED)
      #if room and settings.modules.replay_delay
      #  room.send_replays()
      CLIENT_kick(server.client)
      SERVER_clear_disconnect(server)
    return

  server.on 'error', (error)->
    #log.info "server error", client.name, error
    room=ROOM_all[server.client.rid]
    #log.info "server err close", client.ip, ROOM_connected_ip[client.ip]
    room.disconnector = 'server' if room
    server.closed = error
    if !server.client
      return
    unless server.client.closed
      ygopro.stoc_send_chat(server.client, "${server_error}: #{error}", ygopro.constants.COLORS.RED)
      #if room and settings.modules.replay_delay
      #  room.send_replays()
      CLIENT_kick(server.client)
      SERVER_clear_disconnect(server)
    return

  if ROOM_bad_ip[client.ip] > 5 or ROOM_connected_ip[client.ip] > 10
    log.info 'BAD IP', client.ip
    CLIENT_kick(client)
    return

  if settings.modules.cloud_replay.enabled
    client.open_cloud_replay= (err, replay)->
      if err or !replay
        ygopro.stoc_die(client, "${cloud_replay_no}")
        return
      redisdb.expire("replay:"+replay.replay_id, 60*60*48)
      buffer=Buffer.from(replay.replay_buffer,'binary')
      zlib.unzip buffer, (err, replay_buffer) ->
        if err
          log.info "cloud replay unzip error: " + err
          ygopro.stoc_send_chat(client, "${cloud_replay_error}", ygopro.constants.COLORS.RED)
          CLIENT_kick(client)
          return
        ygopro.stoc_send_chat(client, "${cloud_replay_playing} R##{replay.replay_id} #{replay.player_names} #{replay.date_time}", ygopro.constants.COLORS.BABYBLUE)
        client.write replay_buffer, ()->
          CLIENT_kick(client)
          return
        return
      return

  # 需要重构
  # 客户端到服务端(ctos)协议分析

  client.pre_establish_buffers = new Array()

  client.on 'data', (ctos_buffer) ->
    if client.is_post_watcher
      room=ROOM_all[client.rid]
      room.watcher.write ctos_buffer if room and !CLIENT_is_banned_by_mc(client)
    else
      #ctos_buffer = Buffer.alloc(0)
      ctos_message_length = 0
      ctos_proto = 0
      #ctos_buffer = Buffer.concat([ctos_buffer, data], ctos_buffer.length + data.length) #buffer的错误使用方式，好孩子不要学

      datas = []

      looplimit = 0

      while true
        if ctos_message_length == 0
          if ctos_buffer.length >= 2
            ctos_message_length = ctos_buffer.readUInt16LE(0)
          else
            log.warn("bad ctos_buffer length", client.ip) unless ctos_buffer.length == 0
            break
        else if ctos_proto == 0
          if ctos_buffer.length >= 3
            ctos_proto = ctos_buffer.readUInt8(2)
          else
            log.warn("bad ctos_proto length", client.ip)
            break
        else
          if ctos_buffer.length >= 2 + ctos_message_length
            #console.log "CTOS", ygopro.constants.CTOS[ctos_proto]
            cancel = false
            if settings.modules.reconnect.enabled and client.pre_reconnecting and ygopro.constants.CTOS[ctos_proto] != 'UPDATE_DECK'
              cancel = true
            if ygopro.ctos_follows[ctos_proto] and !cancel
              b = ctos_buffer.slice(3, ctos_message_length - 1 + 3)
              info = null
              if struct = ygopro.structs[ygopro.proto_structs.CTOS[ygopro.constants.CTOS[ctos_proto]]]
                struct._setBuff(b)
                info = _.clone(struct.fields)
              if ygopro.ctos_follows[ctos_proto].synchronous
                cancel = ygopro.ctos_follows[ctos_proto].callback b, info, client, client.server, datas
              else
                ygopro.ctos_follows[ctos_proto].callback b, info, client, client.server, datas
            datas.push ctos_buffer.slice(0, 2 + ctos_message_length) unless cancel
            ctos_buffer = ctos_buffer.slice(2 + ctos_message_length)
            ctos_message_length = 0
            ctos_proto = 0
          else
            log.warn("bad ctos_message length", client.ip, ctos_buffer.length, ctos_message_length, ctos_proto) if ctos_message_length != 17735
            break

        looplimit++
        #log.info(looplimit)
        if looplimit > 800 or ROOM_bad_ip[client.ip] > 5
          log.info("error ctos", client.name, client.ip)
          bad_ip_count = ROOM_bad_ip[client.ip]
          if bad_ip_count
            ROOM_bad_ip[client.ip] = bad_ip_count + 1
          else
            ROOM_bad_ip[client.ip] = 1
          CLIENT_kick(client)
          break
      if !client.server
        return
      if client.established
        client.server.write buffer for buffer in datas
      else
        client.pre_establish_buffers.push buffer for buffer in datas

    return

  # 服务端到客户端(stoc)
  server.on 'data', (stoc_buffer)->
    #stoc_buffer = Buffer.alloc(0)
    stoc_message_length = 0
    stoc_proto = 0
    #stoc_buffer = Buffer.concat([stoc_buffer, data], stoc_buffer.length + data.length) #buffer的错误使用方式，好孩子不要学

    #unless ygopro.stoc_follows[stoc_proto] and ygopro.stoc_follows[stoc_proto].synchronous
    #server.client.write data
    datas = []

    looplimit = 0

    while true
      if stoc_message_length == 0
        if stoc_buffer.length >= 2
          stoc_message_length = stoc_buffer.readUInt16LE(0)
        else
          log.warn("bad stoc_buffer length", server.client.ip) unless stoc_buffer.length == 0
          break
      else if stoc_proto == 0
        if stoc_buffer.length >= 3
          stoc_proto = stoc_buffer.readUInt8(2)
        else
          log.warn("bad stoc_proto length", server.client.ip)
          break
      else
        if stoc_buffer.length >= 2 + stoc_message_length
          #console.log "STOC", ygopro.constants.STOC[stoc_proto]
          cancel = false
          stanzas = stoc_proto
          if ygopro.stoc_follows[stoc_proto]
            b = stoc_buffer.slice(3, stoc_message_length - 1 + 3)
            info = null
            if struct = ygopro.structs[ygopro.proto_structs.STOC[ygopro.constants.STOC[stoc_proto]]]
              struct._setBuff(b)
              info = _.clone(struct.fields)
            if ygopro.stoc_follows[stoc_proto].synchronous
              cancel = ygopro.stoc_follows[stoc_proto].callback b, info, server.client, server, datas
            else
              ygopro.stoc_follows[stoc_proto].callback b, info, server.client, server, datas
          datas.push stoc_buffer.slice(0, 2 + stoc_message_length) unless cancel
          stoc_buffer = stoc_buffer.slice(2 + stoc_message_length)
          stoc_message_length = 0
          stoc_proto = 0
        else
          log.warn("bad stoc_message length", server.client.ip)
          break

      looplimit++
      #log.info(looplimit)
      if looplimit > 800
        log.info("error stoc", server.client.name)
        server.destroy()
        break
    if server.client and !server.client.closed
      server.client.write buffer for buffer in datas

    return
  return
.listen settings.port, ->
  log.info "server started", settings.port
  return

if settings.modules.stop
  log.info "NOTE: server not open due to config, ", settings.modules.stop

# 功能模块
# return true to cancel a synchronous message

ygopro.ctos_follow 'PLAYER_INFO', true, (buffer, info, client, server, datas)->
  # checkmate use username$password, but here don't
  # so remove the password
  name_full =info.name.split("$")
  name = name_full[0]
  vpass = name_full[1]
  if vpass and !vpass.length
    vpass = null
  if (_.any(settings.ban.illegal_id, (badid) ->
    regexp = new RegExp(badid, 'i')
    matchs = name.match(regexp)
    if matchs
      name = matchs[1]
      return true
    return false
  , name))
    client.rag = true
  if settings.modules.mycard.enabled
    #console.log(name)
    request
      url: settings.modules.mycard.ban_get
      json: true
      qs:
        user: name
    , (error, response, body)->
      #console.log(body)
      if _.isString body
        log.warn "ban get bad json", body
      else if error or !body
        log.warn 'ban get error', error, response
      else
        client.ban_mc = body
      return
  struct = ygopro.structs["CTOS_PlayerInfo"]
  struct._setBuff(buffer)
  struct.set("name", name)
  buffer = struct.buffer
  client.name = name
  client.vpass = vpass
  client.name_vpass = if vpass then name + "$" + vpass else name
  if settings.modules.pre_release_compat.enabled
    client.is_using_pre_release = client.name_vpass == "COMPAT"
  #console.log client.name, client.vpass
  if settings.modules.vip.enabled and CLIENT_check_vip(client)
    client.vip = true

  if not settings.modules.i18n.auto_pick or client.is_local
    client.lang=settings.modules.i18n.default
  else
    geo = geoip.lookup(client.ip)
    if not geo
      log.warn("fail to locate ip", client.name, client.ip)
      client.lang=settings.modules.i18n.fallback
    else
      if lang=settings.modules.i18n.map[geo.country]
        client.lang=lang
      else
        #log.info("Not in map", geo.country, client.name, client.ip)
        client.lang=settings.modules.i18n.fallback
  return false

ygopro.ctos_follow 'JOIN_GAME', false, (buffer, info, client, server, datas)->
#log.info info
  info.pass=info.pass.trim()
  client.pass = info.pass
  if CLIENT_is_able_to_reconnect(client) or CLIENT_is_able_to_kick_reconnect(client)
    CLIENT_pre_reconnect(client)
    return
  else if settings.modules.stop
    ygopro.stoc_die(client, settings.modules.stop)
  else if info.pass == "Marshtomp" or info.pass == "the Big Brother"
    ygopro.stoc_die(client, "${bad_user_name}")

  else if info.pass.toUpperCase()=="R" and settings.modules.cloud_replay.enabled
    ygopro.stoc_send_chat(client,"${cloud_replay_hint}", ygopro.constants.COLORS.BABYBLUE)
    redisdb.lrange client.ip+":replays", 0, 2, (err, result)->
      _.each result, (replay_id,id)->
        redisdb.hgetall "replay:"+replay_id, (err, replay)->
          if err or !replay
            log.info "cloud replay getall error: " + err if err
            return
          ygopro.stoc_send_chat(client,"<#{id-0+1}> R##{replay_id} #{replay.player_names} #{replay.date_time}", ygopro.constants.COLORS.BABYBLUE)
          return
        return
      return
    # 强行等待异步执行完毕_(:з」∠)_
    setTimeout (()->
      ygopro.stoc_send client, 'ERROR_MSG',{
        msg: 1
        code: 9
      }
      CLIENT_kick(client)
      return), 500

  else if info.pass.toUpperCase()=="L" and settings.modules.koishi_roomlist.enabled
    ygopro.stoc_send_chat(client,"${koishi_roomlist_hint}", ygopro.constants.COLORS.BABYBLUE)
    room_showed = []
    for room in ROOM_all when room and room.established and room.name.indexOf('$') < 0
      room_showed.push(room)
    buffer_pos = 0
    room_buffer = Buffer.alloc(2 + 333 * room_showed.length)
    room_buffer.writeUInt16LE(room_showed.length, buffer_pos)
    buffer_pos += 2
    for room in room_showed
      room_buffer.write(room.name, buffer_pos, 64, "utf8")
      buffer_pos += 64
      oppo_pos = if room.hostinfo.mode == 2 then 2 else 1
      room_buffer.writeUInt8((if !room.started then 0 else if room.changing_side then 2 else 1), buffer_pos)
      buffer_pos++
      room_buffer.writeInt8(room.duel_count, buffer_pos)
      buffer_pos++
      room_buffer.writeInt8((if room.turn? then room.turn else 0), buffer_pos)
      buffer_pos++
      room_players = []
      for player in room.get_playing_player() when player
        room_players[player.pos] = player
      player_string = "???"
      if room_players[0]
        player_string = room_players[0].name
      if room.hostinfo.mode == 2
        player_string = player_string + "+" + (if room_players[1] then room_players[1].name else "???")
      room_buffer.write(player_string, buffer_pos, 128, "utf8")
      buffer_pos += 128
      if room.started
        room_buffer.writeInt8((if room_players[0] and room.scores[room_players[0].name_vpass]? then room.scores[room_players[0].name_vpass] else 0), buffer_pos)
        buffer_pos++
        room_buffer.writeInt32LE((if room_players[0] and room_players[0].lp? then room_players[0].lp else room.hostinfo.start_lp), buffer_pos)
        buffer_pos += 4
      else
        room_buffer.writeInt8(0, buffer_pos)
        buffer_pos++
        room_buffer.writeInt32LE(0, buffer_pos)
        buffer_pos += 4
      player_string = "???"
      if room_players[oppo_pos]
        player_string = room_players[oppo_pos].name
      if room.hostinfo.mode == 2
        player_string = player_string + "+" + (if room_players[oppo_pos + 1] then room_players[oppo_pos + 1].name else "???")
      room_buffer.write(player_string, buffer_pos, 128, "utf8")
      buffer_pos += 128
      if room.started
        room_buffer.writeInt8((if room_players[oppo_pos] and room.scores[room_players[oppo_pos].name_vpass]? then room.scores[room_players[oppo_pos].name_vpass] else 0), buffer_pos)
        buffer_pos++
        room_buffer.writeInt32LE((if room_players[oppo_pos] and room_players[oppo_pos].lp? then room_players[oppo_pos].lp else room.hostinfo.start_lp), buffer_pos)
        buffer_pos += 4
      else
        room_buffer.writeInt8(0, buffer_pos)
        buffer_pos++
        room_buffer.writeInt32LE(0, buffer_pos)
        buffer_pos += 4

    #console.log(room_buffer.length)
    ygopro.stoc_send(client, "SRVPRO_ROOMLIST", room_buffer)
    setTimeout (()->
      ygopro.stoc_send client, 'ERROR_MSG',{
        msg: 1
        code: 9
      }
      CLIENT_kick(client)
      return), 500
    

  else if info.pass[0...2].toUpperCase()=="R#" and settings.modules.cloud_replay.enabled
    replay_id=info.pass.split("#")[1]
    if (replay_id>0 and replay_id<=9)
      redisdb.lindex client.ip+":replays", replay_id-1, (err, replay_id)->
        if err or !replay_id
          log.info "cloud replay replayid error: " + err if err
          ygopro.stoc_die(client, "${cloud_replay_no}")
          return
        redisdb.hgetall "replay:"+replay_id, client.open_cloud_replay
        return
    else if replay_id
      redisdb.hgetall "replay:"+replay_id, client.open_cloud_replay
    else
      ygopro.stoc_die(client, "${cloud_replay_no}")

  else if info.pass.toUpperCase()=="W" and settings.modules.cloud_replay.enabled
    replay_id=Cloud_replay_ids[Math.floor(Math.random()*Cloud_replay_ids.length)]
    redisdb.hgetall "replay:"+replay_id, client.open_cloud_replay

  else if info.version != settings.version # and (info.version < 9020 or settings.version != 4927) #强行兼容23333版
    ygopro.stoc_send_chat(client, settings.modules.update, ygopro.constants.COLORS.RED)
    ygopro.stoc_send client, 'ERROR_MSG', {
      msg: 4
      code: settings.version
    }
    CLIENT_kick(client)

  else if !info.pass.length and !settings.modules.random_duel.enabled and !settings.modules.windbot.enabled and !settings.modules.challonge.enabled
    ygopro.stoc_die(client, "${blank_room_name}")

  else if info.pass.length and settings.modules.mycard.enabled and info.pass[0...3] != 'AI#'
    ygopro.stoc_send_chat(client, '${loading_user_info}', ygopro.constants.COLORS.BABYBLUE)
    if info.pass.length <= 8
      ygopro.stoc_die(client, '${invalid_password_length}')
      return

    #if info.version >= 9020 and settings.version == 4927 #强行兼容23333版
    #  info.version = settings.version
    #  struct = ygopro.structs["CTOS_JoinGame"]
    #  struct._setBuff(buffer)
    #  struct.set("version", info.version)
    #  buffer = struct.buffer

    buffer = Buffer.from(info.pass[0...8], 'base64')

    if buffer.length != 6
      ygopro.stoc_die(client, '${invalid_password_payload}')
      return

    check = (buf)->
      checksum = 0
      for i in [0...buf.length]
        checksum += buf.readUInt8(i)
      (checksum & 0xFF) == 0

    finish = (buffer)->
      if client.closed
        return
      action = buffer.readUInt8(1) >> 4
      if buffer != decrypted_buffer and action in [1, 2, 4]
        ygopro.stoc_die(client, '${invalid_password_unauthorized}')
        return

      # 1 create public room
      # 2 create private room
      # 3 join room by id
      # 4 create or join room by id (use for match)
      # 5 join room by title
      switch action
        when 1,2
          name = crypto.createHash('md5').update(info.pass + client.name).digest('base64')[0...10].replace('+', '-').replace('/', '_')
          if ROOM_find_by_name(name)
            ygopro.stoc_die(client, '${invalid_password_existed}')
            return

          opt1 = buffer.readUInt8(2)
          opt2 = buffer.readUInt16LE(3)
          opt3 = buffer.readUInt8(5)
          options = {
            lflist: 0
            time_limit: 180
            rule: (opt1 >> 5) & 3
            mode: (opt1 >> 3) & 3
            enable_priority: !!((opt1 >> 2) & 1)
            no_check_deck: !!((opt1 >> 1) & 1)
            no_shuffle_deck: !!(opt1 & 1)
            start_lp: opt2
            start_hand: opt3 >> 4
            draw_count: opt3 & 0xF
          }
          options.lflist = _.findIndex lflists, (list)-> ((options.rule == 1) == list.tcg) and list.date.isBefore()
          room = new Room(name, options)
          if room
            room.title = info.pass.slice(8).replace(String.fromCharCode(0xFEFF), ' ')
            room.private = action == 2
        when 3
          name = info.pass.slice(8)
          room = ROOM_find_by_name(name)
          if(!room)
            ygopro.stoc_die(client, '${invalid_password_not_found}')
            return
        when 4
          room = ROOM_find_or_create_by_name('M#' + info.pass.slice(8))
          if room
            for player in room.get_playing_player() when player and player.name == client.name
              ygopro.stoc_die(client, '${invalid_password_unauthorized}')
              return
            room.private = true
            room.arena = settings.modules.arena_mode.mode
            if room.arena == "athletic"
              room.max_player = 2
              room.welcome = "${athletic_arena_tip}"
        when 5
          title = info.pass.slice(8).replace(String.fromCharCode(0xFEFF), ' ')
          room = ROOM_find_by_title(title)
          if(!room)
            ygopro.stoc_die(client, '${invalid_password_not_found}')
            return
        else
          ygopro.stoc_die(client, '${invalid_password_action}')
          return

      if !room
        ygopro.stoc_die(client, "${server_full}")
      else if room.error
        ygopro.stoc_die(client, room.error)
      else if room.started
        if settings.modules.cloud_replay.enable_halfway_watch and !room.no_watch
          client.setTimeout(300000) #连接后超时5分钟
          client.rid = _.indexOf(ROOM_all, room)
          client.is_post_watcher = true
          if settings.modules.vip.enabled and client.vip and vip_info.players[client.name].words
            for line in _.lines vip_info.players[client.name].words
              ygopro.stoc_send_chat_to_room(room, line, ygopro.constants.COLORS.PINK)
          else if settings.modules.words.enabled and words.words[client.name]
            for line in _.lines words.words[client.name][Math.floor(Math.random() * words.words[client.name].length)]
              ygopro.stoc_send_chat_to_room(room, line, ygopro.constants.COLORS.PINK)
          ygopro.stoc_send_chat_to_room(room, "#{client.name} ${watch_join}")
          room.watchers.push client
          ygopro.stoc_send_chat(client, "${watch_watching}", ygopro.constants.COLORS.BABYBLUE)
          for buffer in room.watcher_buffers
            client.write buffer
        else
          ygopro.stoc_die(client, "${watch_denied}")
      else if room.no_watch and room.players.length >= (if room.hostinfo.mode == 2 then 4 else 2)
        ygopro.stoc_die(client, "${watch_denied_room}")
      else
        #client.room = room
        client.setTimeout(300000) #连接后超时5分钟
        client.rid = _.indexOf(ROOM_all, room)
        room.connect(client)
      return

    if id = users_cache[client.name]
      secret = id % 65535 + 1
      decrypted_buffer = Buffer.allocUnsafe(6)
      for i in [0, 2, 4]
        decrypted_buffer.writeUInt16LE(buffer.readUInt16LE(i) ^ secret, i)
      if check(decrypted_buffer)
        return finish(decrypted_buffer)

    #TODO: query database directly, like preload.
    request
      baseUrl: settings.modules.mycard.auth_base_url,
      url: '/users/' + encodeURIComponent(client.name) + '.json',
      qs:
        api_key: settings.modules.mycard.auth_key,
        api_username: client.name,
        skip_track_visit: true
      json: true
    , (error, response, body)->
      if body and body.user
        users_cache[client.name] = body.user.id
        secret = body.user.id % 65535 + 1
        decrypted_buffer = Buffer.allocUnsafe(6)
        for i in [0, 2, 4]
          decrypted_buffer.writeUInt16LE(buffer.readUInt16LE(i) ^ secret, i)
        if check(decrypted_buffer)
          buffer = decrypted_buffer

      # buffer != decrypted_buffer  ==> auth failed

      if !check(buffer)
        ygopro.stoc_die(client, '${invalid_password_checksum}')
        return

      finish(buffer)

  else if settings.modules.challonge.enabled
    pre_room = ROOM_find_by_name(info.pass)
    if pre_room and pre_room.started and settings.modules.cloud_replay.enable_halfway_watch and !pre_room.no_watch
      room = pre_room
      client.setTimeout(300000) #连接后超时5分钟
      client.rid = _.indexOf(ROOM_all, room)
      client.is_post_watcher = true
      ygopro.stoc_send_chat_to_room(room, "#{client.name} ${watch_join}")
      room.watchers.push client
      ygopro.stoc_send_chat(client, "${watch_watching}", ygopro.constants.COLORS.BABYBLUE)
      for buffer in room.watcher_buffers
        client.write buffer
    else
      ygopro.stoc_send_chat(client, '${loading_user_info}', ygopro.constants.COLORS.BABYBLUE)
      client.setTimeout(300000) #连接后超时5分钟
      challonge.participants._index({
        id: settings.modules.challonge.tournament_id,
        callback: (err, data) ->
          if client.closed
            return
          if err or !data
            if err
              log.warn("Failed loading Challonge user info", err)
            ygopro.stoc_die(client, '${challonge_match_load_failed}')
            return
          found = false
          for k,user of data
            if user.participant and user.participant.name and _.endsWith(user.participant.name, client.name)
              found = user.participant
              break
          if !found
            ygopro.stoc_die(client, '${challonge_user_not_found}')
            return
          client.challonge_info = found
          challonge.matches._index({
            id: settings.modules.challonge.tournament_id,
            callback: (err, data) ->
              if client.closed
                return
              if err or !data
                if err
                  log.warn("Failed loading Challonge match info", err)
                ygopro.stoc_die(client, '${challonge_match_load_failed}')
                return
              found = false
              for k,match of data
                if match and match.match and !match.match.winnerId and match.match.state != "complete" and match.match.player1Id and match.match.player2Id and (match.match.player1Id == client.challonge_info.id or match.match.player2Id == client.challonge_info.id)
                  found = match.match
                  break
              if !found
                ygopro.stoc_die(client, '${challonge_match_not_found}')
                return
              #if found.winnerId
              #  ygopro.stoc_die(client, '${challonge_match_already_finished}')
              #  return
              room = ROOM_find_or_create_by_name('M#' + found.id)
              if room
                room.challonge_info = found
                # room.max_player = 2
                room.welcome = "${challonge_match_created}"
              if !room
                ygopro.stoc_die(client, "${server_full}")
              else if room.error
                ygopro.stoc_die(client, room.error)
              else if room.started
                if settings.modules.cloud_replay.enable_halfway_watch and !room.no_watch
                  #client.setTimeout(300000) #连接后超时5分钟
                  client.rid = _.indexOf(ROOM_all, room)
                  client.is_post_watcher = true
                  if settings.modules.vip.enabled and client.vip and vip_info.players[client.name].words
                    for line in _.lines vip_info.players[client.name].words
                      ygopro.stoc_send_chat_to_room(room, line, ygopro.constants.COLORS.PINK)
                  else if settings.modules.words.enabled and words.words[client.name]
                    for line in _.lines words.words[client.name][Math.floor(Math.random() * words.words[client.name].length)]
                      ygopro.stoc_send_chat_to_room(room, line, ygopro.constants.COLORS.PINK)
                  ygopro.stoc_send_chat_to_room(room, "#{client.name} ${watch_join}")
                  room.watchers.push client
                  ygopro.stoc_send_chat(client, "${watch_watching}", ygopro.constants.COLORS.BABYBLUE)
                  for buffer in room.watcher_buffers
                    client.write buffer
                else
                  ygopro.stoc_die(client, "${watch_denied}")
              else if room.no_watch and room.players.length >= (if room.hostinfo.mode == 2 then 4 else 2)
                ygopro.stoc_die(client, "${watch_denied_room}")
              else
                for player in room.get_playing_player() when player and player != client and player.challonge_info.id == client.challonge_info.id
                  ygopro.stoc_die(client, "${challonge_player_already_in}")
                  return
                #client.room = room
                #client.setTimeout(300000) #连接后超时5分钟
                client.rid = _.indexOf(ROOM_all, room)
                room.connect(client)
              return
          })
          return
      })

  else if !client.name or client.name==""
    ygopro.stoc_die(client, "${bad_user_name}")

  else if ROOM_connected_ip[client.ip] > 5
    log.warn("MULTI LOGIN", client.name, client.ip)
    ygopro.stoc_die(client, "${too_much_connection}" + client.ip)

  else if _.indexOf(settings.ban.banned_user, client.name) > -1 #账号被封
    settings.ban.banned_ip.push(client.ip)
    setting_save(settings)
    log.warn("BANNED USER LOGIN", client.name, client.ip)
    ygopro.stoc_die(client, "${banned_user_login}")

  else if _.indexOf(settings.ban.banned_ip, client.ip) > -1 #IP被封
    log.warn("BANNED IP LOGIN", client.name, client.ip)
    ygopro.stoc_die(client, "${banned_ip_login}")

  else if _.any(badwords.level3, (badword) ->
    regexp = new RegExp(badword, 'i')
    return name.match(regexp)
  , name = client.name)
    log.warn("BAD NAME LEVEL 3", client.name, client.ip)
    ygopro.stoc_die(client, "${bad_name_level3}")

  else if _.any(badwords.level2, (badword) ->
    regexp = new RegExp(badword, 'i')
    return name.match(regexp)
  , name = client.name)
    log.warn("BAD NAME LEVEL 2", client.name, client.ip)
    ygopro.stoc_die(client, "${bad_name_level2}")

  else if _.any(badwords.level1, (badword) ->
    regexp = new RegExp(badword, 'i')
    return name.match(regexp)
  , name = client.name)
    log.warn("BAD NAME LEVEL 1", client.name, client.ip)
    ygopro.stoc_die(client, "${bad_name_level1}")

  else if info.pass.length && !ROOM_validate(info.pass)
    ygopro.stoc_die(client, "${invalid_password_room}")

  else
    #if info.version >= 9020 and settings.version == 4927 #强行兼容23333版
    #  info.version = settings.version
    #  struct = ygopro.structs["CTOS_JoinGame"]
    #  struct._setBuff(buffer)
    #  struct.set("version", info.version)
    #  buffer = struct.buffer
    #  #ygopro.stoc_send_chat(client, "看起来你是YGOMobile的用户，请记得更新先行卡补丁，否则会看到白卡", ygopro.constants.COLORS.GREEN)

    #log.info 'join_game',info.pass, client.name
    room = ROOM_find_or_create_by_name(info.pass, client.ip)
    if !room
      ygopro.stoc_die(client, "${server_full}")
    else if room.error
      ygopro.stoc_die(client, room.error)
    else if room.started
      if settings.modules.cloud_replay.enable_halfway_watch and !room.no_watch
        client.setTimeout(300000) #连接后超时5分钟
        client.rid = _.indexOf(ROOM_all, room)
        client.is_post_watcher = true
        if settings.modules.vip.enabled and client.vip and vip_info.players[client.name].words
          for line in _.lines vip_info.players[client.name].words
            ygopro.stoc_send_chat_to_room(room, line, ygopro.constants.COLORS.PINK)
        else if settings.modules.words.enabled and words.words[client.name]
          for line in _.lines words.words[client.name][Math.floor(Math.random() * words.words[client.name].length)]
            ygopro.stoc_send_chat_to_room(room, line, ygopro.constants.COLORS.PINK)
        ygopro.stoc_send_chat_to_room(room, "#{client.name} ${watch_join}")
        room.watchers.push client
        ygopro.stoc_send_chat(client, "${watch_watching}", ygopro.constants.COLORS.BABYBLUE)
        for buffer in room.watcher_buffers
          client.write buffer
      else
        ygopro.stoc_die(client, "${watch_denied}")
    else if room.no_watch and room.players.length >= (if room.hostinfo.mode == 2 then 4 else 2)
      ygopro.stoc_die(client, "${watch_denied_room}")
    else
      client.setTimeout(300000) #连接后超时5分钟
      client.rid = _.indexOf(ROOM_all, room)
      room.connect(client)
  return

ygopro.stoc_follow 'JOIN_GAME', false, (buffer, info, client, server, datas)->
  #欢迎信息
  room=ROOM_all[client.rid]
  return unless room and !client.reconnecting
  if !room.join_game_buffer
    room.join_game_buffer = buffer
  if settings.modules.vip.enabled and client.vip and vip_info.players[client.name].words
    for line in _.lines vip_info.players[client.name].words
      ygopro.stoc_send_chat_to_room(room, line, ygopro.constants.COLORS.PINK)
  else if settings.modules.words.enabled and words.words[client.name]
    for line in _.lines words.words[client.name][Math.floor(Math.random() * words.words[client.name].length)]
      ygopro.stoc_send_chat_to_room(room, line, ygopro.constants.COLORS.PINK)
  if settings.modules.welcome
    ygopro.stoc_send_chat(client, settings.modules.welcome, ygopro.constants.COLORS.GREEN)
  if room.welcome
    ygopro.stoc_send_chat(client, room.welcome, ygopro.constants.COLORS.BABYBLUE)
  if settings.modules.arena_mode.enabled and !client.is_local #and not client.score_shown
    request
      url: settings.modules.arena_mode.get_score + encodeURIComponent(client.name),
      json: true
    , (error, response, body)->
      if error
        log.warn 'LOAD SCORE ERROR', client.name, error
      else if !body or _.isString body
        log.warn 'LOAD SCORE FAIL', client.name, response.statusCode, response.statusMessage, body
      else
        #log.info 'LOAD SCORE', client.name, body
        rank_txt = if body.arena_rank>0 then "${rank_arena}" + body.arena_rank else "${rank_blank}"
        ygopro.stoc_send_chat(client, "#{client.name}${exp_value_part1}#{body.exp}${exp_value_part2}${exp_value_part3}#{Math.round(body.pt)}#{rank_txt}${exp_value_part4}", ygopro.constants.COLORS.BABYBLUE)
        #client.score_shown = true
      return
  if settings.modules.random_duel.record_match_scores and room.random_type == 'M'
    ygopro.stoc_send_chat_to_room(room, ROOM_player_get_score(client), ygopro.constants.COLORS.GREEN)
    for player in room.players when player.pos != 7 and player != client
      ygopro.stoc_send_chat(client, ROOM_player_get_score(player), ygopro.constants.COLORS.GREEN)
  if !room.recorder
    room.recorder = recorder = net.connect room.port, ->
      ygopro.ctos_send recorder, 'PLAYER_INFO', {
        name: "Marshtomp"
      }
      ygopro.ctos_send recorder, 'JOIN_GAME', {
        version: settings.version,
        pass: "Marshtomp"
      }
      ygopro.ctos_send recorder, 'HS_TOOBSERVER'
      return

    recorder.on 'data', (data)->
      room=ROOM_all[client.rid]
      return unless room and settings.modules.cloud_replay.enabled
      room.recorder_buffers.push data
      return

    recorder.on 'error', (error)->
      return

  if settings.modules.cloud_replay.enable_halfway_watch and !room.watcher and !room.no_watch
    room.watcher = watcher = if settings.modules.test_mode.watch_public_hand then room.recorder else net.connect room.port, ->
      ygopro.ctos_send watcher, 'PLAYER_INFO', {
        name: "the Big Brother"
      }
      ygopro.ctos_send watcher, 'JOIN_GAME', {
        version: settings.version,
        pass: "the Big Brother"
      }
      ygopro.ctos_send watcher, 'HS_TOOBSERVER'
      return

    watcher.on 'data', (data)->
      room=ROOM_all[client.rid]
      return unless room
      room.watcher_buffers.push data
      for w in room.watchers
        w.write data if w #a WTF fix
      return

    watcher.on 'error', (error)->
#log.error "watcher error", error
      return
  return

# 登场台词
load_words = () ->
  request
    url: settings.modules.words.get
    json: true
  , (error, response, body)->
    if _.isString body
      log.warn "words bad json", body
    else if error or !body
      log.warn 'words error', error, response
    else
      setting_change(words, "words", body)
      log.info "words loaded", _.size words.words
    return
  return

if settings.modules.words.get
  load_words()

load_dialogues = () ->
  request
    url: settings.modules.dialogues.get
    json: true
  , (error, response, body)->
    if _.isString body
      log.warn "dialogues bad json", body
    else if error or !body
      log.warn 'dialogues error', error, response
    else
      setting_change(dialogues, "dialogues", body)
      log.info "dialogues loaded", _.size dialogues.dialogues
    return
  return

load_dialogues_custom = () ->
  request
    url: settings.modules.dialogues.get_custom
    json: true
  , (error, response, body)->
    if _.isString body
      log.warn "custom dialogues bad json", body
    else if error or !body
      log.warn 'custom dialogues error', error, response
    else
      setting_change(dialogues, "dialogues_custom", body)
      log.info "custom dialogues loaded", _.size dialogues.dialogues_custom
    return
  return

if settings.modules.dialogues.get
  load_dialogues()

if settings.modules.dialogues.get_custom
  load_dialogues_custom()

ygopro.stoc_follow 'GAME_MSG', true, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return false unless room
  if settings.modules.pre_release_compat.enabled and client.is_using_pre_release
    replace_buffer(buffer, room.list_official_to_pre, 1)
  return false if client.reconnecting
  msg = buffer.readInt8(0)
  if settings.modules.retry_handle.enabled
    if ygopro.constants.MSG[msg] == 'RETRY'
      if !client.retry_count?
        client.retry_count = 0
      client.retry_count++
      log.warn "MSG_RETRY detected", client.name, client.ip, msg, client.retry_count
      if settings.modules.retry_handle.max_retry_count and client.retry_count >= settings.modules.retry_handle.max_retry_count
        ygopro.stoc_send_chat_to_room(room, client.name + "${retry_too_much_room_part1}" + settings.modules.retry_handle.max_retry_count + "${retry_too_much_room_part2}", ygopro.constants.COLORS.BABYBLUE)
        ygopro.stoc_send_chat(client, "${retry_too_much_part1}" + settings.modules.retry_handle.max_retry_count + "${retry_too_much_part2}", ygopro.constants.COLORS.RED)
        CLIENT_send_replays(client, room)
        CLIENT_kick(client)
        return true
      if client.last_game_msg
        if settings.modules.retry_handle.max_retry_count
          ygopro.stoc_send_chat(client, "${retry_part1}" + client.retry_count + "${retry_part2}" + settings.modules.retry_handle.max_retry_count + "${retry_part3}", ygopro.constants.COLORS.RED)
        else
          ygopro.stoc_send_chat(client, "${retry_not_counted}", ygopro.constants.COLORS.BABYBLUE)
        if client.last_hint_msg
          ygopro.stoc_send(client, 'GAME_MSG', client.last_hint_msg)
        ygopro.stoc_send(client, 'GAME_MSG', client.last_game_msg)
        return true
    else
      client.last_game_msg = buffer
      client.last_game_msg_title = ygopro.constants.MSG[msg]
      # log.info(client.name, client.last_game_msg_title)
  else if ygopro.constants.MSG[msg] != 'RETRY'
    client.last_game_msg = buffer
    client.last_game_msg_title = ygopro.constants.MSG[msg]
    # log.info(client.name, client.last_game_msg_title)

  if (msg >= 10 and msg < 30) or msg == 132 or (msg >= 140 and msg <= 144) #SELECT和ANNOUNCE开头的消息
    room.waiting_for_player = client
    room.last_active_time = moment()
  #log.info("#{ygopro.constants.MSG[msg]}等待#{room.waiting_for_player.name}")

  #log.info 'MSG', ygopro.constants.MSG[msg]
  if ygopro.constants.MSG[msg] == 'START'
    playertype = buffer.readUInt8(1)
    client.is_first = !(playertype & 0xf)
    client.lp = room.hostinfo.start_lp
    client.card_count = 0 if room.hostinfo.mode != 2
    room.selecting_tp = false
    if client.pos == 0
      room.turn = 0
      room.duel_count = room.duel_count + 1
      if room.death and room.duel_count > 1
        if room.death == -1
          ygopro.stoc_send_chat_to_room(room, "${death_start_final}", ygopro.constants.COLORS.BABYBLUE)
        else
          ygopro.stoc_send_chat_to_room(room, "${death_start_extra}", ygopro.constants.COLORS.BABYBLUE)
    if settings.modules.retry_handle.enabled
      client.retry_count = 0
      client.last_game_msg = null

  #ygopro.stoc_send_chat_to_room(room, "LP跟踪调试信息: #{client.name} 初始LP #{client.lp}")

  if ygopro.constants.MSG[msg] == 'HINT'
    hint_type = buffer.readUInt8(1)
    if hint_type == 3
      client.last_hint_msg = buffer

  if ygopro.constants.MSG[msg] == 'NEW_TURN'
    r_player = buffer.readUInt8(1)
    if client.pos == 0 and (r_player & 0x2) == 0
      room.turn = room.turn + 1
      if room.death and room.death != -2
        if room.turn >= room.death
          oppo_pos = if room.hostinfo.mode == 2 then 2 else 1
          if room.dueling_players[0].lp != room.dueling_players[oppo_pos].lp and room.turn > 1
            win_pos = if room.dueling_players[0].lp > room.dueling_players[oppo_pos].lp then 0 else oppo_pos
            ygopro.stoc_send_chat_to_room(room, "${death_finish_part1}" + room.dueling_players[win_pos].name + "${death_finish_part2}", ygopro.constants.COLORS.BABYBLUE)
            ygopro.ctos_send(room.dueling_players[oppo_pos - win_pos].server, 'SURRENDER')
          else
            room.death = -1
            ygopro.stoc_send_chat_to_room(room, "${death_remain_final}", ygopro.constants.COLORS.BABYBLUE)
        else
          ygopro.stoc_send_chat_to_room(room, "${death_remain_part1}" + (room.death - room.turn) + "${death_remain_part2}", ygopro.constants.COLORS.BABYBLUE)
    if client.surrend_confirm
      client.surrend_confirm = false
      ygopro.stoc_send_chat(client, "${surrender_canceled}", ygopro.constants.COLORS.BABYBLUE)

  if ygopro.constants.MSG[msg] == 'NEW_PHASE'
    phase = buffer.readInt16LE(1)
    oppo_pos = if room.hostinfo.mode == 2 then 2 else 1
    if client.pos == 0 and room.death == -2 and not (phase == 0x1 and room.turn < 2)
      if room.dueling_players[0].lp != room.dueling_players[oppo_pos].lp
        win_pos = if room.dueling_players[0].lp > room.dueling_players[oppo_pos].lp then 0 else oppo_pos
        ygopro.stoc_send_chat_to_room(room, "${death_finish_part1}" + room.dueling_players[win_pos].name + "${death_finish_part2}", ygopro.constants.COLORS.BABYBLUE)
        ygopro.ctos_send(room.dueling_players[oppo_pos - win_pos].server, 'SURRENDER')
      else
        room.death = -1
        ygopro.stoc_send_chat_to_room(room, "${death_remain_final}", ygopro.constants.COLORS.BABYBLUE)

  if ygopro.constants.MSG[msg] == 'WIN' and client.pos == 0
    pos = buffer.readUInt8(1)
    pos = 1 - pos unless client.is_first or pos == 2 or room.turn <= 0 or !room.turn
    pos = pos * 2 if pos >= 0 and room.hostinfo.mode == 2
    reason = buffer.readUInt8(2)
    #log.info {winner: pos, reason: reason}
    #room.duels.push {winner: pos, reason: reason}
    room.winner = pos
    room.turn = 0
    if settings.modules.heartbeat_detection.enabled
      for player in room.players
        player.heartbeat_protected = false
      delete room.long_resolve_card
      delete room.long_resolve_chain
    if room and !room.finished and room.dueling_players[pos]
      room.winner_name = room.dueling_players[pos].name_vpass
      #log.info room.dueling_players, pos
      room.scores[room.winner_name] = room.scores[room.winner_name] + 1
      if settings.modules.vip.enabled and room.dueling_players[pos].vip and vip_info.players[room.dueling_players[pos].name].victory
        for line in _.lines vip_info.players[room.dueling_players[pos].name].victory
          ygopro.stoc_send_chat_to_room(room, line, ygopro.constants.COLORS.PINK)
      else if room.hostinfo.mode == 2 and settings.modules.vip.enabled and room.dueling_players[pos + 1].vip and vip_info.players[room.dueling_players[pos + 1].name].victory
        for line in _.lines vip_info.players[room.dueling_players[pos + 1].name].victory
          ygopro.stoc_send_chat_to_room(room, line, ygopro.constants.COLORS.PINK)
    if room.death
      if settings.modules.http.quick_death_rule == 1 or settings.modules.http.quick_death_rule == 3
        room.death = -1
      else
        room.death = 5

  #lp跟踪
  if ygopro.constants.MSG[msg] == 'DAMAGE' and client.pos == 0
    pos = buffer.readUInt8(1)
    pos = 1 - pos unless client.is_first
    pos = pos * 2 if pos >= 0 and room.hostinfo.mode == 2
    val = buffer.readInt32LE(2)
    room.dueling_players[pos].lp -= val
    room.dueling_players[pos].lp = 0 if room.dueling_players[pos].lp < 0
    if 0 < room.dueling_players[pos].lp <= 100
      ygopro.stoc_send_chat_to_room(room, "${lp_low_opponent}", ygopro.constants.COLORS.PINK)

  if ygopro.constants.MSG[msg] == 'RECOVER' and client.pos == 0
    pos = buffer.readUInt8(1)
    pos = 1 - pos unless client.is_first
    pos = pos * 2 if pos >= 0 and room.hostinfo.mode == 2
    val = buffer.readInt32LE(2)
    room.dueling_players[pos].lp += val

  if ygopro.constants.MSG[msg] == 'LPUPDATE' and client.pos == 0
    pos = buffer.readUInt8(1)
    pos = 1 - pos unless client.is_first
    pos = pos * 2 if pos >= 0 and room.hostinfo.mode == 2
    val = buffer.readInt32LE(2)
    room.dueling_players[pos].lp = val

  if ygopro.constants.MSG[msg] == 'PAY_LPCOST' and client.pos == 0
    pos = buffer.readUInt8(1)
    pos = 1 - pos unless client.is_first
    pos = pos * 2 if pos >= 0 and room.hostinfo.mode == 2
    val = buffer.readInt32LE(2)
    room.dueling_players[pos].lp -= val
    room.dueling_players[pos].lp = 0 if room.dueling_players[pos].lp < 0
    if 0 < room.dueling_players[pos].lp <= 100
      ygopro.stoc_send_chat_to_room(room, "${lp_low_self}", ygopro.constants.COLORS.PINK)

  #track card count
  #todo: track card count in tag mode
  if ygopro.constants.MSG[msg] == 'MOVE' and room.hostinfo.mode != 2
    pos = buffer.readUInt8(5)
    pos = 1 - pos unless client.is_first
    loc = buffer.readUInt8(6)
    client.card_count-- if (loc & 0xe) and pos == 0
    pos = buffer.readUInt8(9)
    pos = 1 - pos unless client.is_first
    loc = buffer.readUInt8(10)
    client.card_count++ if (loc & 0xe) and pos == 0

  if ygopro.constants.MSG[msg] == 'DRAW' and room.hostinfo.mode != 2
    pos = buffer.readUInt8(1)
    pos = 1 - pos unless client.is_first
    if pos == 0
      count = buffer.readInt8(2)
      client.card_count += count

  # check panel confirming cards in heartbeat
  if settings.modules.heartbeat_detection.enabled and ygopro.constants.MSG[msg] == 'CONFIRM_CARDS'
    check = false
    count = buffer.readInt8(2)
    max_loop = 3 + (count - 1) * 7
    deck_found = 0
    limbo_found = 0 # support custom cards which may be in location 0 in KoishiPro or EdoPro
    for i in [3..max_loop] by 7
      loc = buffer.readInt8(i + 5)
      if (loc & 0x41) > 0
        deck_found++
      else if loc == 0
        limbo_found++
      if (deck_found > 0 and count > 1) or limbo_found > 0
        check = true
        break
    if check
      #console.log("Confirming cards:" + client.name)
      client.heartbeat_protected = true

  # chain detection
  if settings.modules.heartbeat_detection.enabled and client.pos == 0
    if ygopro.constants.MSG[msg] == 'CHAINING'
      card = buffer.readUInt32LE(1)
      found = false
      for id in long_resolve_cards when id == card
        found = true
        break
      if found
        room.long_resolve_card = card
        # console.log(0,card)
      else
        delete room.long_resolve_card
    else if ygopro.constants.MSG[msg] == 'CHAINED' and room.long_resolve_card
      chain = buffer.readInt8(1)
      if !room.long_resolve_chain
        room.long_resolve_chain = []
      room.long_resolve_chain[chain] = true
      # console.log(1,chain)
      delete room.long_resolve_card
    else if ygopro.constants.MSG[msg] == 'CHAIN_SOLVING' and room.long_resolve_chain
      chain = buffer.readInt8(1)
      # console.log(2,chain)
      if room.long_resolve_chain[chain]
        for player in room.get_playing_player()
          player.heartbeat_protected = true
    else if (ygopro.constants.MSG[msg] == 'CHAIN_NEGATED' or ygopro.constants.MSG[msg] == 'CHAIN_DISABLED') and room.long_resolve_chain
      chain = buffer.readInt8(1)
      # console.log(3,chain)
      delete room.long_resolve_chain[chain]
    else if ygopro.constants.MSG[msg] == 'CHAIN_END'
      # console.log(4,chain)
      delete room.long_resolve_card
      delete room.long_resolve_chain

  #登场台词
  if settings.modules.dialogues.enabled or settings.modules.vip.enabled
    if ygopro.constants.MSG[msg] == 'SUMMONING' or ygopro.constants.MSG[msg] == 'SPSUMMONING' or ygopro.constants.MSG[msg] == 'CHAINING'
      card = buffer.readUInt32LE(1)
      trigger_location = buffer.readUInt8(6)
      act_pos = buffer.readUInt8(if ygopro.constants.MSG[msg] == 'CHAINING' then 9 else 5)
      if !room.dueling_players[0].is_first
        act_pos = 1 - act_pos
      if room.hostinfo.mode == 2
        act_pos = act_pos * 2
      if ygopro.constants.MSG[msg] != 'CHAINING' or (trigger_location & 0x8) and client.ready_trap
        if settings.modules.vip.enabled and room.dueling_players[act_pos].vip and vip_info.players[room.dueling_players[act_pos].name].dialogues[card]
          for line in _.lines vip_info.players[room.dueling_players[act_pos].name].dialogues[card]
            ygopro.stoc_send_chat(client, line, ygopro.constants.COLORS.PINK)
        else if settings.modules.vip.enabled and room.hostinfo.mode == 2 and room.dueling_players[act_pos + 1].vip and vip_info.players[room.dueling_players[act_pos + 1].name].dialogues[card]
          for line in _.lines vip_info.players[room.dueling_players[act_pos + 1].name].dialogues[card]
            ygopro.stoc_send_chat(client, line, ygopro.constants.COLORS.PINK)
        else if settings.modules.dialogues.enabled and dialogues.dialogues[card]
          for line in _.lines dialogues.dialogues[card][Math.floor(Math.random() * dialogues.dialogues[card].length)]
            ygopro.stoc_send_chat(client, line, ygopro.constants.COLORS.PINK)
        else if settings.modules.dialogues.enabled and dialogues.dialogues_custom[card]
          for line in _.lines dialogues.dialogues_custom[card][Math.floor(Math.random() * dialogues.dialogues_custom[card].length)]
            ygopro.stoc_send_chat(client, line, ygopro.constants.COLORS.PINK)
    if ygopro.constants.MSG[msg] == 'POS_CHANGE'
      loc = buffer.readUInt8(6)
      ppos = buffer.readUInt8(8)
      cpos = buffer.readUInt8(9)
      client.ready_trap = !!(loc & 0x8) and !!(ppos & 0xa) and !!(cpos & 0x5)
    else if ygopro.constants.MSG[msg] != 'UPDATE_CARD' and ygopro.constants.MSG[msg] != 'WAITING'
      client.ready_trap = false
  return false

#房间管理
ygopro.ctos_follow 'HS_TOOBSERVER', true, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  if room.no_watch or settings.modules.windbot.doom_bots
    ygopro.stoc_send_chat(client, "${watch_denied_room}", ygopro.constants.COLORS.RED)
    return true
  if (!room.arena and !settings.modules.challonge.enabled) or client.is_local
    return false
  for player in room.players
    if player == client
      ygopro.stoc_send_chat(client, "${cannot_to_observer}", ygopro.constants.COLORS.BABYBLUE)
      return true
  return false

ygopro.ctos_follow 'HS_KICK', true, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  for player in room.players
    if player and player.pos == info.pos and player != client
      if room.arena == "athletic" or settings.modules.challonge.enabled or settings.modules.windbot.doom_bots
        ygopro.stoc_send_chat_to_room(room, "#{client.name} ${kicked_by_system}", ygopro.constants.COLORS.RED)
        CLIENT_kick(client)
        return true
      client.kick_count = if client.kick_count then client.kick_count+1 else 1
      if client.kick_count>=5 and room.random_type
        ygopro.stoc_send_chat_to_room(room, "#{client.name} ${kicked_by_system}", ygopro.constants.COLORS.RED)
        ROOM_ban_player(player.name, player.ip, "${random_ban_reason_zombie}")
        CLIENT_kick(client)
        return true
      ygopro.stoc_send_chat_to_room(room, "#{player.name} ${kicked_by_player}", ygopro.constants.COLORS.RED)
  return false

ygopro.stoc_follow 'TYPE_CHANGE', true, (buffer, info, client, server, datas)->
  selftype = info.type & 0xf
  is_host = ((info.type >> 4) & 0xf) != 0
  # if room and room.no_watch and selftype == 7
  #   ygopro.stoc_die(client, "${watch_denied_room}")
  #   return true
  client.is_host = is_host
  client.pos = selftype
  #console.log "TYPE_CHANGE to #{client.name}:", info, selftype, is_host
  return false

ygopro.stoc_follow 'HS_PLAYER_CHANGE', false, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room and room.max_player and client.is_host
  pos = info.status >> 4
  is_ready = (info.status & 0xf) == 9
  if pos < room.max_player
    if room.arena
      room.ready_player_count = 0
      for player in room.players
        if player.pos == pos
          player.is_ready = is_ready
      p1 = room.players[0]
      p2 = room.players[1]
      if !p1 or !p2
        if room.waiting_for_player_interval
          clearInterval room.waiting_for_player_interval
          room.waiting_for_player_interval = null
        return
      room.waiting_for_player2 = room.waiting_for_player
      room.waiting_for_player = null
      if p1.is_ready and p2.is_ready
        room.waiting_for_player = if p1.is_host then p1 else p2
      if !p1.is_ready and p2.is_ready
        room.waiting_for_player = p1
      if !p2.is_ready and p1.is_ready
        room.waiting_for_player = p2
      if room.waiting_for_player != room.waiting_for_player2
        room.waiting_for_player2 = room.waiting_for_player
        room.waiting_for_player_time = settings.modules.arena_mode.ready_time
        room.waiting_for_player_interval = setInterval (()-> wait_room_start_arena(ROOM_all[client.rid]);return), 1000
      else if !room.waiting_for_player and room.waiting_for_player_interval
        clearInterval room.waiting_for_player_interval
        room.waiting_for_player_interval = null
        room.waiting_for_player_time = settings.modules.arena_mode.ready_time
    else
      room.ready_player_count_without_host = 0
      for player in room.players
        if player.pos == pos
          player.is_ready = is_ready
        unless player.is_host
          room.ready_player_count_without_host += player.is_ready
      if room.ready_player_count_without_host >= room.max_player - 1
        #log.info "all ready"
        setTimeout (()-> wait_room_start(ROOM_all[client.rid], settings.modules.random_duel.ready_time);return), 1000
  return

ygopro.ctos_follow 'REQUEST_FIELD', true, (buffer, info, client, server, datas)->
  return true

ygopro.stoc_follow 'FIELD_FINISH', true, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return true unless room and settings.modules.reconnect.enabled
  client.reconnecting = false
  if client.time_confirm_required # client did not send TIME_CONFIRM
    client.waiting_for_last = true
  else if client.last_game_msg and client.last_game_msg_title != 'WAITING' # client sent TIME_CONFIRM
    if client.last_hint_msg
      ygopro.stoc_send(client, 'GAME_MSG', client.last_hint_msg)
    ygopro.stoc_send(client, 'GAME_MSG', client.last_game_msg)
  return true

ygopro.stoc_follow 'DUEL_END', false, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room and settings.modules.replay_delay and room.hostinfo.mode == 1
  SOCKET_flush_data(client, datas)
  CLIENT_send_replays(client, room)
  if !room.replays_sent_to_watchers
    room.replays_sent_to_watchers = true
    for player in room.players when player and player.pos > 3
      CLIENT_send_replays(player, room)
    for player in room.watchers when player
      CLIENT_send_replays(player, room)

wait_room_start = (room, time)->
  unless !room or room.started or room.ready_player_count_without_host < room.max_player - 1
    time -= 1
    if time
      unless time % 5
        ygopro.stoc_send_chat_to_room(room, "#{if time <= 9 then ' ' else ''}#{time}${kick_count_down}", if time <= 9 then ygopro.constants.COLORS.RED else ygopro.constants.COLORS.LIGHTBLUE)
      setTimeout (()-> wait_room_start(room, time);return), 1000
    else
      for player in room.players
        if player and player.is_host
          ROOM_ban_player(player.name, player.ip, "${random_ban_reason_zombie}")
          ygopro.stoc_send_chat_to_room(room, "#{player.name} ${kicked_by_system}", ygopro.constants.COLORS.RED)
          CLIENT_kick(player)
  return

wait_room_start_arena = (room)->
  unless !room or room.started or !room.waiting_for_player
    room.waiting_for_player_time = room.waiting_for_player_time - 1
    if room.waiting_for_player_time > 0
      unless room.waiting_for_player_time % 5
        ygopro.stoc_send_chat_to_room(room, "#{if room.waiting_for_player_time <= 9 then ' ' else ''}#{room.waiting_for_player_time}${kick_count_down_arena_part1} #{room.waiting_for_player.name} ${kick_count_down_arena_part2}", if room.waiting_for_player_time <= 9 then ygopro.constants.COLORS.RED else ygopro.constants.COLORS.LIGHTBLUE)
    else
      ygopro.stoc_send_chat_to_room(room, "#{room.waiting_for_player.name} ${kicked_by_system}", ygopro.constants.COLORS.RED)
      CLIENT_kick(room.waiting_for_player)
      if room.waiting_for_player_interval
        clearInterval room.waiting_for_player_interval
        room.waiting_for_player_interval = null
  return

#tip
ygopro.stoc_send_random_tip = (client)->
  tip_type = "tips"
  if settings.modules.tips.split_zh and tips.tips_zh.length and client.lang == "zh-cn"
    tip_type = "tips_zh"
  if settings.modules.tips.enabled && tips.tips.length && !client.is_local && !client.closed
    ygopro.stoc_send_chat(client, "Tip: " + tips[tip_type][Math.floor(Math.random() * tips[tip_type].length)])
  return
ygopro.stoc_send_random_tip_to_room = (room)->
  if settings.modules.tips.enabled && tips.tips.length
    for player in room.players when player and !player.is_local and !player.closed
      ygopro.stoc_send_random_tip(player)
    for player in room.watchers when player and !player.is_local and !player.closed
      ygopro.stoc_send_random_tip(player)
  return

load_tips = ()->
  request
    url: settings.modules.tips.get
    json: true
  , (error, response, body)->
    if _.isString body
      log.warn "tips bad json", body
    else if error or !body
      log.warn 'tips error', error, response
    else
      setting_change(tips, "tips", body)
      log.info "tips loaded", tips.tips.length
    return
  return

load_tips_zh = ()->
  request
    url: settings.modules.tips.get_zh
    json: true
  , (error, response, body)->
    if _.isString body
      log.warn "zh tips bad json", body
    else if error or !body
      log.warn 'zh tips error', error, response
    else
      setting_change(tips, "tips_zh", body)
      log.info "zh tips loaded", tips.tips_zh.length
    return
  return

if settings.modules.tips.get
  load_tips()
if settings.modules.tips.get_zh
  load_tips_zh()
if settings.modules.tips.enabled
  setInterval ()->
    for room in ROOM_all when room and room.established
      ygopro.stoc_send_random_tip_to_room(room) if !room.started or room.changing_side
    return
  , 30000

ygopro.stoc_follow 'DUEL_START', false, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room and !client.reconnecting
  unless room.started #first start
    room.started = true
    room.start_time = moment().format()
    room.turn = 0
    roomlist.start room if !room.windbot and settings.modules.http.websocket_roomlist
    #room.duels = []
    room.dueling_players = []
    for player in room.players when player.pos != 7
      room.dueling_players[player.pos] = player
      room.scores[player.name_vpass] = 0
      room.player_datas.push ip: player.ip, name: player.name
      if room.random_type == 'T'
        # 双打房不记录匹配过
        ROOM_players_oppentlist[player.ip] = null
  if settings.modules.tips.enabled
    ygopro.stoc_send_random_tip(client)
  deck_text = null
  if client.main and client.main.length
    deck_text = '#ygopro-server deck log\n#main\n' + client.main.join('\n') + '\n!side\n' + client.side.join('\n') + '\n'
    room.decks[client.name] = deck_text
  if settings.modules.deck_log.enabled and deck_text and not client.deck_saved and not room.windbot
    deck_arena = settings.modules.deck_log.arena + '-'
    if room.arena
      deck_arena = deck_arena + room.arena
    else if room.hostinfo.mode == 2
      deck_arena = deck_arena + 'tag'
    else if room.random_type == 'S'
      deck_arena = deck_arena + 'entertain'
    else if room.random_type == 'M'
      deck_arena = deck_arena + 'athletic'
    else
      deck_arena = deck_arena + 'custom'
    #log.info "DECK LOG START", client.name, room.arena
    if settings.modules.deck_log.local
      deck_name = moment().format('YYYY-MM-DD HH-mm-ss') + ' ' + room.process_pid + ' ' + client.pos + ' ' + client.ip.slice(7) + ' ' + client.name.replace(/[\/\\\?\*]/g, '_')
      fs.writeFile settings.modules.deck_log.local + deck_name + '.ydk', deck_text, 'utf-8', (err) ->
        if err
          log.warn 'DECK SAVE ERROR', err
    if settings.modules.deck_log.post
      request.post { url : settings.modules.deck_log.post , form : {
        accesskey: settings.modules.deck_log.accesskey,
        deck: deck_text,
        playername: client.name,
        arena: deck_arena
      }}, (error, response, body)->
        if error
          log.warn 'DECK POST ERROR', error
        else
          if response.statusCode != 200
            log.warn 'DECK POST FAIL', response.statusCode, client.name, body
          #else
            #log.info 'DECK POST OK', response.statusCode, client.name, body
        return
    client.deck_saved = true
  return

ygopro.ctos_follow 'SURRENDER', true, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  if !room.started
    return true
  if room.random_type and room.turn < 3 and not client.flee_free and not settings.modules.test_mode.surrender_anytime and not (room.random_type=='M' and settings.modules.random_duel.record_match_scores)
    ygopro.stoc_send_chat(client, "${surrender_denied}", ygopro.constants.COLORS.BABYBLUE)
    return true
  if room.hostinfo.mode == 2
    if !settings.modules.tag_duel_surrender
      return true
    else if !client.surrend_confirm and !CLIENT_get_partner(client).closed and !CLIENT_get_partner(client).is_local
      sur_player = CLIENT_get_partner(client)
      ygopro.stoc_send_chat(sur_player, "${surrender_confirm_tag}", ygopro.constants.COLORS.BABYBLUE)
      ygopro.stoc_send_chat(client, "${surrender_confirm_sent}", ygopro.constants.COLORS.BABYBLUE)
      sur_player.surrend_confirm = true
      return true
  return false

report_to_big_brother = (roomname, sender, ip, level, content, match) ->
  return unless settings.modules.big_brother.enabled
  request.post { url : settings.modules.big_brother.post , form : {
    accesskey: settings.modules.big_brother.accesskey,
    roomname: roomname,
    sender: sender,
    ip: ip,
    level: level,
    content: content,
    match: match
  }}, (error, response, body)->
    if error
      log.warn 'BIG BROTHER ERROR', error
    else
      if response.statusCode != 200
        log.warn 'BIG BROTHER FAIL', response.statusCode, roomname, body
      #else
        #log.info 'BIG BROTHER OK', response.statusCode, roomname, body
    return
  return

ygopro.ctos_follow 'CHAT', true, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  msg = _.trim(info.msg)
  cancel = _.startsWith(msg, "/")
  room.last_active_time = moment() unless cancel or not (room.random_type or room.arena)
  cmd = msg.split(' ')
  switch cmd[0]
    when '/投降', '/surrender'
      if !room.started or (room.hostinfo.mode==2 and !settings.modules.tag_duel_surrender)
        return cancel
      if room.random_type and room.turn < 3 and !client.flee_free
        ygopro.stoc_send_chat(client, "${surrender_denied}", ygopro.constants.COLORS.BABYBLUE)
        return cancel
      if client.surrend_confirm
        ygopro.ctos_send(client.server, 'SURRENDER')
      else
        sur_player = CLIENT_get_partner(client)
        if sur_player.closed or sur_player.is_local
          sur_player = client
        if room.hostinfo.mode==2 and sur_player != client
          ygopro.stoc_send_chat(sur_player, "${surrender_confirm_tag}", ygopro.constants.COLORS.BABYBLUE)
          ygopro.stoc_send_chat(client, "${surrender_confirm_sent}", ygopro.constants.COLORS.BABYBLUE)
        else
          ygopro.stoc_send_chat(client, "${surrender_confirm}", ygopro.constants.COLORS.BABYBLUE)
        sur_player.surrend_confirm = true

    when '/help'
      ygopro.stoc_send_chat(client, "${chat_order_main}")
      ygopro.stoc_send_chat(client, "${chat_order_help}")
      ygopro.stoc_send_chat(client, "${chat_order_roomname}") if !settings.modules.mycard.enabled
      ygopro.stoc_send_chat(client, "${chat_order_windbot}") if settings.modules.windbot.enabled
      ygopro.stoc_send_chat(client, "${chat_order_tip}") if settings.modules.tips.enabled
      ygopro.stoc_send_chat(client, "${chat_order_chatcolor_1}") if settings.modules.chat_color.enabled and (!(settings.modules.vip.enabled and settings.modules.chat_color.restrict_to_vip) or client.vip)
      ygopro.stoc_send_chat(client, "${chat_order_chatcolor_2}") if settings.modules.chat_color.enabled and (!(settings.modules.vip.enabled and settings.modules.chat_color.restrict_to_vip) or client.vip)
      ygopro.stoc_send_chat(client, "${chat_order_vip}") if settings.modules.vip.enabled

    when '/tip'
      ygopro.stoc_send_random_tip(client) if settings.modules.tips.enabled

    when '/ai'
      if settings.modules.windbot.enabled and client.is_host and !settings.modules.challonge.enabled and !room.arena and room.random_type != 'M'
        if name = cmd[1]
          windbot = _.sample _.filter windbots, (w)->
            w.name == name or w.deck == name
          if !windbot
            ygopro.stoc_send_chat(client, "${windbot_deck_not_found}", ygopro.constants.COLORS.RED)
            return
        else
          windbot = _.sample windbots
        room.add_windbot(windbot)

    when '/roomname'
      ygopro.stoc_send_chat(client, "${room_name} " + room.name, ygopro.constants.COLORS.BABYBLUE) if room

    when '/color'
      if settings.modules.chat_color.enabled
        cip = CLIENT_get_authorize_key(client)
        if settings.modules.vip.enabled and settings.modules.chat_color.restrict_to_vip and !client.vip
          CLIENT_send_vip_status(client)
        else if cmsg = cmd[1]
          if cmsg.toLowerCase() == "help"
            ygopro.stoc_send_chat(client, "${show_color_list}", ygopro.constants.COLORS.BABYBLUE)
            for cname,cvalue of ygopro.constants.COLORS when cvalue > 10
              ygopro.stoc_send_chat(client, cname, cvalue)
          else if cmsg.toLowerCase() == "default"
            if settings.modules.vip.enabled and settings.modules.chat_color.restrict_to_vip
              delete vip_info.players[client.name].chat_color
              setting_save(vip_info)
            else
              delete chat_color.save_list[cip]
            setting_save(chat_color)
            ygopro.stoc_send_chat(client, "${set_chat_color_default}", ygopro.constants.COLORS.BABYBLUE)
          else
            ccolor = cmsg.toUpperCase()
            if ygopro.constants.COLORS[ccolor] and ygopro.constants.COLORS[ccolor] > 10 and ygopro.constants.COLORS[ccolor] < 20
              if settings.modules.vip.enabled and settings.modules.chat_color.restrict_to_vip
                vip_info.players[client.name].chat_color = ccolor
                setting_save(vip_info)
              else
                chat_color.save_list[cip] = ccolor
              setting_save(chat_color)
              ygopro.stoc_send_chat(client, "${set_chat_color_part1}" + ccolor + "${set_chat_color_part2}", ygopro.constants.COLORS.BABYBLUE)
            else
              ygopro.stoc_send_chat(client, "${color_not_found_part1}" + ccolor + "${color_not_found_part2}", ygopro.constants.COLORS.RED)
        else
          if color = (if settings.modules.vip.enabled and settings.modules.chat_color.restrict_to_vip then vip_info.players[client.name].chat_color else chat_color.save_list[cip])
            ygopro.stoc_send_chat(client, "${get_chat_color_part1}" + color + "${get_chat_color_part2}", ygopro.constants.COLORS.BABYBLUE)
          else
            ygopro.stoc_send_chat(client, "${get_chat_color_default}", ygopro.constants.COLORS.BABYBLUE)
    when '/vip'
      if settings.modules.vip.enabled
        if name = cmd[1]
          uname = name.toLowerCase()
          switch uname
            when 'help'
              ygopro.stoc_send_chat(client, "${chat_order_vip_help}")
              ygopro.stoc_send_chat(client, "${chat_order_vip_status}")
              ygopro.stoc_send_chat(client, "${chat_order_vip_buy}")
              ygopro.stoc_send_chat(client, "${chat_order_vip_password}")
              ygopro.stoc_send_chat(client, "${chat_order_vip_dialogues}")
              ygopro.stoc_send_chat(client, "${chat_order_vip_words}")
              ygopro.stoc_send_chat(client, "${chat_order_vip_victory}")
            when 'status'
              CLIENT_send_vip_status(client, true)
            when 'buy'
              if vip_info.players[client.name] and vip_info.players[client.name].password != client.vpass
                ygopro.stoc_send_chat(client, "${vip_account_existed}", ygopro.constants.COLORS.RED)
              else if (!client.vpass and client.name.length > 13) or (client.vpass and (client.name.length + client.vpass.length) > 18)
                ygopro.stoc_send_chat(client, "${vip_player_name_too_long}", ygopro.constants.COLORS.RED)
              else
                key = cmd[2]
                buy_result = CLIENT_use_cdkey(client, key)
                switch buy_result
                  when 0
                    ygopro.stoc_send_chat(client, "${vip_key_not_found}", ygopro.constants.COLORS.RED)
                  when 1
                    ygopro.stoc_send_chat(client, "${vip_success_new_part1}" + client.name + "$" + client.vpass + "${vip_success_new_part2}", ygopro.constants.COLORS.BABYBLUE)
                  when 2
                    ygopro.stoc_send_chat(client, "${vip_success_renew}", ygopro.constants.COLORS.BABYBLUE)
            when 'dialogues'
              if !client.vip
                CLIENT_send_vip_status(client)
              else
                code = cmd[2]
                word = concat_name(cmd, 3)
                if !code or !parseInt(code)
                  ygopro.stoc_send_chat(client, "${vip_invalid_card_code}", ygopro.constants.COLORS.RED)
                else if !word
                  delete vip_info.players[client.name].dialogues[parseInt(code)]
                  setting_save(vip_info)
                  ygopro.stoc_send_chat(client, "${vip_cleared_dialogues_part1}" + code + "${vip_cleared_dialogues_part2}", ygopro.constants.COLORS.BABYBLUE)
                else
                  vip_info.players[client.name].dialogues[parseInt(code)] = word
                  setting_save(vip_info)
                  ygopro.stoc_send_chat(client, "${vip_set_dialogues_part1}" + code + "${vip_set_dialogues_part2}", ygopro.constants.COLORS.BABYBLUE)
            when 'words'
              if !client.vip
                CLIENT_send_vip_status(client)
              else
                word = concat_name(cmd, 2)
                if !word
                  delete vip_info.players[client.name].words
                  setting_save(vip_info)
                  ygopro.stoc_send_chat(client, "${vip_cleared_words}", ygopro.constants.COLORS.BABYBLUE)
                else
                  vip_info.players[client.name].words = word
                  setting_save(vip_info)
                  ygopro.stoc_send_chat(client, "${vip_set_words}", ygopro.constants.COLORS.BABYBLUE)
            when 'victory'
              if !client.vip
                CLIENT_send_vip_status(client)
              else
                word = concat_name(cmd, 2)
                if !word
                  delete vip_info.players[client.name].victory
                  setting_save(vip_info)
                  ygopro.stoc_send_chat(client, "${vip_cleared_victory}", ygopro.constants.COLORS.BABYBLUE)
                else
                  vip_info.players[client.name].victory = word
                  setting_save(vip_info)
                  ygopro.stoc_send_chat(client, "${vip_set_victory}", ygopro.constants.COLORS.BABYBLUE)
            when 'password'
              if !client.vip
                CLIENT_send_vip_status(client)
              else
                word = cmd[2]
                if word and (client.name.length + word.length) <= 18
                  vip_info.players[client.name].password = word
                  client.vpass = word
                  setting_save(vip_info)
                  ygopro.stoc_send_chat(client, "${vip_password_changed}", ygopro.constants.COLORS.BABYBLUE)
        else
          CLIENT_send_vip_status(client)

    #when '/test'
    #  ygopro.stoc_send_hint_card_to_room(room, 2333365)
  if (msg.length>100)
    log.warn "SPAM WORD", client.name, client.ip, msg
    client.abuse_count=client.abuse_count+2 if client.abuse_count
    ygopro.stoc_send_chat(client, "${chat_warn_level0}", ygopro.constants.COLORS.RED)
    cancel = true
  if !(room and (room.random_type or room.arena))
    return cancel
  if client.abuse_count>=5 or CLIENT_is_banned_by_mc(client)
    log.warn "BANNED CHAT", client.name, client.ip, msg
    ygopro.stoc_send_chat(client, "${banned_chat_tip}", ygopro.constants.COLORS.RED)
    return true
  oldmsg = msg
  if (_.any(badwords.level3, (badword) ->
    regexp = new RegExp(badword, 'i')
    return msg.match(regexp)
  , msg))
    log.warn "BAD WORD LEVEL 3", client.name, client.ip, oldmsg, RegExp.$1
    report_to_big_brother room.name, client.name, client.ip, 3, oldmsg, RegExp.$1
    cancel = true
    if client.abuse_count>0
      ygopro.stoc_send_chat(client, "${banned_duel_tip}", ygopro.constants.COLORS.RED)
      ROOM_ban_player(client.name, client.ip, "${random_ban_reason_abuse}")
      ROOM_ban_player(client.name, client.ip, "${random_ban_reason_abuse}", 3)
      CLIENT_send_replays(client, room)
      CLIENT_kick(client)
      return true
    else
      client.abuse_count=client.abuse_count+4
      ygopro.stoc_send_chat(client, "${chat_warn_level2}", ygopro.constants.COLORS.RED)
  else if (client.rag and room.started)
    client.rag = false
    #ygopro.stoc_send_chat(client, "${chat_warn_level0}", ygopro.constants.COLORS.RED)
    cancel = true
  else if (_.any(settings.ban.spam_word, (badword) ->
    regexp = new RegExp(badword, 'i')
    return msg.match(regexp)
  , msg))
    #log.warn "SPAM WORD", client.name, client.ip, oldmsg
    client.abuse_count=client.abuse_count+2
    ygopro.stoc_send_chat(client, "${chat_warn_level0}", ygopro.constants.COLORS.RED)
    cancel = true
  else if (_.any(badwords.level2, (badword) ->
    regexp = new RegExp(badword, 'i')
    return msg.match(regexp)
  , msg))
    log.warn "BAD WORD LEVEL 2", client.name, client.ip, oldmsg, RegExp.$1
    report_to_big_brother room.name, client.name, client.ip, 2, oldmsg, RegExp.$1
    client.abuse_count=client.abuse_count+3
    ygopro.stoc_send_chat(client, "${chat_warn_level2}", ygopro.constants.COLORS.RED)
    cancel = true
  else
    _.each(badwords.level1, (badword) ->
      #log.info msg
      regexp = new RegExp(badword, "ig")
      msg = msg.replace(regexp, "**")
      return
    , msg)
    if oldmsg != msg
      log.warn "BAD WORD LEVEL 1", client.name, client.ip, oldmsg, RegExp.$1
      report_to_big_brother room.name, client.name, client.ip, 1, oldmsg, RegExp.$1
      client.abuse_count=client.abuse_count+1
      ygopro.stoc_send_chat(client, "${chat_warn_level1}")
      struct = ygopro.structs["chat"]
      struct._setBuff(buffer)
      struct.set("msg", msg)
      buffer = struct.buffer
    else if (_.any(badwords.level0, (badword) ->
      regexp = new RegExp(badword, 'i')
      return msg.match(regexp)
    , msg))
      log.info "BAD WORD LEVEL 0", client.name, client.ip, oldmsg, RegExp.$1
      report_to_big_brother room.name, client.name, client.ip, 0, oldmsg, RegExp.$1
  if client.abuse_count>=2
    ROOM_unwelcome(room, client, "${random_ban_reason_abuse}")
  if client.abuse_count>=5
    ygopro.stoc_send_chat_to_room(room, "#{client.name} ${chat_banned}", ygopro.constants.COLORS.RED)
    ROOM_ban_player(client.name, client.ip, "${random_ban_reason_abuse}")
  return cancel

ygopro.ctos_follow 'UPDATE_DECK', true, (buffer, info, client, server, datas)->
  if settings.modules.reconnect.enabled and client.pre_reconnecting
    if !CLIENT_is_able_to_reconnect(client) and !CLIENT_is_able_to_kick_reconnect(client)
      ygopro.stoc_send_chat(client, "${reconnect_failed}", ygopro.constants.COLORS.RED)
      CLIENT_kick(client)
    else if CLIENT_is_able_to_reconnect(client, buffer)
      CLIENT_reconnect(client)
    else if CLIENT_is_able_to_kick_reconnect(client, buffer)
      CLIENT_kick_reconnect(client, buffer)
    else
      ygopro.stoc_send_chat(client, "${deck_incorrect_reconnect}", ygopro.constants.COLORS.RED)
      ygopro.stoc_send(client, 'ERROR_MSG', {
        msg: 2,
        code: 0
      })
      ygopro.stoc_send(client, 'HS_PLAYER_CHANGE', {
        status: (client.pos << 4) | 0xa
      })
    return true
  room=ROOM_all[client.rid]
  return false unless room
  #log.info info
  if info.mainc > 256 or info.sidec > 256 # Prevent attack, see https://github.com/Fluorohydride/ygopro/issues/2174
    CLIENT_kick(client)
    return true
  buff_main = (info.deckbuf[i] for i in [0...info.mainc])
  buff_side = (info.deckbuf[i] for i in [info.mainc...info.mainc + info.sidec])
  client.main = buff_main
  client.side = buff_side
  if room.started
    client.selected_preduel = true
    if client.side_tcount
      clearInterval client.side_interval
      client.side_interval = null
      client.side_tcount = null
  else
    client.start_deckbuf = Buffer.from(buffer)
  oppo_pos = if room.hostinfo.mode == 2 then 2 else 1
  if settings.modules.http.quick_death_rule >= 2 and room.started and room.death and room.scores[room.dueling_players[0].name_vpass] != room.scores[room.dueling_players[oppo_pos].name_vpass]
    win_pos = if room.scores[room.dueling_players[0].name_vpass] > room.scores[room.dueling_players[oppo_pos].name_vpass] then 0 else oppo_pos
    room.finished_by_death = true
    ygopro.stoc_send_chat_to_room(room, "${death2_finish_part1}" + room.dueling_players[win_pos].name + "${death2_finish_part2}", ygopro.constants.COLORS.BABYBLUE)
    CLIENT_send_replays(room.dueling_players[oppo_pos - win_pos], room) if room.hostinfo.mode == 1
    ygopro.stoc_send(room.dueling_players[oppo_pos - win_pos], 'DUEL_END')
    ygopro.stoc_send(room.dueling_players[oppo_pos - win_pos + 1], 'DUEL_END') if room.hostinfo.mode == 2
    room.scores[room.dueling_players[oppo_pos - win_pos].name_vpass] = -1
    CLIENT_kick(room.dueling_players[oppo_pos - win_pos])
    CLIENT_kick(room.dueling_players[oppo_pos - win_pos + 1]) if room.hostinfo.mode == 2
    return true
  if settings.modules.side_restrict.enabled and room.started
    for code in settings.modules.side_restrict.restrict_cards
      if _.indexOf(buff_side, code) > -1 or (settings.modules.pre_release_compat.enabled and _.indexOf(buff_side, room.list_pre_to_official[code]) > -1)
        ygopro.stoc_send_chat_to_room(room, "${invalid_side_rule}", ygopro.constants.COLORS.RED)
        ygopro.stoc_send client, 'ERROR_MSG', {
          msg: 3
          code: 0
        }
        return true
  struct = ygopro.structs["deck"]
  struct._setBuff(buffer)
  if room.random_type or room.arena
    if client.pos == 0
      room.waiting_for_player = room.waiting_for_player2
    room.last_active_time = moment()
  else if !room.started and settings.modules.tournament_mode.enabled and settings.modules.tournament_mode.deck_check and fs.readdirSync(settings.modules.tournament_mode.deck_path).length
    struct.set("mainc", 1)
    struct.set("sidec", 1)
    struct.set("deckbuf", [4392470, 4392470])
    buffer = struct.buffer
    found_deck=false
    decks=fs.readdirSync(settings.modules.tournament_mode.deck_path)
    for deck in decks
      if _.endsWith(deck, client.name+".ydk")
        found_deck=deck
      if _.endsWith(deck, client.name+".ydk.ydk")
        found_deck=deck
    if found_deck
      deck_text=fs.readFileSync(settings.modules.tournament_mode.deck_path+found_deck,{encoding:"ASCII"})
      deck_array=deck_text.split("\n")
      deck_main=[]
      deck_side=[]
      current_deck=deck_main
      for line in deck_array
        if line.indexOf("!side")>=0
          current_deck=deck_side
        card=parseInt(line)
        current_deck.push(card) unless isNaN(card)
      if _.isEqual(buff_main, deck_main) and _.isEqual(buff_side, deck_side)
        deckbuf=deck_main.concat(deck_side)
        struct.set("mainc", deck_main.length)
        struct.set("sidec", deck_side.length)
        struct.set("deckbuf", deckbuf)
        buffer = struct.buffer
        #log.info("deck ok: " + client.name)
        ygopro.stoc_send_chat(client, "${deck_correct_part1} #{found_deck} ${deck_correct_part2}", ygopro.constants.COLORS.BABYBLUE)
      else
        #log.info("bad deck: " + client.name + " / " + buff_main + " / " + buff_side)
        ygopro.stoc_send_chat(client, "${deck_incorrect_part1} #{found_deck} ${deck_incorrect_part2}", ygopro.constants.COLORS.RED)
        return false
    else
      #log.info("player deck not found: " + client.name)
      ygopro.stoc_send_chat(client, "#{client.name}${deck_not_found}", ygopro.constants.COLORS.RED)
      return false

  if settings.modules.pre_release_compat.enabled
    found = false
    buff_main_new = []
    buff_side_new = []
    for code in buff_main
      code_ = code
      if room.list_pre_to_official[code]
        code_ = room.list_pre_to_official[code]
        found = true
      buff_main_new.push(code_)
    for code in buff_side
      code_ = code
      if room.list_pre_to_official[code]
        code_ = room.list_pre_to_official[code]
        found = true
      buff_side_new.push(code_)
    if found
      compat_deckbuf = buff_main_new.concat(buff_side_new)
      struct.set("mainc", buff_main_new.length)
      struct.set("sidec", buff_side_new.length)
      struct.set("deckbuf", compat_deckbuf)
      buffer = struct.buffer
      client.main = buff_main_new
      client.side = buff_side_new
    if !room.started
      client.is_using_pre_release = found or client.vpass == "COMPAT"
      if client.is_using_pre_release
        ygopro.stoc_send_chat(client, "${pre_release_compat_hint}", ygopro.constants.COLORS.BABYBLUE)

  return false

ygopro.ctos_follow 'RESPONSE', false, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  if settings.modules.pre_release_compat.enabled and client.is_using_pre_release
    replace_buffer(buffer, room.list_pre_to_official, 0)
  return unless room.random_type or room.arena
  room.last_active_time = moment()
  return

ygopro.stoc_follow 'TIME_LIMIT', true, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  if settings.modules.reconnect.enabled
    if client.closed
      ygopro.ctos_send(server, 'TIME_CONFIRM')
      return true
    else
      client.time_confirm_required = true
  return unless settings.modules.heartbeat_detection.enabled and room.turn and room.turn > 0 and !room.windbot
  check = false
  if room.hostinfo.mode != 2
    check = (client.is_first and info.player == 0) or (!client.is_first and info.player == 1)
  else
    cur_players = []
    switch room.turn % 4
      when 1
        cur_players[0] = 0
        cur_players[1] = 3
      when 2
        cur_players[0] = 0
        cur_players[1] = 2
      when 3
        cur_players[0] = 1
        cur_players[1] = 2
      when 0
        cur_players[0] = 1
        cur_players[1] = 3
    if !room.dueling_players[0].is_first
      cur_players[0] = cur_players[0] + 2
      cur_players[1] = cur_players[1] - 2
    check = client.pos == cur_players[info.player]
  if check
    CLIENT_heartbeat_register(client, false)
  return false

ygopro.ctos_follow 'TIME_CONFIRM', false, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  if settings.modules.reconnect.enabled
    if client.waiting_for_last
      client.waiting_for_last = false
      if client.last_game_msg and client.last_game_msg_title != 'WAITING'
        if client.last_hint_msg
          ygopro.stoc_send(client, 'GAME_MSG', client.last_hint_msg)
        ygopro.stoc_send(client, 'GAME_MSG', client.last_game_msg)
    client.time_confirm_required = false
  if settings.modules.heartbeat_detection.enabled
    client.heartbeat_protected = false
    client.heartbeat_responsed = true
    CLIENT_heartbeat_unregister(client)
  return

ygopro.ctos_follow 'HAND_RESULT', false, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  client.selected_preduel = true
  return unless room.random_type or room.arena
  if client.pos == 0
    room.waiting_for_player = room.waiting_for_player2
  room.last_active_time = moment().subtract(settings.modules.random_duel.hang_timeout - 19, 's')
  return

ygopro.stoc_follow 'HAND_RESULT', true, (buffer, info, client, server, datas)->
  return settings.modules.windbot.doom_bots

ygopro.ctos_follow 'TP_RESULT', false, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  client.selected_preduel = true
  # room.selecting_tp = false
  return unless room.random_type or room.arena
  room.last_active_time = moment()
  return

ygopro.stoc_follow 'CHAT', true, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  pid = info.player
  return unless room and pid < 4 and settings.modules.chat_color.enabled
  if room.started and room.turn > 0 and !room.dueling_players[0].is_first
    if room.hostinfo.mode == 2
      pid = {
        0: 2,
        1: 3,
        2: 0,
        3: 1
      }[pid]
    else
      pid = 1 - pid
  for player in room.players when player and player.pos == pid
    tplayer = player
  return unless tplayer and (!(settings.modules.vip.enabled and settings.modules.chat_color.restrict_to_vip) or tplayer.vip)
  tcolor = if settings.modules.vip.enabled and settings.modules.chat_color.restrict_to_vip then vip_info.players[tplayer.name].chat_color else chat_color.save_list[CLIENT_get_authorize_key(tplayer)]
  if tcolor
    ygopro.stoc_send client, 'CHAT', {
        player: ygopro.constants.COLORS[tcolor]
        msg: tplayer.name + ": " + info.msg
      }
    return true
  return

ygopro.stoc_follow 'SELECT_HAND', true, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  if settings.modules.windbot.doom_bots
    room.changing_side = false
    ygopro.ctos_send(client.server, "HAND_RESULT", {res: (if client.is_local then 2 else 1)})
    return true
  client.selected_preduel = false
  if client.pos == 0
    room.selecting_hand = true
    room.changing_side = false
  return unless room.random_type or room.arena
  if client.pos == 0
    room.waiting_for_player = client
  else
    room.waiting_for_player2 = client
  room.last_active_time = moment().subtract(settings.modules.random_duel.hang_timeout - 19, 's')
  return

ygopro.stoc_follow 'SELECT_TP', true, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  if settings.modules.windbot.doom_bots
    room.changing_side = false
    room.selecting_hand = false
    ygopro.ctos_send(client.server, "TP_RESULT", {res: (if client.is_local then 1 else 0)})
    return true
  client.selected_preduel = false
  room.changing_side = false
  room.selecting_hand = false
  room.selecting_tp = client
  if room.random_type or room.arena
    room.waiting_for_player = client
    room.last_active_time = moment()
  return

ygopro.stoc_follow 'CHANGE_SIDE', false, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return unless room
  room.changing_side = true
  client.selected_preduel = false
  if settings.modules.side_timeout
    client.side_tcount = settings.modules.side_timeout
    ygopro.stoc_send_chat(client, "${side_timeout_part1}#{settings.modules.side_timeout}${side_timeout_part2}", ygopro.constants.COLORS.BABYBLUE)
    sinterval = setInterval ()->
      if not (room and room.started and client and client.side_tcount and room.changing_side)
        clearInterval sinterval
        return
      if client.side_tcount == 1
        ygopro.stoc_send_chat_to_room(room, client.name + "${side_overtime_room}", ygopro.constants.COLORS.BABYBLUE)
        ygopro.stoc_send_chat(client, "${side_overtime}", ygopro.constants.COLORS.RED)
        #room.scores[client.name_vpass] = -9
        CLIENT_send_replays(client, room)
        CLIENT_kick(client)
        clearInterval sinterval
      else
        client.side_tcount = client.side_tcount - 1
        ygopro.stoc_send_chat(client, "${side_remain_part1}#{client.side_tcount}${side_remain_part2}", ygopro.constants.COLORS.BABYBLUE)
    , 60000
    client.side_interval = sinterval
  if settings.modules.challonge.enabled and settings.modules.challonge.post_score_midduel and room.hostinfo.mode != 2 and client.pos == 0
    temp_log = JSON.parse(JSON.stringify(room.get_challonge_score()))
    delete temp_log.winnerId
    room_name = room.name
    challonge.matches._update({
      id: settings.modules.challonge.tournament_id,
      matchId: room.challonge_info.id,
      match: temp_log,
      callback: (err, data) ->
        if err
          log.warn("Errored pushing scores to Challonge.", room_name, err)
        else
          refresh_challonge_cache()
        return
    })
  if room.random_type or room.arena
    if client.pos == 0
      room.waiting_for_player = client
    else
      room.waiting_for_player2 = client
    room.last_active_time = moment()
  return

ygopro.stoc_follow 'REPLAY', true, (buffer, info, client, server, datas)->
  room=ROOM_all[client.rid]
  return settings.modules.tournament_mode.enabled and settings.modules.tournament_mode.replay_safe and settings.modules.tournament_mode.block_replay_to_player or settings.modules.replay_delay unless room
  if settings.modules.cloud_replay.enabled and room.random_type
    Cloud_replay_ids.push room.cloud_replay_id
  if settings.modules.replay_delay and room.hostinfo.mode == 1 and not (settings.modules.tournament_mode.enabled and settings.modules.tournament_mode.replay_safe and settings.modules.tournament_mode.block_replay_to_player) and !room.replays[room.duel_count - 1]
    # console.log("Replay saved: ", room.duel_count - 1, client.pos)
    room.replays[room.duel_count - 1] = buffer
  if settings.modules.tournament_mode.enabled and settings.modules.tournament_mode.replay_safe
    if client.pos == 0
      dueltime=moment().format('YYYY-MM-DD HH-mm-ss')
      replay_filename=dueltime
      if room.hostinfo.mode != 2
        for player,i in room.dueling_players
          replay_filename=replay_filename + (if i > 0 then " VS " else " ") + player.name
      else
        for player,i in room.dueling_players
          replay_filename=replay_filename + (if i > 0 then (if i == 2 then " VS " else " & ") else " ") + player.name
      replay_filename=replay_filename.replace(/[\/\\\?\*]/g, '_')+".yrp"
      duellog = {
        time: dueltime,
        name: room.name + (if settings.modules.tournament_mode.show_info then (" (Duel:" + room.duel_count + ")") else ""),
        roomid: room.process_pid.toString(),
        cloud_replay_id: "R#"+room.cloud_replay_id,
        replay_filename: replay_filename,
        roommode: room.hostinfo.mode,
        players: (for player in room.dueling_players
          name: player.name + (if settings.modules.tournament_mode.show_ip and !player.is_local then (" (IP: " + player.ip.slice(7) + ")") else "") + (if settings.modules.tournament_mode.show_info and not (room.hostinfo.mode == 2 and player.pos % 2 > 0) then (" (Score:" + room.scores[player.name_vpass] + " LP:" + (if player.lp? then player.lp else room.hostinfo.start_lp) + (if room.hostinfo.mode != 2 then (" Cards:" + (if player.card_count? then player.card_count else room.hostinfo.start_hand)) else "") + ")") else ""),
          winner: player.pos == room.winner
        )
      }
      duel_log.duel_log.unshift duellog
      setting_save(duel_log)
      fs.writeFile(settings.modules.tournament_mode.replay_path + replay_filename, buffer, (err)->
        if err then log.warn "SAVE REPLAY ERROR", replay_filename, err
      )
    if settings.modules.cloud_replay.enabled
      ygopro.stoc_send_chat(client, "${cloud_replay_delay_part1}R##{room.cloud_replay_id}${cloud_replay_delay_part2}", ygopro.constants.COLORS.BABYBLUE)
    return settings.modules.tournament_mode.block_replay_to_player or settings.modules.replay_delay and room.hostinfo.mode == 1
  else
    return settings.modules.replay_delay and room.hostinfo.mode == 1

if settings.modules.random_duel.enabled
  setInterval ()->
    for room in ROOM_all when room and room.started and room.random_type and room.last_active_time and room.waiting_for_player and room.get_disconnected_count() == 0
      time_passed = Math.floor((moment() - room.last_active_time) / 1000)
      #log.info time_passed
      if time_passed >= settings.modules.random_duel.hang_timeout
        room.last_active_time = moment()
        ROOM_ban_player(room.waiting_for_player.name, room.waiting_for_player.ip, "${random_ban_reason_AFK}")
        room.scores[room.waiting_for_player.name_vpass] = -9
        #log.info room.waiting_for_player.name, room.scores[room.waiting_for_player.name_vpass]
        ygopro.stoc_send_chat_to_room(room, "#{room.waiting_for_player.name} ${kicked_by_system}", ygopro.constants.COLORS.RED)
        CLIENT_send_replays(room.waiting_for_player, room)
        CLIENT_kick(room.waiting_for_player)
      else if time_passed >= (settings.modules.random_duel.hang_timeout - 20) and not (time_passed % 10)
        ygopro.stoc_send_chat_to_room(room, "#{room.waiting_for_player.name} ${afk_warn_part1}#{settings.modules.random_duel.hang_timeout - time_passed}${afk_warn_part2}", ygopro.constants.COLORS.RED)
        ROOM_unwelcome(room, room.waiting_for_player, "${random_ban_reason_AFK}")
    return
  , 1000

if settings.modules.mycard.enabled
  setInterval ()->
    for room in ROOM_all when room and room.started and room.arena and room.last_active_time and room.waiting_for_player and room.get_disconnected_count() == 0
      time_passed = Math.floor((moment() - room.last_active_time) / 1000)
      #log.info time_passed
      if time_passed >= settings.modules.random_duel.hang_timeout
        room.last_active_time = moment()
        ygopro.stoc_send_chat_to_room(room, "#{room.waiting_for_player.name} ${kicked_by_system}", ygopro.constants.COLORS.RED)
        room.scores[room.waiting_for_player.name_vpass] = -9
        #log.info room.waiting_for_player.name, room.scores[room.waiting_for_player.name_vpass]
        CLIENT_send_replays(room.waiting_for_player, room)
        CLIENT_kick(room.waiting_for_player)
      else if time_passed >= (settings.modules.random_duel.hang_timeout - 20) and not (time_passed % 10)
        ygopro.stoc_send_chat_to_room(room, "#{room.waiting_for_player.name} ${afk_warn_part1}#{settings.modules.random_duel.hang_timeout - time_passed}${afk_warn_part2}", ygopro.constants.COLORS.RED)
    return
  , 1000

if settings.modules.heartbeat_detection.enabled
  setInterval ()->
    for room in ROOM_all when room and room.started and (room.hostinfo.time_limit == 0 or !room.turn or room.turn <= 0) and !room.windbot
      for player in room.get_playing_player() when player and (!room.changing_side or player.selected_preduel)
        CLIENT_heartbeat_register(player, true)
    return
  , settings.modules.heartbeat_detection.interval

# spawn windbot
windbot_looplimit = 0

spawn_windbot = () ->
  if /^win/.test(process.platform)
    windbot_bin = 'WindBot.exe'
    windbot_parameters = []
  else
    windbot_bin = 'mono'
    windbot_parameters = ['WindBot.exe']
  windbot_parameters.push('ServerMode=true')
  windbot_parameters.push('ServerPort='+settings.modules.windbot.port)
  windbot_process = spawn windbot_bin, windbot_parameters, {cwd: 'windbot'}
  windbot_process.on 'error', (err)->
    log.warn 'WindBot ERROR', err
    if windbot_looplimit < 1000
      windbot_looplimit++
      spawn_windbot()
    return
  windbot_process.on 'exit', (code)->
    log.warn 'WindBot EXIT', code
    if windbot_looplimit < 1000
      windbot_looplimit++
      spawn_windbot()
    return
  windbot_process.stdout.setEncoding('utf8')
  windbot_process.stdout.on 'data', (data)->
    log.info 'WindBot:', data
    return
  windbot_process.stderr.setEncoding('utf8')
  windbot_process.stderr.on 'data', (data)->
    log.warn 'WindBot Error:', data
    return
  return

if settings.modules.windbot.enabled and settings.modules.windbot.spawn
  spawn_windbot()

#http
if settings.modules.http

  addCallback = (callback, text)->
    if not callback then return text
    return callback + "( " + text + " );"

  requestListener = (request, response)->
    parseQueryString = true
    u = url.parse(request.url, parseQueryString)
    #pass_validated = u.query.pass == settings.modules.http.password

    #console.log(u.query.username, u.query.pass)
    if u.pathname == '/api/getrooms'
      if !settings.modules.http.public_roomlist and !auth.auth(u.query.username, u.query.pass, "get_rooms", "get_rooms")
        response.writeHead(200)
        response.end(addCallback(u.query.callback, '{"rooms":[{"roomid":"0","roomname":"密码错误","needpass":"true"}]}'))
      else
        response.writeHead(200)
        roomsjson = JSON.stringify rooms: (for room in ROOM_all when room and room.established
          roomid: room.process_pid.toString(),
          roomname: if pass_validated then room.name else room.name.split('$', 2)[0],
          roommode: room.hostinfo.mode,
          needpass: (room.name.indexOf('$') != -1).toString(),
          users: _.sortBy((for player in room.players when player.pos?
            id: (-1).toString(),
            name: player.name,
            ip: if settings.modules.http.show_ip and pass_validated and !player.is_local then player.ip.slice(7) else null,
            status: if settings.modules.http.show_info and room.started and player.pos != 7 then (
              score: room.scores[player.name_vpass],
              lp: if player.lp? then player.lp else room.hostinfo.start_lp,
              cards: if room.hostinfo.mode != 2 then (if player.card_count? then player.card_count else room.hostinfo.start_hand) else null
            ) else null,
            pos: player.pos
          ), "pos"),
          istart: if room.started then (if settings.modules.http.show_info then ("Duel:" + room.duel_count + " " + (if room.changing_side then "Siding" else "Turn:" + (if room.turn? then room.turn else 0) + (if room.death then "/" + (if room.death > 0 then room.death - 1 else "Death") else ""))) else 'start') else 'wait'
        ), null, 2
        response.end(addCallback(u.query.callback, roomsjson))

    else if u.pathname == '/api/duellog' and settings.modules.tournament_mode.enabled
      if !auth.auth(u.query.username, u.query.pass, "duel_log", "duel_log")
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "[{name:'密码错误'}]"))
        return
      else
        response.writeHead(200)
        duellog = JSON.stringify duel_log.duel_log, null, 2
        response.end(addCallback(u.query.callback, duellog))

    else if u.pathname == '/api/getkeys' and settings.modules.vip.enabled
      if !auth.auth(u.query.username, u.query.pass, "vip", "get_keys")
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "Unauthorized."))
        return
      else if !u.query.keytype or !vip_info.cdkeys[u.query.keytype]
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "Key type not found."))
        return
      else
        response.writeHead(200)
        ret_keys = ""
        for key in vip_info.cdkeys[u.query.keytype]
          ret_keys = ret_keys + u.query.keytype + "D" + settings.port + ":" + key + "\n"
        response.end(addCallback(u.query.callback, ret_keys))

    else if u.pathname == '/api/archive.zip' and settings.modules.tournament_mode.enabled
      if !auth.auth(u.query.username, u.query.pass, "download_replay", "download_replay_archive")
        response.writeHead(403)
        response.end("Invalid password.")
        return
      else
        try
          archive_name = moment().format('YYYY-MM-DD HH-mm-ss') + ".zip"
          archive_args = ["a", "-mx0", "-y", archive_name]
          check = false
          for replay in duel_log.duel_log
            check = true
            archive_args.push(replay.replay_filename)
          if !check
            response.writeHead(403)
            response.end("Duel logs not found.")
            return
          archive_process = spawn settings.modules.tournament_mode.replay_archive_tool, archive_args, {cwd: settings.modules.tournament_mode.replay_path}
          archive_process.on 'error', (err)=>
            response.writeHead(403)
            response.end("Failed packing replays. " + err)
            return
          archive_process.on 'exit', (code)=>
            fs.readFile(settings.modules.tournament_mode.replay_path + archive_name, (error, buffer)->
              if error
                response.writeHead(403)
                response.end("Failed sending replays. " + error)
                return
              else
                response.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Disposition": "attachment" })
                response.end(buffer)
                return
            )
          archive_process.stdout.setEncoding 'utf8'
          archive_process.stdout.on 'data', (data)=>
            log.info "archive process: " + data
          archive_process.stderr.setEncoding 'utf8'
          archive_process.stderr.on 'data', (data)=>
            log.warn "archive error: " + data
        catch error
          response.writeHead(403)
          response.end("Failed reading replays. " + error)

    else if u.pathname == '/api/clearlog' and settings.modules.tournament_mode.enabled
      if !auth.auth(u.query.username, u.query.pass, "clear_duel_log", "clear_duel_log")
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "[{name:'密码错误'}]"))
        return
      else
        response.writeHead(200)
        if settings.modules.tournament_mode.log_save_path
          fs.writeFile(settings.modules.tournament_mode.log_save_path + 'duel_log.' + moment().format('YYYY-MM-DD HH-mm-ss') + '.json', JSON.stringify(duel_log, null, 2), (err) ->
            if err
              log.warn 'DUEL LOG SAVE ERROR', err
          )
        duel_log.duel_log = []
        setting_save(duel_log)
        response.end(addCallback(u.query.callback, "[{name:'Success'}]"))

    else if _.startsWith(u.pathname, '/api/replay') and settings.modules.tournament_mode.enabled
      if !auth.auth(u.query.username, u.query.pass, "download_replay", "download_replay")
        response.writeHead(403)
        response.end("密码错误")
        return
      else
        getpath=u.pathname.split("/")
        filename=decodeURIComponent(getpath.pop())
        fs.readFile(settings.modules.tournament_mode.replay_path + filename, (error, buffer)->
          if error
            response.writeHead(404)
            response.end("未找到文件 " + filename)
          else
            response.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Disposition": "attachment" })
            response.end(buffer)
          return
        )

    else if u.pathname == '/api/message'
      #if !pass_validated
      #  response.writeHead(200)
      #  response.end(addCallback(u.query.callback, "['密码错误', 0]"))
      #  return

      if u.query.shout
        if !auth.auth(u.query.username, u.query.pass, "shout", "shout")
          response.writeHead(200)
          response.end(addCallback(u.query.callback, "['密码错误', 0]"))
          return
        for room in ROOM_all when room and room.established
          ygopro.stoc_send_chat_to_room(room, u.query.shout, ygopro.constants.COLORS.YELLOW)
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "['shout ok', '" + u.query.shout + "']"))

      else if u.query.stop
        if !auth.auth(u.query.username, u.query.pass, "stop", "stop")
          response.writeHead(200)
          response.end(addCallback(u.query.callback, "['密码错误', 0]"))
          return
        if u.query.stop == 'false'
          u.query.stop = false
        setting_change(settings, 'modules:stop', u.query.stop)
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "['stop ok', '" + u.query.stop + "']"))

      else if u.query.welcome
        if !auth.auth(u.query.username, u.query.pass, "change_settings", "change_welcome")
          response.writeHead(200)
          response.end(addCallback(u.query.callback, "['密码错误', 0]"))
          return
        setting_change(settings, 'modules:welcome', u.query.welcome)
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "['welcome ok', '" + u.query.welcome + "']"))

      else if u.query.getwelcome
        if !auth.auth(u.query.username, u.query.pass, "change_settings", "get_welcome")
          response.writeHead(200)
          response.end(addCallback(u.query.callback, "['密码错误', 0]"))
          return
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "['get ok', '" + settings.modules.welcome + "']"))

      else if u.query.loadtips
        if !auth.auth(u.query.username, u.query.pass, "change_settings", "change_tips")
          response.writeHead(200)
          response.end(addCallback(u.query.callback, "['密码错误', 0]"))
          return
        load_tips()
        if settings.modules.tips.get_zh
          load_tips_zh()
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "['loading tip', '" + settings.modules.tips.get + (if settings.modules.tips.get_zh then " and " + settings.modules.tips.get_zh else "") + "']"))

      else if u.query.loaddialogues
        if !auth.auth(u.query.username, u.query.pass, "change_settings", "change_dialogues")
          response.writeHead(200)
          response.end(addCallback(u.query.callback, "['密码错误', 0]"))
          return
        load_dialogues()
        if settings.modules.dialogues.get_custom
          load_dialogues_custom()
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "['loading dialogues', '" + settings.modules.dialogues.get + (if settings.modules.dialogues.get_custom then " and " + settings.modules.dialogues.get_custom else "") + "']"))

      else if u.query.loadwords
        load_words()
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "['loading words', '" + settings.modules.words.get + "']"))

      else if u.query.ban
        if !auth.auth(u.query.username, u.query.pass, "ban_user", "ban_user")
          response.writeHead(200)
          response.end(addCallback(u.query.callback, "['密码错误', 0]"))
          return
        ban_user(u.query.ban)
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "['ban ok', '" + u.query.ban + "']"))

      else if u.query.kick
        if !auth.auth(u.query.username, u.query.pass, "kick_user", "kick_user")
          response.writeHead(200)
          response.end(addCallback(u.query.callback, "['密码错误', 0]"))
          return
        kick_room_found = false
        for room in ROOM_all when room and room.established and (u.query.kick == "all" or u.query.kick == room.process_pid.toString() or u.query.kick == room.name)
          kick_room_found = true
          if room.started
            room.scores[room.dueling_players[0].name_vpass] = 0
            room.scores[room.dueling_players[1].name_vpass] = 0
          room.kicked = true
          room.send_replays()
          room.process.kill()
          room.delete()
        response.writeHead(200)
        if kick_room_found
          response.end(addCallback(u.query.callback, "['kick ok', '" + u.query.kick + "']"))
        else
          response.end(addCallback(u.query.callback, "['room not found', '" + u.query.kick + "']"))

      else if u.query.death
        if !auth.auth(u.query.username, u.query.pass, "start_death", "start_death")
          response.writeHead(200)
          response.end(addCallback(u.query.callback, "['密码错误', 0]"))
          return
        death_room_found = false
        for room in ROOM_all when room and room.established and room.started and !room.death and (u.query.death == "all" or u.query.death == room.process_pid.toString() or u.query.death == room.name)
          death_room_found = true
          oppo_pos = if room.hostinfo.mode == 2 then 2 else 1
          if !room.changing_side and (!room.duel_count or room.turn)
            switch settings.modules.http.quick_death_rule
              when 3
                room.death = -2
                ygopro.stoc_send_chat_to_room(room, "${death_start_phase}", ygopro.constants.COLORS.BABYBLUE)
              else
                room.death = (if room.turn then room.turn + 4 else 5)
                ygopro.stoc_send_chat_to_room(room, "${death_start}", ygopro.constants.COLORS.BABYBLUE)
          else
            switch settings.modules.http.quick_death_rule
              when 2,3
                if room.scores[room.dueling_players[0].name_vpass] == room.scores[room.dueling_players[oppo_pos].name_vpass]
                  if settings.modules.http.quick_death_rule == 3
                    room.death = -1
                    ygopro.stoc_send_chat_to_room(room, "${death_start_quick}", ygopro.constants.COLORS.BABYBLUE)
                  else
                    room.death = 5
                    ygopro.stoc_send_chat_to_room(room, "${death_start_siding}", ygopro.constants.COLORS.BABYBLUE)
                else
                  win_pos = if room.scores[room.dueling_players[0].name_vpass] > room.scores[room.dueling_players[oppo_pos].name_vpass] then 0 else oppo_pos
                  room.finished_by_death = true
                  ygopro.stoc_send_chat_to_room(room, "${death2_finish_part1}" + room.dueling_players[win_pos].name + "${death2_finish_part2}", ygopro.constants.COLORS.BABYBLUE)
                  CLIENT_send_replays(room.dueling_players[oppo_pos - win_pos], room) if room.hostinfo.mode == 1
                  ygopro.stoc_send(room.dueling_players[oppo_pos - win_pos], 'DUEL_END')
                  ygopro.stoc_send(room.dueling_players[oppo_pos - win_pos + 1], 'DUEL_END') if room.hostinfo.mode == 2
                  room.scores[room.dueling_players[oppo_pos - win_pos].name_vpass] = -1
                  CLIENT_kick(room.dueling_players[oppo_pos - win_pos])
                  CLIENT_kick(room.dueling_players[oppo_pos - win_pos + 1]) if room.hostinfo.mode == 2
              when 1
                room.death = -1
                ygopro.stoc_send_chat_to_room(room, "${death_start_quick}", ygopro.constants.COLORS.BABYBLUE)
              else
                room.death = 5
                ygopro.stoc_send_chat_to_room(room, "${death_start_siding}", ygopro.constants.COLORS.BABYBLUE)
        response.writeHead(200)
        if death_room_found
          response.end(addCallback(u.query.callback, "['death ok', '" + u.query.death + "']"))
        else
          response.end(addCallback(u.query.callback, "['room not found', '" + u.query.death + "']"))

      else if u.query.deathcancel
        if !auth.auth(u.query.username, u.query.pass, "start_death", "cancel_death")
          response.writeHead(200)
          response.end(addCallback(u.query.callback, "['密码错误', 0]"))
          return
        death_room_found = false
        for room in ROOM_all when room and room.established and room.started and room.death and (u.query.deathcancel == "all" or u.query.deathcancel == room.process_pid.toString())
          death_room_found = true
          room.death = 0
          ygopro.stoc_send_chat_to_room(room, "${death_cancel}", ygopro.constants.COLORS.BABYBLUE)
        response.writeHead(200)
        if death_room_found
          response.end(addCallback(u.query.callback, "['death cancel ok', '" + u.query.deathcancel + "']"))
        else
          response.end(addCallback(u.query.callback, "['room not found', '" + u.query.deathcancel + "']"))

      else if u.query.generatekey and settings.modules.vip.enabled
        if !auth.auth(u.query.username, u.query.pass, "vip", "generate_keys")
          response.writeHead(200)
          response.end(addCallback(u.query.callback, "['密码错误', 0]"))
          return
        VIP_generate_cdkeys(u.query.generatekey, settings.modules.vip.generate_count)
        response.writeHead(200)
        response.end(addCallback(u.query.callback, "['Keys generated', '" + u.query.generatekey + "']"))

      else
        response.writeHead(400)
        response.end()

    else
      response.writeHead(400)
      response.end()
    return

  http_server = http.createServer(requestListener)
  http_server.listen settings.modules.http.port

  if settings.modules.http.ssl.enabled
    https = require 'https'
    options =
      cert: fs.readFileSync(settings.modules.http.ssl.cert)
      key: fs.readFileSync(settings.modules.http.ssl.key)
    https_server = https.createServer(options, requestListener)
    if settings.modules.http.websocket_roomlist and roomlist
      roomlist.init https_server, ROOM_all
    https_server.listen settings.modules.http.ssl.port
