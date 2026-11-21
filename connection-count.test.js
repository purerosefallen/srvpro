'use strict';

const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const coffee = require('coffeescript');

// Exercise the actual admission and close handlers without starting the server.
const source = fs.readFileSync(
  require.resolve('./ygopro-server.coffee'),
  'utf8',
);
const admission = source.slice(
  source.indexOf('CLIENT_set_ip ='),
  source.indexOf('SOCKET_flush_data ='),
);
const closeStart = source.indexOf('  closeHandler = (error) ->');
const close = source.slice(
  closeStart,
  source.indexOf('\n  if client.isWs', closeStart),
);
const context = {
  ROOM_connected_ip: {},
  ROOM_bad_ip: {},
  ROOM_all: [],
  settings: { modules: { test_mode: {}, heartbeat_detection: {} } },
  getRealIp: (physical, forwarded) => forwarded || physical,
  isTrustedProxy: (ip) => ip === 'proxy',
  real_windbot_server_ip: 'bot',
  log: { info() {} },
  SERVER_kick() {},
  CLIENT_reconnect_register: () => false,
  mycardSpectatorReplay: { leave() {} },
};
context.global = context;
vm.createContext(context);
vm.runInContext(
  coffee.compile(
    admission +
      '\ncreateClose = (client) ->\n' +
      close +
      '\n  return closeHandler\n',
    { bare: true },
  ),
  context,
);

function connect(ip, ws = false) {
  const client = {
    physical_ip: ip,
    isWs: ws,
    destroy() {
      this.destroyed = true;
      if (this.close) this.close();
    },
  };
  if (!context.CLIENT_set_ip(client))
    client.close = context.createClose(client);
  return client;
}

for (const ws of [false, true]) {
  const ip = ws ? 'websocket' : 'tcp';
  const accepted = Array.from({ length: 10 }, () => connect(ip, ws));
  assert.strictEqual(context.ROOM_connected_ip[ip], 10);
  for (let i = 0; i < 30; i++) {
    assert.strictEqual(connect(ip, ws).destroyed, true);
    assert.strictEqual(context.ROOM_connected_ip[ip], 10);
  }
  accepted.forEach((client) => {
    client.close();
    client.close();
  });
  assert.strictEqual(context.ROOM_connected_ip[ip], undefined);
  const next = connect(ip, ws);
  assert.strictEqual(next.destroyed, undefined);
  next.close();
}

const full = Array.from({ length: 10 }, () => connect('forwarded'));
const migrating = connect('physical');
assert.strictEqual(context.CLIENT_set_ip(migrating, 'forwarded'), true);
assert.strictEqual(
  context.ROOM_connected_ip.forwarded,
  10,
  'close must not release an existing user slot',
);
assert.strictEqual(context.ROOM_connected_ip.physical, undefined);
migrating.close();
assert.strictEqual(context.ROOM_connected_ip.forwarded, 10);
full.forEach((client) => client.close());

context.ROOM_bad_ip.bad = 6;
assert.strictEqual(connect('bad').destroyed, true);
assert.strictEqual(context.ROOM_connected_ip.bad, undefined);
context.ROOM_bad_ip.proxy = 6;
assert.strictEqual(connect('proxy', true).destroyed, true);
assert.ok(!context.ROOM_connected_ip.proxy);
assert.ok(
  Object.values(context.ROOM_connected_ip).every((count) => count === 0),
);

async function testNeos() {
  const defaults = require('./data/default_config.json');
  const neos = {
    ROOM_connected_ip: {},
    ROOM_bad_ip: {},
    net: require('net'),
    ip6addr: require('ip6addr'),
    merge: require('deepmerge'),
    _: require('underscore'),
    real_windbot_server_ip: 'bot',
    log: { info() {}, warn() {} },
    ygopro: {
      ctos_follow(name, synchronous, handler) {
        assert.strictEqual(name, 'EXTERNAL_ADDRESS');
        assert.strictEqual(synchronous, true);
        neos.externalAddress = handler;
      },
    },
    setting_save(settings) {
      neos.savedConfig = JSON.parse(JSON.stringify(settings));
    },
  };
  neos.global = neos;
  const between = (first, last) => {
    const start = source.indexOf(first);
    const end = source.indexOf(last, start);
    assert.ok(start >= 0 && end > start, first);
    return source.slice(start, end);
  };
  vm.runInNewContext(
    coffee.compile(
      between('setting_get =', 'importOldConfig =') +
        '\nmigrate = (defaultConfig, config) ->\n' +
        '  settings = global.settings = merge(defaultConfig, config)\n' +
        '  imported = false\n' +
        between('  if settings.modules.neos.trusted_proxies', '  if settings.modules.mysql.enabled') +
        '  return settings\n' +
        between('toIpv4 =', 'CLIENT_set_ip =') + admission +
        between('netRequestHandler = (client) ->', '  # server stand') +
        '  client.connected = true\n' +
        between("ygopro.ctos_follow 'EXTERNAL_ADDRESS'", "ygopro.ctos_follow 'PLAYER_INFO'") +
        between('neosRequestListener = (client, req) ->', '\ninit()'),
      { bare: true },
    ),
    neos,
  );

  const oldKey = 'trusted_proxy_header';
  const newKey = 'ip_header';
  const envPrefix = 'SRVPRO_modules__neos__';
  async function migrate(config, env = {}) {
    neos.process = { env };
    neos.savedConfig = undefined;
    return neos.migrate(defaults, config);
  }

  const fileCases = [
    [{}, 'x-forwarded-for', false],
    [{ [oldKey]: 'X-Real-IP' }, 'X-Real-IP', true],
    [{ [newKey]: 'X-Client-IP' }, 'X-Client-IP', false],
    [{ [oldKey]: 'X-Real-IP', [newKey]: 'x-forwarded-for' }, 'x-forwarded-for', true],
  ];
  for (const [file, expected, saved] of fileCases) {
    const settings = await migrate({ modules: { neos: file } });
    assert.strictEqual(settings.modules.neos.ip_header, expected);
    assert.ok(!(oldKey in settings.modules.neos));
    assert.strictEqual(Boolean(neos.savedConfig), saved);
    if (saved) {
      const reloaded = await migrate(neos.savedConfig);
      assert.strictEqual(reloaded.modules.neos.ip_header, expected);
      assert.strictEqual(neos.savedConfig, undefined);
    }
  }
  for (const env of [
    { [envPrefix + oldKey]: 'X-Legacy-Env' },
    { [envPrefix + oldKey]: 'X-Ignored', [envPrefix + newKey]: 'X-New-Env' },
    { [envPrefix + newKey]: 'X-New-Env', [envPrefix + oldKey]: 'X-Ignored' },
  ]) {
    const expected = env[envPrefix + newKey] ?? env[envPrefix + oldKey];
    const settings = await migrate({ modules: { neos: { [newKey]: 'X-File' } } }, env);
    assert.strictEqual(settings.modules.neos.ip_header, expected);
    assert.ok(!(oldKey in neos.savedConfig.modules.neos));
  }

  const proxy = '::ffff:127.0.0.1';
  const peer = '::ffff:192.0.2.1';
  const packetIp = '::ffff:203.0.113.40';
  const headerIp = '::ffff:198.51.100.20';
  const packet = Buffer.from([203, 0, 113, 40]);
  const xff = 'x-forwarded-for';
  const connectionCases = [
    { headers: { [xff]: ' 198.51.100.20, 127.0.0.1' }, initial: headerIp, final: headerIp },
    { headers: { [xff]: '2001:db8::1' }, initial: '2001:db8::1', final: '2001:db8::1' },
    { headers: { [xff]: proxy }, initial: proxy, final: proxy },
    { headers: { [xff]: 'invalid, 198.51.100.20' }, initial: proxy, final: packetIp },
    { headers: {}, initial: proxy, final: packetIp },
    { remote: peer, headers: { [xff]: '198.51.100.20' }, initial: peer, final: peer },
    { header: 'X-Real-IP', headers: { 'x-real-ip': ['198.51.100.20'], [xff]: '192.0.2.1' }, initial: headerIp, final: headerIp },
    { header: '', headers: { [xff]: '198.51.100.20' }, initial: proxy, final: packetIp },
    { initial: proxy, final: packetIp },
    { remote: peer, initial: peer, final: peer },
  ];
  for (const { remote = proxy, header, headers, initial, final } of connectionCases) {
    await migrate({ modules: { neos: header === undefined ? {} : { ip_header: header } } });
    neos.ROOM_connected_ip = {};
    const client = { remoteAddress: remote };
    if (headers) {
      neos.neosRequestListener(client, { headers, socket: { remoteAddress: remote } });
    } else {
      neos.netRequestHandler(client);
    }
    assert.strictEqual(client.connected, true);
    assert.strictEqual(client.ip, initial);
    assert.strictEqual(neos.externalAddress(packet, {}, client), false);
    assert.strictEqual(client.ip, final);
    assert.deepStrictEqual(
      Object.entries(neos.ROOM_connected_ip).filter(([, count]) => count),
      final === proxy ? [] : [[final, 1]],
    );
  }
}

testNeos().then(() => {
  console.log('Neos migration and connection IP regression tests passed');
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
console.log('connection count regression tests passed');
