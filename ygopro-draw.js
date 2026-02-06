/*
 ygopro-draw.js
 get card usage from decks
 Author: Nanahira
 License: MIT
 
 generate a lflist.conf for drafts.
 the config file is at ./config/draw.json, which should be:
{
  "dbfile": "ygopro/cards.cdb",
  "lflist": "ygopro/lflist.conf",
  "list": "2018.7",
  "main": 600,
  "extra": 300,
  "output": "./lflist.conf"
  "output_plain": "./pool_plain.txt"
}

*/
var fs = require('fs');
var initSqlJs = require('sql.js');
var loadJSON = require('load-json-file').sync;
var config = loadJSON('./config/draw.json');
var constants = loadJSON('./data/constants.json');

var ALL_MAIN_CARDS={};
var ALL_EXTRA_CARDS={};
var CARD_RESULT={};
var CARD_RESULT_PLAIN=[[], [], [], []];
var LFLIST={"unknown": []};
var MAIN_POOL=[];
var EXTRA_POOL=[];

var sqlJsPromise;
var SQL = null;
function ensureSqlJs() {
    if (!sqlJsPromise) {
        var wasmPath = require.resolve('sql.js/dist/sql-wasm.wasm');
        sqlJsPromise = initSqlJs({
            locateFile: function() {
                return wasmPath;
            }
        }).then(function(SQLLib) {
            SQL = SQLLib;
            return SQLLib;
        });
    }
    return sqlJsPromise;
}

function load_database(callback) {
    ensureSqlJs().then(function() {
        var dbBuffer = fs.readFileSync(config.dbfile);
        var db = new SQL.Database(dbBuffer);
        var stmt = db.prepare("select * from datas,texts where datas.id=texts.id");
        while (stmt.step()) {
            var result = stmt.getAsObject();
            if ((result.type & constants.TYPES.TYPE_TOKEN) || result.alias) {
                continue;
            }
            CARD_RESULT[result.id] = 0;
            if((result.type & constants.TYPES.TYPE_FUSION) || (result.type & constants.TYPES.TYPE_SYNCHRO) || (result.type & constants.TYPES.TYPE_XYZ) || (result.type & constants.TYPES.TYPE_LINK)) {
                ALL_EXTRA_CARDS[result.id] = 3;
            } else {
                ALL_MAIN_CARDS[result.id] = 3;
            }
        }
        stmt.free();
        db.close();
        if (callback) {
            callback();
        }
    }).catch(function(err) {
        console.log(config.dbfile + ":" + err);
    });
}

function load_lflist() {
    var raw = fs.readFileSync(config.lflist, 'utf8').split(/\n/g);
    var current_list = "unknown";
    for(var i in raw) {
        var line = raw[i];
        if(line.match(/!(.+)/)) {
            current_list = line.match(/!(.+)/)[1];
            if (!LFLIST[current_list]) {
                LFLIST[current_list] = {};
            }
        } else if (line.match(/(\d+) 0/)) {
            LFLIST[current_list][parseInt(line.match(/(\d+) 0/)[1])] = 0;
        } else if (line.match(/(\d+) 1/)) {
            LFLIST[current_list][parseInt(line.match(/(\d+) 1/)[1])] = 1;
        } else if (line.match(/(\d+) 2/)) {
            LFLIST[current_list][parseInt(line.match(/(\d+) 2/)[1])] = 2;
        }
    }
    if (LFLIST[config.list]) {
        for(var code in LFLIST[config.list]) {
            count = LFLIST[config.list][code];
            if(ALL_MAIN_CARDS[code] === 3) {
                ALL_MAIN_CARDS[code] = count;
            } else if (ALL_EXTRA_CARDS[code] === 3) {
                ALL_EXTRA_CARDS[code] = count;
            }
        }
    }
    generate_pool();
}

function generate_pool() {
    for (var code in ALL_MAIN_CARDS) {
        var count = ALL_MAIN_CARDS[code];
        for (var i = 0; i < count; ++i) {
            MAIN_POOL.push(code);
        }
    }
    for (var code in ALL_EXTRA_CARDS) {
        var count = ALL_EXTRA_CARDS[code];
        for (var i = 0; i < count; ++i) {
            EXTRA_POOL.push(code);
        }
    }
    pick_cards();
}

function pick_cards() {
    for (var i = 0; i < config.main; ++i) {
        var l = MAIN_POOL.length;
        if (!l) {break;}
        var index = Math.floor(Math.random() * l);
        var code = MAIN_POOL[index];
        if(CARD_RESULT[code] < 3) {
            CARD_RESULT[code]++;
        }
        MAIN_POOL.splice(index, 1);
    }
    for (var i = 0; i < config.extra; ++i) {
        var l = EXTRA_POOL.length;
        if (!l) {break;}
        var index = Math.floor(Math.random() * l);
        var code = EXTRA_POOL[index];
        if(CARD_RESULT[code] < 3) {
            CARD_RESULT[code]++;
        }
        EXTRA_POOL.splice(index, 1);
    }
    output();
}
function output() {
    var op = "#[Random]\n\n!Random\n";
    var op_plain = "";
    for (var code in CARD_RESULT) {
        op = op + code + " " + CARD_RESULT[code] + "\n";
        if(CARD_RESULT[code] > 0) {
            CARD_RESULT_PLAIN[CARD_RESULT[code]].push(code);
        }
    }
    for (var i = 1; i < 4; ++i) {
        for (var j in CARD_RESULT_PLAIN[i]) {
            const code = CARD_RESULT_PLAIN[i][j];
            op_plain = op_plain + code + " " + i + "\n";
        }
    }
    fs.writeFile(config.output, op, 'utf-8', function(err) {
        if (err) {
            console.log(err);
        }
    });
    console.log(op_plain);
}

load_database(load_lflist);
