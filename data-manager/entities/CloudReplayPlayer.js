"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var CloudReplayPlayer_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.CloudReplayPlayer = void 0;
const typeorm_1 = require("typeorm");
const CloudReplay_1 = require("./CloudReplay");
const BasePlayer_1 = require("./BasePlayer");
let CloudReplayPlayer = CloudReplayPlayer_1 = class CloudReplayPlayer extends BasePlayer_1.BasePlayer {
    static fromPlayerInfo(info) {
        const p = new CloudReplayPlayer_1();
        p.key = info.key;
        p.name = info.name;
        p.pos = info.pos;
        return p;
    }
};
exports.CloudReplayPlayer = CloudReplayPlayer;
__decorate([
    (0, typeorm_1.Index)(),
    (0, typeorm_1.Column)({ type: "varchar", length: 128 }),
    __metadata("design:type", String)
], CloudReplayPlayer.prototype, "key", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => CloudReplay_1.CloudReplay, replay => replay.players),
    __metadata("design:type", CloudReplay_1.CloudReplay)
], CloudReplayPlayer.prototype, "cloudReplay", void 0);
exports.CloudReplayPlayer = CloudReplayPlayer = CloudReplayPlayer_1 = __decorate([
    (0, typeorm_1.Entity)()
], CloudReplayPlayer);
