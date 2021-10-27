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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.User = void 0;
const typeorm_1 = require("typeorm");
const UserDialog_1 = require("./UserDialog");
const VipKey_1 = require("./VipKey");
const moment_1 = __importDefault(require("moment"));
const CreateAndUpdateTimeBase_1 = require("./CreateAndUpdateTimeBase");
let User = class User extends CreateAndUpdateTimeBase_1.CreateAndUpdateTimeBase {
    key;
    chatColor;
    vipExpireDate;
    isVip() {
        return this.vipExpireDate && (0, moment_1.default)().isBefore(this.vipExpireDate);
    }
    victory;
    words;
    dialogues;
    usedKeys;
};
__decorate([
    (0, typeorm_1.PrimaryColumn)({ type: "varchar", length: 128 }),
    __metadata("design:type", String)
], User.prototype, "key", void 0);
__decorate([
    (0, typeorm_1.Column)("varchar", { length: 16, nullable: true }),
    __metadata("design:type", String)
], User.prototype, "chatColor", void 0);
__decorate([
    (0, typeorm_1.Index)(),
    (0, typeorm_1.Column)("datetime", { nullable: true }),
    __metadata("design:type", Date)
], User.prototype, "vipExpireDate", void 0);
__decorate([
    (0, typeorm_1.Column)("text", { nullable: true }),
    __metadata("design:type", String)
], User.prototype, "victory", void 0);
__decorate([
    (0, typeorm_1.Column)("text", { nullable: true }),
    __metadata("design:type", String)
], User.prototype, "words", void 0);
__decorate([
    (0, typeorm_1.OneToMany)(() => UserDialog_1.UserDialog, dialog => dialog.user),
    __metadata("design:type", Array)
], User.prototype, "dialogues", void 0);
__decorate([
    (0, typeorm_1.OneToMany)(() => VipKey_1.VipKey, vipKey => vipKey.usedBy),
    __metadata("design:type", Array)
], User.prototype, "usedKeys", void 0);
User = __decorate([
    (0, typeorm_1.Entity)()
], User);
exports.User = User;
//# sourceMappingURL=User.js.map