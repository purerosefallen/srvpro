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
Object.defineProperty(exports, "__esModule", { value: true });
exports.VipKey = void 0;
const typeorm_1 = require("typeorm");
const User_1 = require("./User");
const CreateAndUpdateTimeBase_1 = require("./CreateAndUpdateTimeBase");
let VipKey = class VipKey extends CreateAndUpdateTimeBase_1.CreateAndUpdateTimeBase {
    id;
    key;
    type;
    isUsed;
    usedBy;
    toJSON() {
        return { key: this.key, type: this.type };
    }
};
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)({ unsigned: true, type: "bigint" }),
    __metadata("design:type", Number)
], VipKey.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Index)({ unique: true }),
    (0, typeorm_1.Column)("varchar", { length: 30 }),
    __metadata("design:type", String)
], VipKey.prototype, "key", void 0);
__decorate([
    (0, typeorm_1.Column)("int", { unsigned: true }),
    __metadata("design:type", Number)
], VipKey.prototype, "type", void 0);
__decorate([
    (0, typeorm_1.Index)(),
    (0, typeorm_1.Column)("tinyint", { unsigned: true, default: 0 }),
    __metadata("design:type", Number)
], VipKey.prototype, "isUsed", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => User_1.User, user => user.usedKeys),
    __metadata("design:type", User_1.User)
], VipKey.prototype, "usedBy", void 0);
VipKey = __decorate([
    (0, typeorm_1.Entity)()
], VipKey);
exports.VipKey = VipKey;
//# sourceMappingURL=VipKey.js.map