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
exports.UserDialog = void 0;
const typeorm_1 = require("typeorm");
const User_1 = require("./User");
let UserDialog = class UserDialog {
    id;
    cardCode;
    text;
    user;
};
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)({ unsigned: true, type: "bigint" }),
    __metadata("design:type", Number)
], UserDialog.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Index)(),
    (0, typeorm_1.Column)("int", { unsigned: true }),
    __metadata("design:type", Number)
], UserDialog.prototype, "cardCode", void 0);
__decorate([
    (0, typeorm_1.Column)("text"),
    __metadata("design:type", String)
], UserDialog.prototype, "text", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => User_1.User, user => user.dialogues),
    __metadata("design:type", User_1.User)
], UserDialog.prototype, "user", void 0);
UserDialog = __decorate([
    (0, typeorm_1.Entity)()
], UserDialog);
exports.UserDialog = UserDialog;
//# sourceMappingURL=UserDialog.js.map