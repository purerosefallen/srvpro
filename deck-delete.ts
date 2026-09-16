import * as fs from "fs";
import * as path from "path";

type DeleteCallback = (err?: NodeJS.ErrnoException | null) => void;

const invalidDeckError = function (): NodeJS.ErrnoException {
  const err = new Error("Invalid deck") as NodeJS.ErrnoException;
  err.code = "EINVAL";
  return err;
};

const resolveDeckFilePath = function (deck_path: string, deck_name: string): string {
  if (
    typeof deck_name !== "string" ||
    deck_name.length === 0 ||
    deck_name === "." ||
    deck_name === ".." ||
    deck_name.includes("\0") ||
    deck_name.includes("/") ||
    deck_name.includes("\\") ||
    path.isAbsolute(deck_name) ||
    path.win32.isAbsolute(deck_name) ||
    /^[A-Za-z]:/.test(deck_name)
  ) {
    throw invalidDeckError();
  }

  const resolved_deck_path = path.resolve(deck_path);
  const resolved_file_path = path.resolve(resolved_deck_path, deck_name);
  if (path.dirname(resolved_file_path) !== resolved_deck_path) {
    throw invalidDeckError();
  }

  return resolved_file_path;
};

export const deleteDeckFile = function (deck_path: string, deck_name: string, callback: DeleteCallback): void {
  let deck_file_path: string;
  try {
    deck_file_path = resolveDeckFilePath(deck_path, deck_name);
  } catch (err) {
    return callback(err as NodeJS.ErrnoException);
  }

  fs.unlink(deck_file_path, callback);
};
