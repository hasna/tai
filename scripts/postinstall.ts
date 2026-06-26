import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

mkdirSync(join(homedir(), ".hasna", "tai"), { recursive: true });
