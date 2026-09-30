import { runTests } from "./index.ts";

const result = await runTests();
for (const line of result.results) console.log(line);
console.log(`TypeScript tests: ${result.passed} passed, ${result.failed} failed`);
if (result.failed > 0) process.exit(1);
