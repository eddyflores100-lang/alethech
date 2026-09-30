import { runTests } from "./index.ts";

async function main(): Promise<void> {
  const result = await runTests();
  for (const line of result.results) console.log(line);
  console.log(`TypeScript tests: ${result.passed} passed, ${result.failed} failed`);
  if (result.failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
