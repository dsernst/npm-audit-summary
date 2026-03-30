# npm-audit-report

Print concise **npm audit** tables: one flat list (severity → vulnerable package → responsible root dependency) and one summary grouped by that root.

## Usage

From a project that has a `package.json`:

```bash
npx npm-audit-report
```

Or pipe audit JSON:

```bash
npm audit --json 2>/dev/null | npx npm-audit-report --stdin
# equivalent:
npm audit --json 2>/dev/null | npx npm-audit-report -
```

## Responsible column

The tool reads **`package.json` in the current working directory** to map audit entries to a “responsible” direct dependency (including heuristics for common stacks such as `firebase-admin` and Google Cloud transitives).

## Requirements

- Node.js 18+
- `npm` on `PATH` when the CLI runs `npm audit --json` (default mode).
