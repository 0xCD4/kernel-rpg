# Kernel Academy: Ring-0 Chronicles

Level-based Linux kernel programming RPG with built-in quiz + coding lab flow.

## In-Game Instruction Flow
- Talk to the active mentor.
- Pass quiz questions for the level.
- Open terminal and complete Coding Lab TODO tasks.
- Run coding tests, then deploy the level patch.
- Unlock the next gate and continue.
- After all levels, synchronize with Kernel Core.

## Local Development
```bash
cd "/Users/mathematician/Documents/New project/windows-assembly-rpg-lesson1"
npm install
npm run dev:web
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000)

## Quality Gate (DevOps)
```bash
npm run validate
```

This runs:
- ESLint (`lint:js`)
- Prettier check (`lint:format`)
- Syntax check (`test:syntax`)
- Smoke test with game progression simulation (`test:smoke`)

## macOS App (Tauri)
### Dev mode
```bash
# terminal 1
npm run dev:web

# terminal 2
npm run dev:tauri
```

### Build macOS bundle
```bash
npm run build:tauri
```

Build output is generated under:
- `src-tauri/target/release/bundle`

## CI/CD
- `/.github/workflows/ci.yml`
  - Runs on push/PR for game folder changes.
  - Executes full quality gate.
- `/.github/workflows/macos-app-build.yml`
  - Runs on tags (`v*`) and manual dispatch.
  - Builds macOS Tauri bundle and uploads artifacts.
