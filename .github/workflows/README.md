# GitHub Actions for EWP

| Workflow | Triggers | What it does |
|---|---|---|
| `build.yml` | push / PR to main, dev; manual | Tests + cross-builds the unified `cmd/ewp` binary, the Qt6 GUI, and the gomobile aar. One artefact per OS/arch. |
| `build-android-apk.yml` | push / PR / tag matching paths in `ewpmobile/` or `ewp-android/`; manual | Self-contained pipeline: gomobile bind → Android assembleRelease (or assembleDebug if no signing secrets). |
| `release.yml` | manual only (give it a `v2.x.y` tag) | Tag the commit, build everything in `build.yml` + signed Android APK, attach all artefacts to a GitHub release. |

## Artefact map

`build.yml`:
- `ewp-<os>-<arch>` — single static binary (`cmd/ewp`). Behaves as
  client / server / relay based on the YAML config you point it at.
- `ewp-gui-linux` — Qt6 GUI (`EWP-GUI`).
- `ewp-core-aar` — gomobile binding consumed by `ewp-android`.

`build-android-apk.yml`:
- `ewp-core-aar` — same as above (rebuilt here so the apk job can run independently).
- `ewp-android-apks` — one apk per ABI split, plus the universal apk.

`release.yml`:
- All of the above, prefixed with the release version, plus
  per-file `.sha256` checksums.

## v1 → v2 changes worth noting

- One binary, not two. v1 had `cmd/client` and `cmd/server`;
  v2's `cmd/ewp` is configured at runtime via YAML, so the
  matrix builds half as many artefacts.
- No more Trojan or XHTTP-stream-down output. Both were
  removed from the codebase; the workflows can't ship them.
- Java 21 everywhere (was 17). Required by the latest Compose
  BOM the v2 Android UI uses.
- Android NDK r26b is the floor. Earlier NDKs miss the
  `__cxa_thread_atexit_impl` symbol Go 1.25 needs.
- gomobile is reinstalled on every run rather than cached —
  the cache eviction churn was costing more time than the
  ~10s the install takes.
