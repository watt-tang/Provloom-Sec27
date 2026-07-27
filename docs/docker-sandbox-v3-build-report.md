# Docker Sandbox v3 Build Report

Date: 2026-07-27

## Summary

The official sandbox image rebuild path is fixed and verified. The final image does not rely on a source-mounted runtime; `/opt/skill_sandbox/app` is copied into the image by `docker/sandbox/Dockerfile`.

## Root Cause

The repository is approximately 21 GiB, and no `.dockerignore` existed. The previous `docker build -f docker/sandbox/Dockerfile .` appeared to hang before useful Dockerfile logs because Docker had to send the full repository context, including artifacts and `.git`, to the daemon.

A transient compatibility issue was also found during the fix: this environment uses Docker's legacy builder, which rejects `docker build --progress plain`. That flag was removed.

Root cause classification:

- Docker daemon problem: not observed
- build context too large: confirmed
- apt/pip network blocking: not the primary cause
- Dockerfile stage stuck: not observed after context fix
- image cache problem: not observed
- runner did not trigger rebuild: fixed with `force_rebuild`
- tag/source mismatch: fixed with `skill-runtime-sandbox:dynamic-v3` and build info

## Fixes

- Added `.dockerignore` to exclude `.git`, `artifacts`, caches, docs, tests, and scripts from image context.
- Added Docker build metadata to `/opt/skill_sandbox/runtime-build-info.json`.
- Added `force_rebuild`, `reuse_existing_image`, and `build_timeout_seconds` to `DockerRunner`.
- Added build args for `IMAGE_TAG`, `SOURCE_FINGERPRINT`, `BUILD_TIMESTAMP`, and `DYNAMIC_ANALYSIS_VERSION`.
- Copied runtime build info into each run's artifacts as `runtime-build-info.json`.
- Added build failure timeout and stderr/stdout tail reporting.

## Final Image

- Tag: `skill-runtime-sandbox:dynamic-v3`
- Image id: `sha256:b8f114fa58cfe522a45c5e07d0b86bb53a15de1d8a301f983e21e849dcbcaabb`
- Created: `2026-07-27T18:23:14.06791135+08:00`
- Runtime fingerprint: `71c962d5de631e79d96696cd503ef9f2f088ebc4090fd3386edee0e2f0196178`
- Final successful rebuild duration: 107.786 seconds
- Source mount used for runtime code: false

## Smoke Test

Final smoke test confirmed:

- `runtime-build-info.json` exists in image
- Dynamic v3 fingerprint is present
- `CanonicalAssessment` code is present
- `llm_context` carrier code is present
- Static-runtime alignment fixes are present
- Source-mounted runtime was not used

