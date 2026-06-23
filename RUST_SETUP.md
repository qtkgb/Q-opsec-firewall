# Rust core — toolchain setup (one time)

The forwarding datapath (`firewall_core`, a Rust + smoltcp library) cross-compiles to
`libfirewall_core.so` and is bundled into the APK. The Gradle build invokes it
automatically **once the toolchain below is installed**. Until then the app still builds
and runs — it just shows `core: not built` (no forwarding).

## 1. Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# restart the terminal (or: source "$HOME/.cargo/env")
rustc --version    # confirm
```

## 2. Add the Android build targets
```bash
rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi
```

## 3. Install cargo-ndk
```bash
cargo install cargo-ndk
```

## 4. Install the Android NDK (in Android Studio)
**Settings → Languages & Frameworks → Android SDK → SDK Tools** tab →
check **NDK (Side by side)** and **CMake** → **Apply** (downloads ~1 GB).

## 5. Re-sync Gradle, then run
In Android Studio click **Sync Project with Gradle Files** (the elephant icon). This
re-evaluates the build so it picks up `cargo`. Then **Run ▶**.

The build now runs `cargo ndk` first and packages the `.so`. First Rust build takes a
few minutes; later builds are incremental.

## 6. Verify
Launch the app — the header should read:
```
core: firewall-core 0.1.0 (smoltcp)
```
That means the Rust library built, packaged, loaded, and JNI works end-to-end. ✅
With Phase 1b forwarding active, the status line also reads "Forwarding — internet active
(Phase 1b)" and the device keeps working internet while capturing.

---

## Manual build (optional / debugging)
```bash
cd "Q opsec firewall/android/v1/rust"
ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/<version>" \
  cargo ndk -t arm64-v8a -t x86_64 \
  -o ../app/src/main/jniLibs build --release
ls ../app/src/main/jniLibs/*/libfirewall_core.so
```

## Troubleshooting
- **`core: not built`** after setup → re-sync Gradle (step 5); the build block only wires
  in if `~/.cargo/bin/cargo` exists at sync time.
- **`cargo: command not found` in the Gradle build** → ensure Rust installed for your user
  (`~/.cargo/bin/cargo`), then re-sync.
- **NDK not found** → confirm step 4; the build reads the NDK path from the Android SDK.
- **Wrong ABI on emulator** → Apple-Silicon emulators are `arm64-v8a`; Intel are `x86_64`.
  Both are built by default (see `rustAbis` in `app/build.gradle.kts`).
