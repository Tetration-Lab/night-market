# WASM

## Usage

Build WASM pkg to `./pkg`

```zsh
RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' \
 rustup run nightly-2022-12-12 \
 wasm-pack build --target web \
 -- . -Z build-std=panic_abort,std
```
