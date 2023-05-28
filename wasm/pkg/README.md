# WASM

## Usage

Build WASM pkg to `./pkg`

```zsh
RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' \
 rustup run nightly-2023-05-16 \
 wasm-pack build --target web \
 -- . -Z build-std=panic_abort,std
```
