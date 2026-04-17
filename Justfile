ensure-no-std:
  cargo test -p ntag424-core 2>&1 | tail -12 && cargo build -p ntag424-core --no-default-features --target thumbv7em-none-eabihf
