# rustfmt, clippy (warnings are errors) and tests with 100% line and function coverage
check:
    cargo fmt --check
    cargo clippy --all-targets --locked -- -D warnings
    cargo llvm-cov --all-targets --locked --fail-under-lines 100 --fail-under-functions 100

# Move the shared crates (and the patched rmcp) to the newest commit of deadhop/server's main
update-server-crates:
    cargo update -p deadhop-tlspin -p deadhop-cvm -p deadhop-net -p deadhop-common -p deadhop-netengine -p rmcp
