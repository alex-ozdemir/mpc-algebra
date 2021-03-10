#!/usr/bin/env zsh

cargo build --bin client

cargo run --bin client -- --port 8001 --peer-host localhost --peer-port 8000 -d 1 0 &
cargo run --bin client -- --port 8000 --peer-host localhost --peer-port 8001 -d 0 0 &

wait
