#!/usr/bin/env zsh
set -xe

cargo build --bin client

BIN=./target/debug/client

$BIN --port 8001 --peer-host localhost --peer-port 8000 -d sum 1 0 --party 0 &
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d sum 0 1 --party 1 &

wait

$BIN --port 8001 --peer-host localhost --peer-port 8000 -d product 1 0 --party 0 &
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d product 0 1 --party 1 &

wait

$BIN --port 8001 --peer-host localhost --peer-port 8000 -d commit 1 0 --party 0 &
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d commit 0 1 --party 1 &

wait

$BIN --port 8001 --peer-host localhost --peer-port 8000 -d merkle 1 2 3 4 --party 0 &
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d merkle 0 0 0 0 --party 1 &

wait

$BIN --port 8001 --peer-host localhost --peer-port 8000 -d fri 2 2 1 7 --party 0 &
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d fri 0 0 0 0 --party 1 &

wait

# DDH triple check
$BIN --port 8001 --peer-host localhost --peer-port 8000 -d dh 0 4 6 --party 0 &
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d dh 1 2 1 --party 1 &

wait

# DDH triple check (G2)
$BIN --port 8001 --peer-host localhost --peer-port 8000 -d dh 0 4 6 --party 0 --use-g2 &
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d dh 1 2 1 --party 1 --use-g2 &

wait
