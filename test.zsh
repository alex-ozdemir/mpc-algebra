#!/usr/bin/env zsh
set -xe

cargo build --bin client

BIN=./target/debug/client

$BIN --port 8001 --peer-host localhost --peer-port 8000 -d sum 1 0 --party 0 & ; pid0=$!
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d sum 0 1 --party 1 & ; pid1=$!

wait $pid0 $pid1

$BIN --port 8001 --peer-host localhost --peer-port 8000 -d product 1 0 --party 0 & ; pid0=$!
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d product 0 1 --party 1 & ; pid1=$!

wait $pid0 $pid1

$BIN --port 8001 --peer-host localhost --peer-port 8000 -d commit 1 0 --party 0 & ; pid0=$!
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d commit 0 1 --party 1 & ; pid1=$!

wait $pid0 $pid1

$BIN --port 8001 --peer-host localhost --peer-port 8000 -d merkle 1 2 3 4 --party 0 & ; pid0=$!
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d merkle 0 0 0 0 --party 1 & ; pid1=$!

wait $pid0 $pid1

$BIN --port 8001 --peer-host localhost --peer-port 8000 -d fri 2 2 1 7 --party 0 & ; pid0=$!
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d fri 0 0 0 0 --party 1 & ; pid1=$!

wait $pid0 $pid1

# sum-check (G1)
$BIN --port 8001 --peer-host localhost --peer-port 8000 -d dh 0 4 6 --party 0 & ; pid0=$!
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d dh 1 2 1 --party 1 & ; pid1=$!

wait $pid0 $pid1

# sum-check (G2)
$BIN --port 8001 --peer-host localhost --peer-port 8000 -d dh 0 4 6 --party 0 --use-g2 & ; pid0=$!
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d dh 1 2 1 --party 1 --use-g2 & ; pid1=$!

wait $pid0 $pid1

# DDH triple check (pairing)
$BIN --port 8001 --peer-host localhost --peer-port 8000 -d pairingdh 0 1 6 --party 0 & ; pid0=$!
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d pairingdh 2 2 0 --party 1 & ; pid1=$!

wait $pid0 $pid1

# lin-check (pairing)
$BIN --port 8001 --peer-host localhost --peer-port 8000 -d pairingprod 0 1 6 1 --party 0 & ; pid0=$!
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d pairingprod 2 2 0 1 --party 1 & ; pid1=$!

wait $pid0 $pid1

# lin-check (pairing)
$BIN --port 8001 --peer-host localhost --peer-port 8000 -d pairingdiv 0 1 6 1 --party 0 & ; pid0=$!
$BIN --port 8000 --peer-host localhost --peer-port 8001 -d pairingdiv 2 2 0 1 --party 1 & ; pid1=$!

wait $pid0 $pid1

# groth16
$BIN --port 8001 --peer-host localhost --peer-port 8000 groth16 --party 0 & ; pid0=$!
$BIN --port 8000 --peer-host localhost --peer-port 8001 groth16 --party 1 & ; pid1=$!

wait $pid0 $pid1
