#!/bin/zsh
../sigscan repo localhost:5005 --output pretty
../sigscan repo localhost:5010 --insecure --output pretty
# zot
../sigscan repo localhost:5001 --insecure --output pretty

