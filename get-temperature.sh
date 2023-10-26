#!/bin/bash

set -eu

sudo apt-get install libbsd-dev
gcc main.c -lbsd
/usr/bin/time -f "%e" ./a.out 2>&1 | tee temperature.txt