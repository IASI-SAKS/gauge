#!/bin/bash

set -eu

gcc thermo/main.c thermo/rng.c
/usr/bin/time -f "%e" ./a.out 2>&1 | tee temperature.txt
