#!/bin/bash

CHANNEL="${1:-navdata-0}"
PORT="${2:-3131}"

./XMPPtoGNSS.py -c "${CHANNEL}" | nc -l "${PORT}"

