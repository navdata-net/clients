#!/bin/bash

[ -f /etc/default/navdatanet ] || {
  echo "/etc/default/navdatanet missing"
  sleep 60
  exit 1
  }

source /etc/default/navdatanet

nc "${SRC_HOST}" "${SRC_PORT}" | GNSStoXMPP -f "${FMT}" -u "${XMPPuser}" -p "${XMPPpwd}" ${*}

