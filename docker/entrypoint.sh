#!/bin/sh
# Container entrypoint: run AIS-catcher on the LiteX-M2SDR board, or any other command.
#
# Arguments starting with '-' (or none) are passed to AIS-catcher after the M2SDR input.
# Community sharing is off unless the arguments turn it back on with -X on.
set -e

case "$1" in
"" | -*)
	device="driver=LiteXM2SDR,path=${M2SDR_DEVICE}"
	[ -n "$M2SDR_ARGS" ] && device="$device,$M2SDR_ARGS"

	if [ ! -c "$M2SDR_DEVICE" ]; then
		echo "entrypoint: $M2SDR_DEVICE not found, start the container with --device $M2SDR_DEVICE" >&2
		exit 1
	fi

	exec /usr/bin/AIS-catcher -d SOAPYSDR -gu DEVICE "$device" -s "$SAMPLE_RATE" -X off "$@"
	;;
*)
	exec "$@"
	;;
esac
