#!/bin/sh
# Container entrypoint: run AIS-catcher from the mounted config file, or any other command.
#
# Arguments starting with '-' (or none) are passed to AIS-catcher after the config file.
# Community sharing is off unless the config sets "sharing": true or the arguments add -X on.
set -e

case "$1" in
"" | -*)
	if [ ! -f "$AISCATCHER_CONFIG" ]; then
		echo "entrypoint: no config file at $AISCATCHER_CONFIG" >&2
		echo "entrypoint: mount one, e.g. -v \$PWD/aiscatcher.json:$AISCATCHER_CONFIG:ro" >&2
		exit 1
	fi

	exec /usr/bin/AIS-catcher -X off -C "$AISCATCHER_CONFIG" "$@"
	;;
*)
	exec "$@"
	;;
esac
