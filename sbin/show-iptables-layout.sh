#!/bin/bash

#set -o xtrace

DIR=/etc/iptables.d
OUTPUT=0

function output() {
	LINE="$1"
	INDENT="${2:-1}"

	for n in $( seq 2 $INDENT ); do
		#echo -en '\t'
		echo -n '    '
	done
	echo "$LINE"
	OUTPUT=1
}

function processfile() {
	local INDENT FILE TARGETS TARGET n
	FILE="$1"
	INDENT="${2:-1}"

	[[ -e "$FILE" ]] || return 1

	TARGETS="$( cat "$FILE" | sed 's/#.*$//' | grep -- '-j ' | sed -r 's/^.*-j ([^ ]+).*$/\1/' | grep -Ev "^(SNAT|DNAT|MASQUERADE|ACCEPT|DROP|REJECT|RETURN|LOG|MARK|TOS|TCPMSS)$" )"
	#echo >&2 "DEBUG: $FILE ($INDENT) $TARGETS"
	if [[ "$INDENT" != "1" ]]; then
		#if [[ -s "$FILE" ]]; then
		if (( $( sed 's/#.*$//' "$FILE" | grep -Ev "^[[:space:]]*$" | wc -l ) )); then
			output " $( basename "$FILE" )" $INDENT
		else
			output "($( basename "$FILE" ))" $INDENT
		fi
	fi
	for TARGET in $TARGETS; do
		if [[ -e "$( dirname "$FILE" )"/"$TARGET" ]]; then
			processfile "$( dirname "$FILE" )"/"$TARGET" $(( INDENT + 1 ))
		fi
	done
}

OPT="$( getopt -o c:hi:t:v: -l version:,ip-version:,table:,chain:,help -n "$( basename "$0" )" -- "$@" )"
eval set -- "$OPT"

while true ; do
	case "$1" in
		-i|-v|-version|-ip-version)
			m_version="$2"
			shift 2
			;;
		-t|--table)
			m_table="$2"
			shift 2
			;;
		-c|--chain)
			m_chain="$2"
			shift 2
			;;
		-h|--help)
			echo "$( basename "$0" ) [--chain ...|--table ...|--version ...]"
			exit 0
			;;
		--)
			shift
			break
			;;
		*)
			echo >&2 "getopt() Internal error: Read '$*'"
			exit 1
			;;
	esac
done

for VERSION in $( find "$DIR" -mindepth 1 -maxdepth 1 -type d ); do
	version="$( basename "$VERSION" )"
	if [[ -n "$m_version" ]]; then
		[[ "$version" == "$m_version" ]] || continue
	fi
	for TABLE in $( find "$DIR"/"$version" -mindepth 1 -maxdepth 1 -type d ); do
		table="$( basename "$TABLE" )"
		if [[ -n "$m_table" ]]; then
			[[ "$table" == "$m_table" ]] || continue
		fi
		for CHAIN in PREROUTING INPUT FORWARD OUTPUT POSTROUTING; do
			if [[ -n "$m_chain" ]]; then
				[[ "$CHAIN" == "$m_chain" ]] || continue
			fi
			if [[ -e "$DIR"/"$version"/"$table"/"$CHAIN" ]]; then
				echo "$version/$table/$CHAIN"
				OUTPUT=1
				processfile "$DIR"/"$version"/"$table"/"$CHAIN" 1
				echo
				OUTPUT=0
			fi
		done
		(( OUTPUT )) && echo
		OUTPUT=0
	done
	(( OUTPUT )) && echo
	OUTPUT=0
done | uniq

exit 0
