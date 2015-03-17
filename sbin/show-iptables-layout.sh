#!/bin/bash

debug="${DEBUG:-0}"
trace="${TRACE:-0}"

shopt -s expand_aliases
alias extern=':'

set -u

(( trace )) && set -o xtrace

declare DIR=/etc/iptables.d
declare OPT VERSION version m_version TABLE table m_table CHAIN m_chain
declare -i OUTPUT=0

function output() {
	local line="${1}"
	local -i indent="${2:-1}"

	extern OUTPUT

	[[ -n "${line}" ]] || return 1

	for n in $( seq 2 ${indent} ); do
		#echo -en '\t'
		echo -n '    '
	done
	echo "$line"

	OUTPUT=1

	return 0
}

function processfile() {
	local file="${1}"
	local -i indent="${2:-1}"

	[[ -n "${file:-}" && -e "${file}" ]] || return 1

	local targets target n

	targets="$( cat "${file}" | sed 's/#.*$//' | grep -- '-j ' | sed -r 's/^.*-j ([^ ]+).*$/\1/' | grep -Ev "^(SNAT|DNAT|MASQUERADE|ACCEPT|DROP|REJECT|RETURN|LOG|MARK|TOS|TCPMSS)$" )"

	(( debug )) && echo >&2 "DEBUG: $file ($indent) $targets"

	if (( indent != 1 )); then
		if (( $( sed 's/#.*$//' "$file" | grep -Ev "^[[:space:]]*$" | wc -l ) )); then
			output " $( basename "${file}" )" ${indent}
		else
			output "($( basename "${file}" ))" ${indent}
		fi
	fi
	for target in ${targets}; do
		if [[ -e "$( dirname "${file}" )"/"${target}" ]]; then
			processfile "$( dirname "${file}" )"/"${target}" $(( indent + 1 ))
		fi
	done

	return 0
}

OPT="$( getopt -o c:hi:t:v: -l version:,ip-version:,table:,chain:,help -n "$( basename "${0}" )" -- "${@:-}" )"
eval set -- "${OPT:-}"

while true ; do
	case "${1:-}" in
		-i|-v|--version|--ip-version)
			m_version="${2:-}"
			shift 2
			;;
		-t|--table)
			m_table="${2:-}"
			shift 2
			;;
		-c|--chain)
			m_chain="${2:-}"
			shift 2
			;;
		-h|--help)
			echo "$( basename "${0}" ) [--chain ...|--table ...|--version ...]"
			exit 0
			;;
		--)
			shift
			break
			;;
		*)
			echo >&2 "getopt() Internal error: Read '${*:-}'"
			exit 1
			;;
	esac
done

[[ -d "${DIR:-}" ]] || exit 1

for VERSION in $( find "${DIR}" -mindepth 1 -maxdepth 1 -type d ); do
	version="$( basename "${VERSION:-}" )"
	if [[ -n "${m_version:-}" ]]; then
		[[ "${version:-}" == "${m_version}" ]] || continue
	fi
	for TABLE in $( find "${DIR}"/"${version}" -mindepth 1 -maxdepth 1 -type d ); do
		table="$( basename "${TABLE:-}" )"
		if [[ -n "${m_table:-}" ]]; then
			[[ "${table:-}" == "${m_table}" ]] || continue
		fi
		for CHAIN in PREROUTING INPUT FORWARD OUTPUT POSTROUTING; do
			if [[ -n "${m_chain:-}" ]]; then
				[[ "${CHAIN}" == "${m_chain}" ]] || continue
			fi
			if [[ -e "${DIR}/${version}/${table}/${CHAIN}" ]]; then
				echo "${version}/${table}/${CHAIN}"
				OUTPUT=1
				processfile "${DIR}/${version}/${table}/${CHAIN}" 1
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
