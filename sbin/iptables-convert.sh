#!/bin/bash

# iptables-convert: Export /etc/iptables.d/ file-structure from a running
# iptables configuration or on-disk backup...

debug="${DEBUG:-}"
trace="${TRACE:-}"

set -u

declare DIR=/etc/iptables.d
declare DATE="$( date +"%Y%m%d.%H%M" )"
declare TEMPLATE="\n# vi: set syntax=iptables:\n"

function die() {
	echo >&2 "FATAL: ${*:-Unknown error}"
	exit 1
} # die

function main() {
	local version

	if grep -Fq -- ' -4 ' <<<" ${*:-} "; then
		if [[ -z "${version:-}" ]]; then
			version='ipv4'
		else
			die "Incorrect arguments - version already set to '${version}'"
		fi
	elif grep -Fq -- ' -6 ' <<<" ${*:-} "; then
		if [[ -z "${version:-}" ]]; then
			version='ipv6'
		else
			die "Incorrect arguments - version already set to '${version}'"
		fi
	else
		version='ipv4'
	fi
	grep -Fq -- ' --debug ' <<<" ${*:-} " && debug=1
	grep -Fq -- ' --trace ' <<<" ${*:-} " && trace=1

	(( trace )) && set -o xtrace

	[[ -d "${DIR}" ]] || echo >&2 "WARNING: '${DIR}' does not exist${debug:+, and so will be created}"
	[[ "$( stat -Lc '%F' /dev/stdin )" == "fifo" ]] || die "No input provided - please pipe the output of 'ip$( [[ "${version}" == 'ipv6' ]] && echo -n '6' )tables-save' or a saved file to this command"

	# FIXME: These patterns assume that all substitutions will be in the
	#        form of XX_XXX, which we may not always want to be the case...
	local vars subs sedsub
	if [[ -r "${DIR}"/"${version}"/iptables.defs ]]; then
		vars="$( cat "${DIR}"/"${version}"/iptables.defs | sed 's/#.*$// ; s/^\s\+// ; s/\s\+$//' | grep -E '^[A-Z]{2}_[A-Z1-9]{3}="[^"]+"$' )"
		eval "${vars}"
		subs="$( echo "${vars}" | cut -d'=' -f 1 | xargs echo )"
		for sub in ${subs}; do
			eval sedsub+="s\|\$${sub}\|__${sub}__\|g\ \;\ "
		done
	else
		echo >&2 "WARNING: No defaults found in '${DIR}/iptables.defs'"
	fi
	unset subs vars

	if ! (( debug )); then
		mkdir -p "${DIR}/${version}" || die "mkdir() on '${DIR}/${version}' failed: ${?}"
		if (( $( find "${DIR}/${version}"/ -mindepth 1 -maxdepth 1 -type d -iname "[a-z]*" | wc -l ) > 0 )); then
			[[ -d "${DIR}/${version}/${DATE}" ]] && die "Backup directory '${DIR}/${version}/${DATE}' already exists"

			echo "Backing up existing definitions to '${DIR}/${version}/${DATE}' ..."
			mkdir "${DIR}/${version}/${DATE}" || die "mkdir() on '${DIR}/${version}/${DATE}' failed: ${?}"
			find "${DIR}/${version}"/ -mindepth 1 -maxdepth 1 -type d -iname "[a-z]*" -exec mv {} "${DIR}/${version}/${DATE}" \; || die "Backup failed: ${?}"
		fi
	fi

	local line statement table chain lastchain
	while read -r line; do
		(( trace & debug )) && echo "Read '${line}'"
		statement="$( sed 's/^\[[0-9]\+:[0-9]\+\] //' <<<"${line}" )"
		case "${statement}" in
			\#*)
				echo "${line}"
				;;
			\**)
				[[ -n "${table:-}" ]] && die "Found new table before previous table '${table}' was COMMITted"

				table="$( cut -d' ' -f 1 <<<"${statement#\*}" )"
				echo "Found table '${table}'"
				if ! (( debug )); then
					mkdir "${DIR}/${version}/${table}" || die "mkdir() on '${DIR}/${version}/${table}' failed: ${?}"
				fi
				;;
			:*)
				chain="$( cut -d' ' -f 1 <<<"${statement#:}" )"
				echo "Found chain '${chain}'"
				if ! (( debug )); then
					touch "${DIR}/${version}/${table}/${chain}" || die "Could not write to file '${DIR}/${version}/${table}/${chain}: ${?}"
				fi
				;;
			-A\ *)
				local entry
				chain="$( cut -d' ' -f 2 <<<"${statement}" )"
				if [[ "${chain}" =~ ^MINIUPNPD ]]; then
					echo >&2 "Skipping externally-managed chain '${chain}'"
					continue
				fi
				[[ -e "${DIR}/${version}/${table}/${chain}" ]] || die "Attempted to write to undisclosed chain '${chain}'"
				if [[ -n "${lastchain:-}" && "${lastchain}" != "${chain}" ]]; then
					if ! (( debug )); then
						[[ -n "${TEMPLATE:-}" ]] && echo -en "${TEMPLATE}" >> "${DIR}/${version}/${table}/${lastchain}" || die "Could not write to file '${DIR}/${version}/${table}/${lastchain}: ${?}"
					fi
				fi
				lastchain="${chain}"

				entry="$( cut -d' ' -f 3- <<<"${statement}" | sed "${sedsub}" )"
				if ! (( debug )); then
					echo "${entry}" >> "${DIR}/${version}/${table}/${chain}" || die "Could not write to file '${DIR}/${version}/${table}/${chain}: ${?}"
				else
					echo "${entry}"
				fi
				unset entry
				;;
			COMMIT)
				echo "Table complete"
				unset chain
				unset table
				;;
			*)
				die "Unexpected input - '${line}'"
				;;
		esac
	done

	(( trace )) && set +o xtrace
} # main

main "${@:-}"

exit ${?}

