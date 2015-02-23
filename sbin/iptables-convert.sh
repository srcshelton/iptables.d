#!/bin/bash

# iptables-convert: Export /etc/iptables.d/ file-structure from a running
# iptables configuration or on-disk backup...

set -u

DIR=/etc/iptables.d
DATE="$( date +"%Y%m%d.%H%M" )"
TEMPLATE="\n# vi: set syntax=iptables:\n"

debug="${DEBUG:-}"
trace="${TRACE:-}"

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
			die "Incorrect arguments - version already set to '$version'"
		fi
	elif grep -Fq -- ' -6 ' <<<" ${*:-} "; then
		if [[ -z "${version:-}" ]]; then
			version='ipv6'
		else
			die "Incorrect arguments - version already set to '$version'"
		fi
	else
		version='ipv4'
	fi
	grep -Fq -- ' --debug ' <<<" ${*:-} " && debug=1
	grep -Fq -- ' --trace ' <<<" ${*:-} " && trace=1

	[[ -n "${trace:-}" ]] && set -o xtrace

	[[ -d "${DIR}" ]] || echo >&2 "WARNING: '${DIR}' does not exist${debug:+, and so will be created}"

	# FIXME: These patterns assume that all substitutions will be in the
	#        form of XX_XXX, which we may not always want to be the case...
	local vars subs sedsub
	if [[ -r "${DIR}"/"${version}"/iptables.defs ]]; then
		vars="$( cat "${DIR}"/"${version}"/iptables.defs | sed 's/#.*$// ; s/^\s\+// ; s/\s\+$//' | grep -E '^[A-Z]{2}_[A-Z1-9]{3}="[^"]+"$' )"
		eval "${vars}"
		subs="$( echo "${vars}" | cut -d'=' -f 1 | xargs echo )"
		for sub in $subs; do
			eval sedsub+="s\|\$${sub}\|__${sub}__\|g\ \;\ "
		done
	else
		echo >&2 "WARNING: No defaults found in '${DIR}/iptables.defs'"
	fi
	unset subs vars

	if [[ -z "${debug:-}" ]]; then
		mkdir -p "${DIR}/${version}" || die "mkdir() on '${DIR}/${version}' failed: ${?}"
		if (( $( find "${DIR}/${version}"/ -mindepth 1 -maxdepth 1 -type d -iname "[a-z]*" | wc -l ) > 0 )); then
			[[ -d "${DIR}/${version}/${DATE}" ]] && die "Backup directory '${DIR}/${version}/${DATE}' already exists"

			echo "Backing up existing definitions to '${DIR}/${version}/${DATE}' ..."
			mkdir "${DIR}/${version}/${DATE}" || die "mkdir() on '${DIR}/${version}/${DATE}' failed: ${?}"
			find "${DIR}/${version}"/ -mindepth 1 -maxdepth 1 -type d -iname "[a-z]*" -exec mv {} "${DIR}/${version}/${DATE}" \; || die "Backup failed: ${?}"
		fi
	fi

	local line table chain lastchain
	while read -r line; do
		case "${line}" in
			\#*)
				echo "${line}"
				;;
			\**)
				[[ -n "${table:-}" ]] && die "Found new table before previous table '${table}' was COMMITted"

				table="$( cut -d' ' -f 1 <<<"${line#\*}" )"
				echo "Found table '${table}'"
				if [[ -z "${debug:-}" ]]; then
					mkdir "${DIR}/${version}/${table}" || die "mkdir() on '${DIR}/${version}/${table}' failed: ${?}"
				fi
				;;
			:*)
				chain="$( cut -d' ' -f 1 <<<"${line#:}" )"
				echo "Found chain '${chain}'"
				if [[ -z "${debug:-}" ]]; then
					touch "${DIR}/${version}/${table}/${chain}" || die "Could not write to file '${DIR}/${version}/${table}/${chain}: ${?}"
				fi
				;;
			-A\ *)
				local entry
				chain="$( cut -d' ' -f 2 <<<"${line}" )"
				if [[ "${chain}" =~ ^MINIUPNPD ]]; then
					echo >&2 "Skipping externally-managed chain '${chain}'"
					continue
				fi
				[[ -e "${DIR}/${version}/${table}/${chain}" ]] || die "Attempted to write to undisclosed chain '${chain}'"
				if [[ -n "${lastchain:-}" && "${lastchain}" != "${chain}" ]]; then
					if [[ -z "${debug:-}" ]]; then
						[[ -n "${TEMPLATE:-}" ]] && echo -en "${TEMPLATE}" >> "${DIR}/${version}/${table}/${lastchain}" || die "Could not write to file '${DIR}/${version}/${table}/${lastchain}: ${?}"
					fi
				fi
				lastchain="${chain}"

				entry="$( cut -d' ' -f 3- <<<"${line}" | sed "${sedsub}" )"
				if [[ -z "${debug:-}" ]]; then
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

	[[ -n "${trace:-}" ]] && set +o xtrace
} # main

main "{@:-}"

exit ${?}

