#!/bin/bash

debug="${DEBUG:-0}"
trace="${TRACE:-0}"

set -o pipefail

shopt -s expand_aliases
alias extern=':'

(( trace )) && set -o xtrace

GITSRC="https://github.com/srcshelton/iptables.d"
VER="0.1"

#
# FIXME:
# 	There's some nasty code below...
#	Update with current coding conventions, and port to use stdlib.sh
#	(see github.com/srcshelton/stdlib.sh)
#	Everything is painfully slow...
#	'compare' mode sometimes fails to match valid entries
#
# TODO:
#	... and the entire script should probably be re-implemented in perl
#	Alternatively, parsing the output of 'iptables-xml' may be helpful?
#

DIR="/etc/iptables.d"
COUNTERS=0
COMPARE=0
RUNNING=1

# Ensure sane sort ordering...
export LC_COLLATE=C

# Use 'respond' rather than 'echo' to clearly differentiate function results
# from pipeline-intermediate commands.
#
function respond() {
	[[ -n "${@:-}" ]] && echo "${@}"
} # respond

function cleanup() {
	local rc="${1:-}"

	[[ -n "$TMPFILE" && -e "$TMPFILE" ]] && rm "$TMPFILE"
	[[ -n "$BACKUP" && -e "$BACKUP" ]] && rm "$BACKUP"
	[[ -n "$WORKING" && -e "$WORKING" ]] && rm "$WORKING"

	if [[ -n "${rc:-}" ]]; then
		trap - EXIT
		exit $(( rc ))
	fi
} # cleanup

function die() {
	echo >&2 "$( basename "$0" ) FATAL: $*"
	cleanup 1
	exit 1
} # die

function gettargets() {
	#
	# Yes, we really are auto-populating the list of valid iptables targets
	# from the iptables documentation on-the-fly... deep breath, everyone!
	#
	local manconf="/etc/man.conf"
	local manpage="iptables-extensions"
	local manfile="$( man -w "${manpage}" )"
	local manext="${manfile##*.}"
	local decomp="$( grep "^.${manext}" "${manconf}" | sed 's|\s\+| |g' | cut -d' ' -f 2- )"
	[[ -n "${decomp}" && -x "${decomp%% *}" ]] || decomp="cat"
	local ipt_targets="$( echo -n 'ACCEPT|QUEUE|DROP|REJECT|RETURN|' ; cat "${manfile}" | ${decomp} | grep '^\.SS ' | cut -d ' ' -f 2 | grep "^[A-Z]" | xargs echo -n | sed 's/ /|/g' )"

	(( debug )) && echo >&2 "DEBUG: IPT_TARGETS is '$ipt_targets'"

	respond "${ipt_targets}"
} # gettargets

function processfile() {
	local filename="${1:-}" ; shift
	local chains="${@:-}"

	local table targets target
	extern IPT_TARGETS

	[[ -n "${filename:-}" && -e "${filename}" ]] || { (( debug )) && echo >&2 "DEBUG: Cannot read file '${filename:-}'" ; return 254 ; }

	table="$( basename "${filename}" )"
	[[ "${table}" =~ ^\..*\.swp$ ]] && { (( debug )) && echo >&2 "DEBUG: Skipping swap-file '${table}'" ; return 254 ; }
	[[ "${table}" =~ ~$ ]] && { (( debug )) && echo >&2 "DEBUG: Skipping file '${table}" ; return 254 ; }

	if echo " ${chains:-} " | grep -q " ${table} " >/dev/null 2>&1; then
		(( debug )) && echo >&2 "DEBUG: chain '${table}' already processed"
		respond "${chains}"
		return 1
	fi

	targets="$( cat "${filename}" | grep --line-buffered -- '-j ' | sed -r 's|^.*-j ([^ ]+).*$|\1|' | grep -Ev "^(${IPT_TARGETS})$" )"
	(( debug )) && echo >&2 "DEBUG: ${filename} => ${targets}"

	#(( COMPARE )) || echo ":${table} - [0:0]"

	chains="${chains:+${chains} }${table}"
	for target in ${targets}; do
		if [[ -e "$( dirname "${filename}" )"/"${target}" ]]; then
			chains="$( processfile "$( dirname "${filename}" )"/"${target}" "${chains}" )"
		fi
	done

	respond "${chains}"

	return 0
} # processfile

NAME="$( basename "$0" )"
case "$NAME" in
	generate-iptables-rules|generate-iptables-rules.sh)
		m_version="ipv4"
		;;
	generate-ip6tables-rules|generate-ip6tables-rules.sh)
		m_version="ipv6"
		;;
	*)
		die "Unknown invocation '$NAME'"
		;;
esac

[[ -d "$DIR" ]] || die "Directory '$DIR' doesn't exist"

OPT="$( getopt -o cdh -l compare,counters,diff,help -n "$NAME" -- "$@" )"
eval set -- "$OPT"

while true ; do
	case "$1" in
		-c|--counters)
			COUNTERS=1
			shift
			;;
		-d|--compare|--diff)
			COMPARE=1
			shift
			;;
		-h|--help)
			echo "$NAME [--counters|--compare]"
			exit 0
			;;
		--)
			shift
			break
			;;
		*)
			die "getopt() Internal error, read '$*'"
			;;
	esac
done

trap 'cleanup 1' HUP INT QUIT TERM

DISTRIB_ID="Gentoo"
[[ -r /etc/lsb-release ]] && source /etc/lsb-release

case "${DISTRIB_ID}" in
	Gentoo)
		INIT="/etc/init.d/iptables"
		RULES="/var/lib/iptables/rules-save"
		IPTS="/sbin/iptables-save"
		if [[ "$m_version" == "ipv6" ]]; then
			INIT="/etc/init.d/ip6tables"
			RULES="/var/lib/ip6tables/rules-save"
			IPTS="/sbin/ip6tables-save"
		fi
		[[ -x "$INIT" ]] || die "Cannot locate '$INIT'"
		if "$INIT" status --quiet; then
			# ip6?tables is running, so use current state
			[[ -x "$IPTS" ]] || die "Cannot locate '$IPTS'"
		else
			(( COMPARE )) && die "$( basename "$INIT" ) must be running in order to compare differences"
			BACKUP="$( mktemp -t $NAME.XXXXXXXX )" || die "mktemp failed: $?"
			# ip6?tables is not running, so use on-disk state
			cat "$RULES" > "$BACKUP" 2>/dev/null || die "Cannot copy '$RULES': $?"
			RUNNING=0
		fi
		;;
	Ubuntu)
		# Ubuntu is a bit of a mess... iptables doesn't exist as a
		# service, and instead users are expected to add 'pre-up'
		# instructions to their network interface definitions.
		# If the 'iptables-persistent' package is installed, then
		# state is at least saved and restored.  However, the 'ufw'
		# service appears to be installed by default and will manage
		# iptables rules, so it's probably a good service to check...
		INIT="ufw"
		RULES="/etc/iptables/rules.v4"
		IPTS="/sbin/iptables-save"
		if [[ "$m_version" == "ipv6" ]]; then
			RULES="/etc/iptables/rules.v6"
			IPTS="/sbin/ip6tables-save"
		fi
		# Really Canonical?  This is just painful...
		if [[ -x "/etc/init.d/${INIT}" ]]; then
			SVC="service '${INIT}' status"
		elif [[ -e "/etc/init/${INIT}.conf" ]]; then
			SVC="initctl status ${INIT} --quiet"
		elif [[ -x "$INIT" ]]; then
			# Fallback, just in case...
			SVC="${INIT}"
		else
			die "Cannot locate '$INIT'"
		fi
		if ${SVC} 2>/dev/null; then
			# ip6?tables is running, so use current state
			[[ -x "$IPTS" ]] || die "Cannot locate '$IPTS'"
		else
			(( COMPARE )) && die "$( basename "$INIT" ) must be running in order to compare differences"
			BACKUP="$( mktemp -t $NAME.XXXXXXXX )" || die "mktemp failed: $?"
			# ip6?tables is not running, so use on-disk state
			cat "$RULES" > "$BACKUP" 2>/dev/null || die "Cannot copy '$RULES': $?"
			RUNNING=0
		fi
		;;
	*)
		die "Unknown value for '\$DISTRIB_ID' in /etc/lsb-release - please submit a bug-report or patch to '${GITSRC}'"
		;;
esac

if (( COMPARE || COUNTERS )); then
	TMPFILE="$( mktemp -t $NAME.XXXXXXXX )" || die "mktemp failed: $?"
fi
WORKING="$( mktemp -t $NAME.XXXXXXXX )" || die "mktemp failed: $?"

IPT_TARGETS="$( gettargets )"

# At this point, if iptables isn't running and we're writing to $RULES,
# then we've just clobbered our input file :(
#
# This isn't actually significant until we obtain separate tables, below...
#
for VERSION in $( find "$DIR" -mindepth 1 -maxdepth 1 -type d ); do
	version="$( basename "$VERSION" )"
	if [[ -n "$m_version" ]]; then
		[[ "$version" == "$m_version" ]] || continue
	fi

	# FIXME: These patterns assume that all substitutions will be in the
	#        form of XX_XXX, which we may not always want to be the case...
	if ! [[ -r "$DIR"/"$version"/iptables.defs ]]; then
		echo >&2 "WARNING: No defaults found in '$DIR/iptables.defs'"
	else
		eval $( cat /etc/iptables.d/ipv4/iptables.defs | sed 's/#.*$// ; s/^\s\+// ; s/\s\+$//' | grep -E '^[A-Z]{2}_[A-Z1-9]{3}="[^"]+"$' )
		subs="$( cat /etc/iptables.d/ipv4/iptables.defs | sed 's/#.*$// ; s/^\s\+// ; s/\s\+$//' | grep -E '^[A-Z]{2}_[A-Z1-9]{3}="[^"]+"$' | cut -d'=' -f 1 | xargs echo )"
		sedsub=""
		for sub in $subs; do
			eval sedsub+="s\|__${sub}__\|\$${sub}\|g\ \;\ "
		done
	fi

	lasttable=""
	# 'security' is IPv4-only, and potentially only relevant for SELinux.
	for table in raw nat mangle filter security; do
		[[ -d "$DIR"/"$version"/"$table" ]] || continue

		(( COMPARE )) || echo "# Generated by $NAME $VER on $( date )"
		chains=""
		case $table in
			filter)
				chains="INPUT FORWARD OUTPUT"
				;;
			nat)
				chains="PREROUTING INPUT OUTPUT POSTROUTING"
				;;
			mangle)
				chains="PREROUTING INPUT FORWARD OUTPUT POSTROUTING"
				;;
			raw)
				chains="PREROUTING OUTPUT"
				;;
			security)
				chains="INPUT FORWARD OUTPUT"
				;;
			*)
				die "Unknown table '$table'"
				;;
		esac
		(( COMPARE )) || echo "*$table"
		for CHAIN in $chains; do
			POLICY="ACCEPT"
			if [[ -e "$DIR"/"$version"/"$table"/"$CHAIN" ]]; then
				POLICY="$(
					  sed 's|#.*$||' "$DIR"/"$version"/"$table"/"$CHAIN"	\
					| grep -E '^\s*-P\s+(ACCEPT|QUEUE|DROP|RETURN)\s*$'	\
					| tr -d '[:space:]'					\
					| sed 's|^-P||'						\
				)"
				[[ -n "$POLICY" ]] || POLICY="ACCEPT"
			fi
			(( COMPARE )) || echo ":$CHAIN $POLICY [0:0]"
		done
		newchains=""
		for CHAIN in PREROUTING INPUT FORWARD OUTPUT POSTROUTING; do
			newchains="$( processfile "$DIR"/"$version"/"$table"/"$CHAIN" "$newchains" )"
		done
		for CHAIN in $( export LC_ALL=C ; find "$DIR"/"$version"/"$table"/ -mindepth 1 -maxdepth 1 -type f | sort ); do
			chain="$( basename "$CHAIN" )"
			[[ "$chain" =~ ^\..*\.swp$ || "$chain" =~ ~$ ]] && continue
			echo " $chains $newchains " | grep -qE " $chain " >/dev/null 2>&1 || newchains="$( processfile "$CHAIN" "$newchains" )"
		done
		if ! (( COMPARE )); then
			for chain in $newchains; do
				grep -q " ${chain} " <<<" ${chains} " || echo ":${chain} - [0:0]"
			done
		fi
		[[ -n "$newchains" ]] && chains="${chains:+${chains} }${newchains}"
		unset chain newchains

		(( debug )) && echo >&2 "DEBUG: \$chains is '$chains'"

		rulenumber=0
		for CHAIN in $chains; do
			#(( debug )) && echo >&2 "DEBUG: \$CHAIN is '$CHAIN'"
			if [[ -e "$DIR"/"$version"/"$table"/"$CHAIN" ]]; then
				COMMENT_MATCH="(-m comment --comment ([^ ]*|\"[^\"]*\") ?)?"
				NUMBER=0
				src="$DIR"/"$version"/"$table"/"$CHAIN"
				if grep -q '^!include .*$' "${src}"; then
					cat "${src}" > "${WORKING}"
					while grep -q '^!include .*$' "${WORKING}"; do
						FILE="$( grep -nm 1 '^!include .*$' "${WORKING}" )"
						POS="$( cut -d':' -f 1 <<<"${FILE}" )"
						FILE="$( sed 's/#.*$//' <<<"${FILE}" | cut -d' ' -f 2- )"
						FILE="$( sed -r "s|['\"]([^'\"]+)['\"]|\1|" <<<"${FILE}" )"
						if [[ -f "${DIR}"/"${version}"/"${table}.${FILE}.include" ]]; then
							FILE="${DIR}"/"${version}"/"${table}.${FILE}.include"
						elif [[ -f "${DIR}"/"${version}"/"${table}.${FILE}" ]]; then
							FILE="${DIR}"/"${version}"/"${table}.${FILE}"
						elif [[ -f "${DIR}"/"${version}"/"${FILE}.include" ]]; then
							FILE="${DIR}"/"${version}"/"${FILE}.include"
						elif [[ -f "${DIR}"/"${version}"/"${FILE}" ]]; then
							FILE="${DIR}"/"${version}"/"${FILE}"
						else
							die "!include unable to locate file '${FILE}' from ${src}"
						fi
						#sed -i -e "0,/^!include .*$/ {r ${FILE}" -e "d}" "${WORKING}" || die "!include failed for file '${FILE}' in ${src}: ${?}"
						if ! touch "${WORKING}.tmp" || ! [[ -e "${WORKING}.tmp" ]] || [[ -s "${WORKING}.tmp" ]]; then
							die "Unable to create empty temporary file '${WORKING}.tmp'"
						fi
						{
							head -n $(( POS - 1 )) "${WORKING}"
							cat "${FILE}"
							tail -n +$(( POS + 1 )) "${WORKING}"
						} > "${WORKING}.tmp" && mv "${WORKING}.tmp" "${WORKING}" || die "!include failed for file '${FILE}' in ${src}: ${?}"
					done
					src="${WORKING}"
					if (( debug )); then
						echo >&2 "------------------------------------------------------------------------------"
						echo >&2 "DEBUG: Current definitions ($DIR/$version/$table/$CHAIN) contains:"
						cat >&2 "$src"
						echo >&2 "------------------------------------------------------------------------------"
					fi
				fi
				  sed -r '
				 	s|#.*$||
					 /^\s*-P\s+(ACCEPT|QUEUE|DROP|RETURN)\s*$/d
					s|\s\+$||
				  ' "$src"							\
				| grep -v '^\s*$'						\
				| sed "${sedsub}"						\
				| while read -r LINE; do
					ORIGINAL="${LINE}"
				  	(( NUMBER++ ))
					(( debug )) && echo >&2 "DEBUG: Read '$LINE'"
					COMMENT="$( grep -Eo ' -m comment --comment ([^ "][^ ]*|"[^"]*")( |$)' <<<"$LINE" )"
					#[[ -n "$COMMENT" ]] && (( debug )) && echo >&2 "DEBUG: COMMENT is '$COMMENT'"

					if [[ "$lasttable" != "$table" ]]; then
						if (( COMPARE || COUNTERS )); then
							if (( RUNNING )); then
								$IPTS -ct "$table" >"$TMPFILE" 2>&1 || die "Cannot execute '$IPTS'"
							else
								awk "BEGIN { output = 0 } ; /^\*$table/ { output = 1 } ; ( 1 == output ) { print \$0 } ; ( 1 == output ) && /^COMMIT$/ { exit; }" "$BACKUP" >"$TMPFILE" 2>&1 || die "Cannot copy '$BACKUP': $?"
							fi

							if (( debug )); then
								echo >&2 "------------------------------------------------------------------------------"
								echo >&2 "DEBUG: Current table ($table) contains:"
								cat >&2 "$TMPFILE"
								echo >&2 "------------------------------------------------------------------------------"
							fi
						fi
						lasttable="$table"
					fi
					if echo -- " $LINE " | grep -q -- " -o " >/dev/null 2>&1; then
						NOT=""
						grep -q ' ! -o ' >/dev/null 2>&1 <<<" $LINE " && NOT='! '
						OUT="$( echo " $LINE " | sed -r 's|^.* -o ([^ ]+) .*$|\1|' )"
						LINE="$( sed "s|^${NOT}-o $OUT || ; s| ${NOT}-o ${OUT}$|| ; s|^${NOT}-o ${OUT}$|| ; s| ${NOT}-o $OUT | |" <<<"$LINE" )"
						LINE="${NOT}-o $OUT $LINE"
						unset OUT
					fi
					if echo -- " $LINE " | grep -q -- " -i " >/dev/null 2>&1; then
						NOT=""
						grep -q ' ! -i ' >/dev/null 2>&1 <<<" $LINE " && NOT='! '
						IN="$( echo " $LINE " | sed -r 's|^.* -i ([^ ]+) .*$|\1|' )"
						LINE="$( sed "s|^${NOT}-i $IN || ; s| ${NOT}-i ${IN}$|| ; s|^${NOT}-i ${IN}$|| ; s| ${NOT}-i $IN | |" <<<"$LINE" )"
						LINE="${NOT}-i $IN $LINE"
						unset IN
					fi
					if echo -- " $LINE " | grep -q -- " -d " >/dev/null 2>&1; then
						NOT=""
						grep -q ' ! -d ' >/dev/null 2>&1 <<<" $LINE " && NOT='! '
						DST="$( echo " $LINE " | sed -r 's|^.* -d ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(/[0-9]{1,2})? .*$|\1\2|' )"
						LINE="$( sed "s|^${NOT}-d $DST || ; s| ${NOT}-d ${DST}$|| ; s|^${NOT}-d $DST$|| ; s| ${NOT}-d $DST | |" <<<"$LINE" )"
						grep -q '/' >/dev/null 2>&1 <<<"$DST" || DST="${DST}/32"
						LINE="${NOT}-d $DST $LINE"
						unset DST
					fi
					if echo -- " $LINE " | grep -q -- " -s " >/dev/null 2>&1; then
						NOT=""
						grep -q ' ! -s ' >/dev/null 2>&1 <<<" $LINE " && NOT='! '
						SRC="$( echo " $LINE " | sed -r 's|^.* -s ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(/[0-9]{1,2})? .*$|\1\2|' )"
						LINE="$( sed "s|^${NOT}-s $SRC || ; s| ${NOT}-s ${SRC}$|| ; s|^${NOT}-s $SRC$|| ; s| ${NOT}-s $SRC | |" <<<"$LINE" )"
						grep -q '/' >/dev/null 2>&1 <<<"$SRC" || SRC="${SRC}/32"
						LINE="${NOT}-s $SRC $LINE"
						unset SRC
					fi
					if echo -- " $LINE " | grep -q -- " -m comment --comment " >/dev/null 2>&1; then
						LINE="$( echo " $LINE " | sed -r 's| -m comment --comment "([A-Za-z0-9]+)" | -m comment --comment \1 | ; s|^ +|| ; s| +$||' )"
					fi
					if echo -- " $LINE " | grep -q -- " --syn " >/dev/null 2>&1; then
						LINE="$( echo " $LINE " | sed 's| --syn | --tcp-flags FIN,SYN,RST,ACK SYN | ; s|^ +|| ; s| +$||' )"
					fi
					if echo -- " $LINE " | grep -q -- " --tcp-flags ALL " >/dev/null 2>&1; then
						LINE="$( echo " $LINE " | sed 's| --tcp-flags ALL ALL | --tcp-flags ALL FIN,SYN,RST,PSH,ACK,URG |g ; s|^ +|| ; s| +$||' )"
						LINE="$( echo " $LINE " | sed 's| --tcp-flags ALL | --tcp-flags FIN,SYN,RST,PSH,ACK,URG |g ; s|^ +|| ; s| +$||' )"
					fi
					# '--limit-burst 5' is default, and so optimised out...
					if echo -- " $LINE " | grep -q -- " --limit-burst 5 " >/dev/null 2>&1; then
						LINE="$( echo " $LINE " | sed 's| --limit-burst 5 | | ; s|^ +|| ; s| +$||' )"
					fi
					if echo -- " $LINE " | grep -q -- "[0-9]\.[0-9]" >/dev/null 2>&1; then
						LINE="$( echo " $LINE " | sed -r 's|(-[sd]) ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|\1 \2(/32)?|g ; s|^ +|| ; s| +$||' )"
					fi
					if echo -- " $LINE " | grep -q -- " --set-mark " >/dev/null 2>&1; then
						LINE="$( echo " $LINE " | sed -r 's| --set-mark ([0-9a-fx]+) | --set-xmark \1/0xffffffff |g ; s|^ +|| ; s| +$||' )"
						if ! echo -- " $LINE " | grep -q -- " --set-mark 0x" >/dev/null 2>&1; then
							VALUE="$( echo " $LINE " | sed -r 's|^.* --set-xmark ([^/]+)/.*$|\1|' )"
							HEX="$( printf '%x' "$VALUE" )"
							LINE="$( echo " $LINE " | sed "s| --set-xmark ${VALUE}/| --set-xmark 0x${HEX}/| ; s|^ \+|| ; s| \+$||"  )"
							unset HEX VALUE
						fi
					fi
					if echo -- " $LINE " | grep -q -- " --mark " >/dev/null 2>&1; then
						if ! echo -- " $LINE " | grep -q -- " --mark 0x" >/dev/null 2>&1; then
							VALUE="$( echo " $LINE " | sed -r 's|^.* --mark ([^ ]+) .*$|\1|' )"
							HEX="$( printf '%x' "$VALUE" )"
							LINE="$( echo " $LINE " | sed "s| --mark ${VALUE} | --mark 0x${HEX} | ; s|^ \+|| ; s| \+$||" )"
							unset HEX VALUE
						fi
					fi
					if echo -- " $LINE " | grep -Eq -- " --(save|restore)-mark " >/dev/null 2>&1; then
						if ! echo -- " $LINE " | grep -Eq -- " --(save|restore)-mark .*--nfmask 0x" >/dev/null 2>&1; then
							LINE="$LINE --nfmask 0xffffffff"
						fi
						if ! echo -- " $LINE " | grep -Eq -- " --(save|restore)-mark .*--ctmask 0x" >/dev/null 2>&1; then
							LINE="$LINE --ctmask 0xffffffff"
						fi
					fi
					if echo -- " $LINE " | grep " -j REJECT *$" >/dev/null 2>&1; then
						LINE="$LINE --reject-with icmp-port-unreachable"
					fi
					if echo -- "$LINE" | grep -q -- " -m ipv6-icmp " >/dev/null 2>&1; then
						LINE="$( echo " $LINE " | sed 's| -m ipv6-icmp | -m icmp6 | ; s|^ \+|| ; s| \+$||' )"
					fi
					if echo -- " $LINE " | grep -q -- " --icmp-type " >/dev/null 2>&1; then
						TYPE="$( echo " $LINE " | sed -r "s|^.* --icmp-type ([^ ]+) .*$|\1|" )"
						case $TYPE in
							echo-reply|0)
								TYPE=0
								;;
							destination-unreachable|3)
								TYPE=3
								;;
							echo-request|8)
								TYPE=8
								;;
							time-exceeded|11)
								TYPE=11
								;;
							4|5|6|9|1[0-8]|3[0-9]|4[01])
								:
								;;
							*)
								echo >&2 "WARN: Unrecognised ICMP message type '$TYPE'"
								unset TYPE
								;;
						esac
						[[ -n "$TYPE" ]] && LINE="$( echo " $LINE " | sed "s| --icmp-type [^ ]\+ | --icmp-type ${TYPE} | ; s|^ \+|| ; s| \+$||" )"
						unset TYPE
					fi
					if echo -- " $LINE " | grep -q -- " --icmpv6-type " >/dev/null 2>&1; then
						TYPE="$( echo " $LINE " | sed -r "s|^.* --icmpv6-type ([^ ]+) .*$|\1|" )"
						case $TYPE in
							destination-unreachable|1)
								TYPE=1
								;;
							packet-too-big|2)
								TYPE=2
								;;
							time-exceeded|ttl-exceeded|3)
								TYPE=3
								;;
							parameter-problem|4)
								TYPE=4
								;;
							echo-request|128)
								TYPE=128
								;;
							echo-reply|129)
								TYPE=129
								;;
							router-solicitation|133)
								TYPE=133
								;;
							router-advertisement|134)
								TYPE=134
								;;
							neighbour-solicitation|neighbor-solicitation|135)
								TYPE=135
								;;
							neighbour-advertisement|neighbor-advertisement|136)
								TYPE=136
								;;
							redirect|137)
								TYPE=137
								;;
							13[0-289]|14[0-9]|15[1-35])
								:
								;;
							*)
								echo >&2 "WARN: Unrecognised ICMPv6 message type '$TYPE'"
								unset TYPE
								;;
						esac
						[[ -n "$TYPE" ]] && LINE="$( echo " $LINE " | sed "s| --icmpv6-type [^ ]\+ | --icmpv6-type ${TYPE} | ; s|^ \+|| ; s| \+$||" )"
						unset TYPE
					fi
					if echo -- " $LINE " | grep -q -- " --header " >/dev/null 2>&1; then
						TYPE="$( echo " $LINE " | sed -r "s|^.* --header ([^ ]+) .*$|\1|" )"
						case $TYPE in
							auth)
								TYPE=ah
								;;
							*)
								unset TYPE
								;;
						esac
						[[ -n "$TYPE" ]] && LINE="$( echo " $LINE " | sed "s| --header [^ ]\+ | --header ${TYPE} | ; s|^ \+|| ; s| \+$||" )"
						unset TYPE
					fi
					if echo -- " $LINE " | grep -q -- " -j LOG " >/dev/null 2>&1; then
						if echo -- " $LINE " | grep -q -- " --log-level " >/dev/null 2>&1; then
							LEVEL="$( echo " $LINE " | sed -r "s|^.* --log-level ([^ ]+) .*$|\1|" )"
							case $LEVEL in
								alert)
									LEVEL=1
									;;
								info)
									LEVEL=6
									;;
							esac
							LINE="$( echo " $LINE " | sed "s| --log-level [^ ]\+ | --log-level ${LEVEL} | ; s|^ \+|| ; s| \+$||" )"
							unset LEVEL
						fi
						LINE="$( echo "$LINE" | sed -r 's|(-j LOG.*)( --log-prefix \"[^\"]+\")(.*)$|\1\3\2|' )"
						LINE="$( echo "$LINE" | sed -r 's|(-j LOG.*)( --log-level [^ ]+)(.*)$|\1\3\2|' )"
						LINE="$( echo "$LINE" | sed -r 's|(-j LOG.*)( --log-tcp-sequence)(.*)$|\1\3\2|' )"
						LINE="$( echo "$LINE" | sed -r 's|(-j LOG.*)( --log-tcp-options)(.*)$|\1\3 --log-ip-options|' )"
						LINE="$( echo "$LINE" | sed -r 's|(-j LOG.*)( --log-ip-options)(.*)$|\1\3\2|' )"
						LINE="$( echo "$LINE" | sed -r 's|(-p tcp.*-j LOG.*) --log-ip-options(.*)$|\1 --log-tcp-options\2|' )"
						LINE="$( echo "$LINE" | sed -r 's|(-j LOG.*)( --log-uid)(.*)$|\1\3\2|' )"
						LINE="$( echo "$LINE" | sed -r 's|(-j LOG.*)( --log-macdecode)(.*)$|\1\3\2|' )"
						LINE="$( echo "$LINE" | sed 's| \+--log| --log|g ; s|^ \+|| ; s| \+$||' )"
						(( debug )) && echo "DEBUG: LINE is now '$LINE'"
					fi
					if echo -- " $LINE " | grep -q -- " -m mac --mac-source " >/dev/null 2>&1; then
						MAC="$( echo " $LINE " | sed -r 's|^.* -m mac --mac-source ([0-9a-fA-F:]+) .*|\1|' )"
						MAC="$( tr [:lower:] [:upper:] <<<"$MAC" )"
						LINE="$( echo " $LINE " | sed "s| --mac-source [^ ]\+ | --mac-source ${MAC} | ; s|^ \+|| ; s| \+$||" )"
						unset MAC
					fi
					PREFIX=""
					S=""
					D=""
					I=""
					O=""
					J=""
					SUFFIX=""
					STRING=""
					for ITEM in ${LINE/$COMMENT/ }; do
						(( debug )) && echo >&2 "DEBUG: ITEM is '$ITEM'"
						case $ITEM in
							!)
								PREFIX="!"
								;;
							-s)
								S="$PREFIX -s"
								PREFIX="__next_s_"
								;;
							-d)
								D="$PREFIX -d"
								PREFIX="__next_d_"
								;;
							-i)
								I="$PREFIX -i"
								PREFIX="__next_i_"
								;;
							-o)
								O="$PREFIX -o"
								PREFIX="__next_o_"
								;;
							-j)
								J="-j"
								SUFFIX="__next_j_"
								;;
							*)
								if [[ "$PREFIX" == "__next_i_" ]]; then
									I="$I $ITEM"
									unset PREFIX
								elif [[ "$PREFIX" == "__next_o_" ]]; then
									O="$O $ITEM"
									unset PREFIX
								elif [[ "$PREFIX" == "__next_s_" ]]; then
									S="$S $ITEM"
									unset PREFIX
								elif [[ "$PREFIX" == "__next_d_" ]]; then
									D="$D $ITEM"
									unset PREFIX
								elif [[ "$SUFFIX" == "__next_j_" ]]; then
									J="$J $ITEM"
									# Don't un-set SUFFIX, as it is exhaustive once encountered
									#unset SUFFIX
								elif [[ -n "$PREFIX" ]]; then
									STRING="$STRING $PREFIX $ITEM"
									unset PREFIX
								else
									STRING="$STRING $ITEM"
								fi
								;;
						esac
						(( debug )) && echo >&2 "DEBUG: STRING is '$STRING'"
					done # ITEM in ${LINE/$COMMENT/ }

					# Use '*' instead of '+' so that all instances of '+' may be escaped...
					STRING="$S $D $I $O ?$STRING ?$COMMENT_MATCH ?$J"
					STRING=" -A $CHAIN $STRING "
					# XXX: This squashes spaces inside comments, too...
					STRING="$( sed -r 's|^ +|| ; s| +| |g ; s| $||' <<<"$STRING" )"
					(( debug )) && echo >&2 "DEBUG: STRING is '$STRING' (was '-A $CHAIN $LINE')"
					plain="$( [[ "character special file" == "$( stat -Lc '%F' /dev/stderr )" ]] && echo -n "1" || echo -n "0" )"
					if (( COMPARE )); then
						result="$( grep --colour=$( (( plain )) && echo -n "always" || echo -n "never" ) -En -- "${STRING/+/\\+}$" "${TMPFILE}" )"
						rc=${?}
						if (( ${rc} )); then
							echo -e >&2 "MISS: -t ${table} $( sed 's|(.*)?||g ; s|?||g ; s| \+| |g' <<<"${STRING}" )"
							echo "iptables -t ${table} -I ${CHAIN} $(( ++rulenumber )) ${ORIGINAL}"
							(( debug )) && sleep 5
						else
							if (( 1 == $( echo "${result}" | wc -l ) )); then
								pos="$( cut -d':' -f 1 <<<"${result}" )$( (( plain )) && echo -n "\e[0m" )"
								output="$( cut -d':' -f 2- <<<"${result}" | sed -r 's/^(.*)\[[0-9]+:[0-9]+\] (.*)$/\1\2/' )"
								#echo -e >&2 "OKAY: -t ${table} ${output} # ${DIR}/${version}/${table}/${CHAIN}:${pos}"
								echo -e >&2 "OKAY: -t ${table} ${output} # ${pos}"
								unset pos
								(( rulenumber++ ))
							else
								n=0
								while read -r line; do
									pos="$( cut -d':' -f 1 <<<"${line}" )$( (( plain )) && echo -n "\e[0m" )"
									output="$( cut -d':' -f 2- <<<"${line}" | sed -r 's/^(.*)\[[0-9]+:[0-9]+\] (.*)$/\1\2/' )"
									if ! (( n )); then
										echo -e >&2 "OKAY: -t ${table} ${output} # input line ${pos}"
										(( n++ ))
									else
										echo -e >&2 "DUP:  -t ${table} ${output} # input line ${pos}"
									fi
									unset pos
								done <<<"${result}"
								unset n
								(( rulenumber++ ))
							fi

						fi
					else # ! (( COMPARE ))
						#COUNTER="[0:0]"
						COUNTER=""
						if (( COUNTERS )); then
							COUNTER="$( grep -E -- "${STRING/+/\\+}$" "$TMPFILE" | cut -d' ' -f 1 | sort -k 1.2gr | head -n 1 )"
							#echo >&2 "DEBUG: Read counter '$COUNTER'"
							[[ -n "$COUNTER" ]] || COUNTER="[0:0]"
						fi
						LINE="$( sed 's|^ \+|| ; s| \+$||' <<<"$LINE" )"
						echo "${COUNTER:+${COUNTER} }-A $CHAIN ${LINE//(\/32)?}"
					fi
				done # read -r LINE < "$DIR"/"$version"/"$table"/"$CHAIN"
			fi
		done # CHAIN in $chains
		(( COMPARE )) || echo "COMMIT"
		(( COMPARE )) || echo "# Completed on $( date )"
		rulenumber=0
	done # table in raw nat mangle filter security
done # VERSION in $( find "$DIR" -mindepth 1 -maxdepth 1 -type d )

cleanup

exit 0
