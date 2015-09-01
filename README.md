iptables.d - A management system and rules generator for iptables
=================================================================

Large or complex iptables rule-sets can be awkward to manage, and there are few
good alternatives between the unmanagable flexibility of iptables init scripts
which dynamically generate rules on the fly and the constraints imposed by
loading a static rule-set.

The rules in `/etc/iptables.d/` and the `generate-iptables-rules.sh` script
allow for a variable-interpolated set of rules to be declared chain-by-chain
with per-table grouping and then combined into an iptables rule-set which is
identical to that which would be produced by iptables itself.

`generate-iptables-rules.sh` can produce output with or without counters taken
from the kernel's active state or - for a more deterministic approach - from
data committed to disk.  It can also perform a comparison between the currently
active rules and those stored on-disk, to identify where configuration changes
are not yet live.

It is now possible to round-trip between iptables rules and iptables.d
configuration via the new `iptables-convert.sh` script which generates a full
iptables.d configuration in `/etc/iptables.d` from the output of
`iptables-save`.  In addition, `generate-iptables-rules.sh` is now able to
output the necessary `iptables` statements to update the active set to match
the iptables.d rules.  Currently missing iptables rules are detected, but
additional rules are not commented upon - iptables.d is assumed to be the main
point of configuration.

It is worth noting that the `generate-iptables-rules.sh` script has increased
in complexity over several iterations, and has now reached the point where it
is arguably overly-complex for a shell-script task: whilst fully functional, it
is verging on being painfully slow, and very much needs to be re-implemented in
perl or some similar language.  At the very least, is should likely be ported
to use [stdlib.sh](https://github.com/srcshelton/stdlib.sh).
Patches are welcome ;)

The default IPv4 rules provided in this repo originated from a Billion router
which itself derives from a stock Broadcom firmware.  These rules are somehwhat
convoluted and not always entirely populated, but do provide a widely-used set
of attack-mitigation rules from which to build.  Unfortunately, the
pre-existing IPv6 rules were not exposed, so these rules are merely derived
from their IPv4 variants.

Changes and additions should be made to `filter/INPUT` and `filter/FORWARD` as
usual, with incoming connections being DNAT'd from `nat/VS_PRE`.  MAC address
filtering may be performed from `raw/hwchk` if so wished.
