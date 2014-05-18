iptables.d - A management system and rules generator for iptables
=================================================================

Large or complex iptables rule-sets can be awkward to manage, and there are few
good alternatives between the unmanagable flexibility of an iptables init script
which dynamically generated rules on the fly, and the standardisation of loading
a static rule-set.

The rules in `/etc/iptables.d/` and the `generate-iptables-rules.sh` script
allow for a variable-interpolated set of rules to be stored by chain on a per-
table basis, and combined into a iptables rule-set which is identical to that
which would be produced by iptables itself.

`generate-iptables-rules.sh` can produce output with or without counters taken
from the kernel's active counters or - for a more deterministic approach - from
data committed to disk.  It can also output a diff between the currently active
rules and those stored on-disk.

It is worth noting that the `generate-iptables-rules.sh` script has built in
complexity over several years, and it is overly-complex for a shell script and
so is painfully slow, and very much needs to be re-implemented in perl or
similar.  At the very least, is should be ported to use [stdlib.sh](https://github.com/srcshelton/stdlib.sh).
Patches are welcome ;)

The default IPv4 rules provided in this repo originated from a Billion router
which itself derives from a stock Broadcom firmware.  These rules are somehwhat
convoluted and not ialways entirely populated, but do provide a widely-used set
of attack-mitigation rules to build from.  Unfortunately, the pre-existing IPv6
rules were not exposed, so these rules are merely derived from the IPv4
variants.  Additions should be placed in `filter/INPUT` and `filter/FORWARD` as
usual, with incoming connections being DNAT'd from `nat/VS_PRE`.  MAC address
filtering may be performed from `raw/hwchk`.

