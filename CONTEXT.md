# xdpgate

A default-deny ingress gate: traffic to guarded destination addresses is dropped
unless an SPA knock has earned the sender a time-limited exception.

## Language

**Protected set**:
The local destination addresses the gate guards. Traffic to any address outside
it is never filtered.
_Avoid_: gated IPs, protected list

**Declared protected set**:
The addresses the config file lists. Attaching and reloading make the protected
set match it; runtime overrides are where the two differ.
_Avoid_: config set, desired set, prot_set

**Runtime override**:
A change to the live protected set made outside the config file, which the next
reload or reboot undoes.
_Avoid_: transient entry, manual add

**SPA carve-out**:
The single exception to the gate: SPA knocks reach any address, including the
protected set, so fwknopd can always receive them.
_Avoid_: bypass, whitelist, exemption

**Grant**:
Permission for one source address to reach one protocol and port on the
protected set, until its expiry. Issued in response to a valid SPA knock.
_Avoid_: allow entry, rule, opening

**Expired grant**:
A grant past its expiry. The gate already refuses it; it lingers only until it
is reaped.
_Avoid_: stale entry
