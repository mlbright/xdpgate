# xdpgate

A default-deny ingress gate: traffic to guarded destination addresses is dropped
unless an SPA knock has earned the sender a time-limited exception.

## Language

**Protected set**:
The local destination addresses the gate guards. Traffic to any address outside
it is never filtered.
_Avoid_: gated IPs, protected list

**Runtime override**:
A change to the live protected set made outside the config file, which the next
reload or reboot undoes.
_Avoid_: transient entry, manual add

**Grant**:
Permission for one source address to reach one protocol and port on the
protected set, until its expiry. Issued in response to a valid SPA knock.
_Avoid_: allow entry, rule, opening

**Expired grant**:
A grant past its expiry. The gate already refuses it; it lingers only until it
is reaped.
_Avoid_: stale entry
