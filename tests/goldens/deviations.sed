# Every place the port knowingly prints something other than the C did.
# tests/goldens.sh --record applies this to the C build's stdout and stderr, so
# the goldens record what the port must print and still re-record from the C.

# The protected maps' capacity moved from xdpgate.bpf.c, which the port
# deletes, to xdpgate-common/src/lib.rs, so the advice on raising it names the
# new file.
s|^  xdpgate\.bpf\.c and rebuild if you genuinely need more\.$|  xdpgate-common/src/lib.rs and rebuild if you genuinely need more.|
s|; raise it in xdpgate\.bpf\.c and rebuild\.$|; raise it in xdpgate-common/src/lib.rs and rebuild.|
