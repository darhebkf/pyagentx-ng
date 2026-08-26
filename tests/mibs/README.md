# MIB test fixtures

Standard MIB modules used by `tests/mib_tests.rs` and `python/tests/mib/`.

They are vendored so the test suite does not depend on Net-SNMP being installed.
All of them are published in IETF RFCs and are reproduced verbatim from the
copies Net-SNMP ships:

| File | Source |
|------|--------|
| `smiv2/SNMPv2-SMI` | RFC 2578 |
| `smiv2/SNMPv2-TC` | RFC 2579 |
| `smiv2/SNMPv2-CONF` | RFC 2580 |
| `smiv2/SNMPv2-MIB` | RFC 3418 |
| `smiv2/IF-MIB` | RFC 2863 |
| `smiv2/IANAifType-MIB` | IANA registry |
| `smiv1/RFC1155-SMI` | RFC 1155 |
| `smiv1/RFC1213-MIB` | RFC 1213 |

The two directories are kept apart on purpose. RFC1213-MIB defines SMIv1
versions of most of what SNMPv2-MIB and IF-MIB define, so loading both at once
produces a long list of duplicate-symbol diagnostics — correct behaviour, but
it buries everything else.

`broken/BROKEN-MIB` is not a real module. It is hand-written to exercise error
recovery: every definition in it is wrong in a different way, and the parser
has to keep going and still produce the valid definitions around them.
