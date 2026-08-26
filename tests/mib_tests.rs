//! MIB parsing against real modules.
//!
//! The fixtures in `tests/mibs/` are the published RFC modules, so anything
//! that fails here would fail on a real device's MIB too.

use std::fs;
use std::path::{Path, PathBuf};

use snmpkit::mib::{BaseType, MibModule, NodeKind, Registry, parse_modules};

const SPEC_FIXTURES: &[&str] = &[
    "smiv2/SNMPv2-SMI",
    "smiv2/SNMPv2-TC",
    "smiv2/SNMPv2-CONF",
    "smiv2/SNMPv2-MIB",
    "smiv2/IANAifType-MIB",
    "smiv2/IF-MIB",
];

const SMIV1_FIXTURES: &[&str] = &["smiv1/RFC1155-SMI", "smiv1/RFC1213-MIB"];

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mibs")
}

fn parse_fixtures(names: &[&str]) -> Vec<MibModule> {
    let mut modules = Vec::new();
    for name in names {
        let path = fixture_dir().join(name);
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
        let parsed =
            parse_modules(&text, name).unwrap_or_else(|e| panic!("{name} failed to lex: {e}"));
        assert_eq!(parsed.len(), 1, "{name} should hold exactly one module");
        modules.extend(parsed);
    }
    modules
}

fn spec_registry() -> Registry {
    Registry::build(&parse_fixtures(SPEC_FIXTURES))
}

#[test]
fn test_sys_up_time_resolves_in_both_directions() {
    let reg = spec_registry();

    let by_name = reg.lookup("sysUpTime").expect("sysUpTime is in SNMPv2-MIB");
    assert_eq!(by_name.oid.to_string(), "1.3.6.1.2.1.1.3");
    assert_eq!(by_name.module, "SNMPv2-MIB");

    let by_oid = reg.lookup(".1.3.6.1.2.1.1.3").expect("looks up by OID");
    assert_eq!(by_oid.name, "sysUpTime");
    assert_eq!(by_oid.base_type(), Some(BaseType::TimeTicks));
}

#[test]
fn test_every_object_round_trips_name_to_oid_to_name() {
    let reg = spec_registry();
    assert!(
        reg.len() > 140,
        "expected a substantial tree, got {}",
        reg.len()
    );

    for node in reg.nodes() {
        let from_name = reg
            .lookup(&node.name)
            .unwrap_or_else(|| panic!("{} is not reachable by name", node.name));
        assert_eq!(
            from_name.oid, node.oid,
            "{} resolved to a different OID",
            node.name
        );

        let from_oid = reg
            .lookup(&node.oid.to_string())
            .unwrap_or_else(|| panic!("{} is not reachable by OID", node.oid));
        assert_eq!(
            from_oid.name, node.name,
            "{} resolved back to a different name",
            node.oid
        );
    }
}

#[test]
fn test_if_table_is_detected_with_its_row_type_and_index() {
    let reg = spec_registry();

    let table = reg.lookup("ifTable").expect("ifTable");
    assert_eq!(table.kind, NodeKind::Table);
    assert_eq!(table.oid.to_string(), "1.3.6.1.2.1.2.2");
    assert_eq!(table.row_type.as_deref(), Some("IfEntry"));

    let row = reg.lookup("ifEntry").expect("ifEntry");
    assert_eq!(row.kind, NodeKind::Row);
    assert_eq!(row.parent.map(|p| &reg.nodes()[p].name), Some(&table.name));
    let index: Vec<&str> = row.index.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(index, vec!["ifIndex"]);
    assert!(!row.index[0].implied);

    let column = reg.lookup("ifDescr").expect("ifDescr");
    assert_eq!(column.kind, NodeKind::Column);
    assert_eq!(column.oid.to_string(), "1.3.6.1.2.1.2.2.1.2");

    // Every column of ifTable hangs off ifEntry.
    let columns = &reg.nodes()[reg.index_of_name("ifEntry").unwrap()].children;
    assert_eq!(columns.len(), 22, "RFC 2863 gives ifEntry 22 columns");
}

#[test]
fn test_augmenting_row_inherits_the_index_it_augments() {
    let reg = spec_registry();
    let row = reg.lookup("ifXEntry").expect("ifXEntry augments ifEntry");
    assert_eq!(row.augments.as_deref(), Some("ifEntry"));
    let index: Vec<&str> = row.index.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(index, vec!["ifIndex"], "RFC 2578 §7.8.1");
}

#[test]
fn test_textual_convention_chains_resolve_to_a_base_type() {
    let reg = spec_registry();

    // ifIndex -> InterfaceIndex -> Integer32
    let if_index = reg.lookup("ifIndex").unwrap();
    assert_eq!(if_index.syntax.as_ref().unwrap().declared, "InterfaceIndex");
    assert_eq!(if_index.base_type(), Some(BaseType::Integer32));

    // ifDescr -> DisplayString -> OCTET STRING
    let if_descr = reg.lookup("ifDescr").unwrap();
    assert_eq!(if_descr.syntax.as_ref().unwrap().declared, "DisplayString");
    assert_eq!(if_descr.base_type(), Some(BaseType::OctetString));

    // sysServices is a plain Integer32 with no convention in between.
    assert_eq!(
        reg.lookup("sysServices").unwrap().base_type(),
        Some(BaseType::Integer32)
    );
}

#[test]
fn test_display_hint_is_inherited_from_the_textual_convention() {
    let reg = spec_registry();

    // ifPhysAddress -> PhysAddress, whose DISPLAY-HINT is "1x:".
    let phys = reg.lookup("ifPhysAddress").unwrap();
    assert_eq!(phys.display_hint(), Some("1x:"));

    // DisplayString carries "255a".
    assert_eq!(reg.lookup("sysDescr").unwrap().display_hint(), Some("255a"));
}

#[test]
fn test_enumeration_labels_survive_resolution() {
    let reg = spec_registry();

    let admin = reg.lookup("ifAdminStatus").unwrap();
    let labels: Vec<(&str, i64)> = admin
        .enums()
        .iter()
        .map(|e| (e.name.as_str(), e.value))
        .collect();
    assert_eq!(labels, vec![("up", 1), ("down", 2), ("testing", 3)]);

    // ifType's labels come through IANAifType, a textual convention in
    // another module with over 250 enumeration values.
    let if_type = reg.lookup("ifType").unwrap();
    assert_eq!(if_type.syntax.as_ref().unwrap().declared, "IANAifType");
    assert_eq!(if_type.base_type(), Some(BaseType::Integer32));
    assert!(
        if_type.enums().len() > 200,
        "IANAifType has hundreds of values, found {}",
        if_type.enums().len()
    );
    assert!(if_type.enums().iter().any(|e| e.name == "ethernetCsmacd"));
}

#[test]
fn test_notifications_are_recorded_with_their_objects() {
    let reg = spec_registry();
    let link_down = reg.lookup("linkDown").expect("linkDown");
    assert_eq!(link_down.kind, NodeKind::Notification);
    assert!(link_down.objects.contains(&"ifIndex".to_string()));
}

#[test]
fn test_spec_fixtures_resolve_without_complaint() {
    let reg = spec_registry();
    let complaints: Vec<String> = reg.diagnostics().iter().map(|d| d.to_string()).collect();
    assert!(
        complaints.is_empty(),
        "the published RFC modules should parse cleanly, got: {complaints:#?}"
    );
}

#[test]
fn test_smiv1_modules_parse_and_resolve() {
    let reg = Registry::build(&parse_fixtures(SMIV1_FIXTURES));

    // RFC 1155 §3.2.3 spells the root path with named-number components.
    assert_eq!(reg.lookup("internet").unwrap().oid.to_string(), "1.3.6.1");
    assert_eq!(
        reg.lookup("enterprises").unwrap().oid.to_string(),
        "1.3.6.1.4.1"
    );

    // RFC 1213 uses the SMIv1 ACCESS/STATUS keywords throughout.
    let sys_descr = reg.lookup("sysDescr").expect("sysDescr from RFC1213-MIB");
    assert_eq!(sys_descr.oid.to_string(), "1.3.6.1.2.1.1.1");
    assert_eq!(sys_descr.base_type(), Some(BaseType::OctetString));
    assert_eq!(sys_descr.status.map(|s| s.as_str()), Some("mandatory"));

    // SMIv1's Counter and Gauge are recognised as base types.
    assert_eq!(
        reg.lookup("ifInOctets").unwrap().base_type(),
        Some(BaseType::Counter32)
    );
    assert_eq!(
        reg.lookup("ifSpeed").unwrap().base_type(),
        Some(BaseType::Gauge32)
    );

    // ipAddrTable is a conceptual table even in SMIv1.
    assert_eq!(reg.lookup("ipAddrTable").unwrap().kind, NodeKind::Table);
    let row = reg.lookup("ipAddrEntry").unwrap();
    assert_eq!(row.kind, NodeKind::Row);
    assert_eq!(
        row.index
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        vec!["ipAdEntAddr"]
    );
}

#[test]
fn test_a_broken_mib_loads_with_diagnostics_instead_of_failing() {
    let mut modules = parse_fixtures(SPEC_FIXTURES);
    modules.extend(parse_fixtures(&["broken/BROKEN-MIB"]));
    let reg = Registry::build(&modules);

    // The good definitions on either side of the damage came through.
    let first = reg
        .lookup("goodScalarOne")
        .expect("the object before the damage");
    assert_eq!(first.oid.to_string(), "1.3.6.1.4.1.99999.1");
    let last = reg
        .lookup("goodScalarTwo")
        .expect("the object after the damage");
    assert_eq!(last.oid.to_string(), "1.3.6.1.4.1.99999.9");
    assert_eq!(last.base_type(), Some(BaseType::OctetString));

    // The definition using an invented macro was dropped.
    assert!(reg.lookup("nonsenseMacro").is_none());
    // So was the one hanging off a parent that does not exist.
    assert!(reg.lookup("orphan").is_none());
    // And the pair that point at each other.
    assert!(reg.lookup("loopA").is_none());
    assert!(reg.lookup("loopB").is_none());

    // Bad enumerated keywords are reported but the objects still load.
    assert!(reg.lookup("badAccess").is_some());
    assert!(reg.lookup("badStatus").is_some());

    let messages: Vec<&str> = reg
        .diagnostics()
        .iter()
        .map(|d| d.message.as_str())
        .collect();
    for expected in [
        "nonsenseMacro",
        "read-sideways",
        "lukewarm",
        "neverDefinedAnywhere",
    ] {
        assert!(
            messages.iter().any(|m| m.contains(expected)),
            "expected a diagnostic mentioning {expected}, got {messages:#?}"
        );
    }
}

// Parses every MIB Net-SNMP installs, if it is installed.
//
// The fixtures above prove correctness; this proves the parser survives 300
// modules written by different people over thirty years.
#[test]
fn test_net_snmp_corpus_parses() {
    let corpus = Path::new("/usr/share/snmp/mibs");
    if !corpus.is_dir() {
        eprintln!("skipping: {} is not present", corpus.display());
        return;
    }

    let mut modules = Vec::new();
    let mut files = 0usize;
    let mut lex_failures = Vec::new();
    for path in walk(corpus) {
        let Ok(bytes) = fs::read(&path) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        if !text.contains("DEFINITIONS") {
            continue;
        }
        files += 1;
        match parse_modules(&text, &path.display().to_string()) {
            Ok(parsed) => modules.extend(parsed),
            Err(e) => lex_failures.push(format!("{}: {e}", path.display())),
        }
    }

    // Distributions ship this directory with only Net-SNMP's own handful of
    // MIBs; the IETF corpus arrives with snmp-mibs-downloader, which CI has no
    // reason to install. Skip rather than fail when it is not there.
    if files < 100 {
        eprintln!(
            "skipping: {} holds {files} MIBs, not the full corpus",
            corpus.display()
        );
        return;
    }
    assert!(
        lex_failures.is_empty(),
        "these files could not be tokenised at all: {lex_failures:#?}"
    );
    assert_eq!(
        modules.len(),
        files,
        "every corpus file should yield at least one module"
    );

    let reg = Registry::build(&modules);
    eprintln!(
        "corpus: {files} files, {} modules, {} nodes, {} diagnostics",
        modules.len(),
        reg.len(),
        reg.diagnostics().len()
    );

    // Spot-check objects from modules right across the corpus.
    for (name, oid) in [
        ("sysUpTime", "1.3.6.1.2.1.1.3"),
        ("ifDescr", "1.3.6.1.2.1.2.2.1.2"),
        ("tcpConnState", "1.3.6.1.2.1.6.13.1.1"),
        ("udpLocalPort", "1.3.6.1.2.1.7.5.1.2"),
        ("hrSystemUptime", "1.3.6.1.2.1.25.1.1"),
        ("snmpInPkts", "1.3.6.1.2.1.11.1"),
        ("entPhysicalDescr", "1.3.6.1.2.1.47.1.1.1.1.2"),
        ("bgpPeerState", "1.3.6.1.2.1.15.3.1.2"),
        ("dot1dBaseNumPorts", "1.3.6.1.2.1.17.1.2"),
        ("usmUserName", "1.3.6.1.6.3.15.1.2.2.1.2"),
    ] {
        let node = reg
            .lookup(name)
            .unwrap_or_else(|| panic!("{name} did not resolve"));
        assert_eq!(
            node.oid.to_string(),
            oid,
            "{name} resolved to the wrong OID"
        );
    }

    // None of the vendored fixtures use UNITS; HOST-RESOURCES-MIB does.
    assert_eq!(
        reg.lookup("hrMemorySize").unwrap().units.as_deref(),
        Some("KBytes")
    );

    // A tree this size is mostly resolvable; a large unresolved fraction would
    // mean the parser is dropping definitions.
    assert!(
        reg.len() > 20_000,
        "expected the corpus to yield a large tree, got {} nodes",
        reg.len()
    );

    // Most diagnostics are real disagreements between overlapping standard
    // MIBs. What is left is the parser's own failures, and there should be
    // almost none: at the time of writing, one genuine typo in HPR-MIB and two
    // constructs in SNMPv2-PDU, which is ASN.1 rather than SMI.
    let parse_failures: Vec<&str> = reg
        .diagnostics()
        .iter()
        .map(|d| d.message.as_str())
        .filter(|m| !m.contains("already defined") && !m.contains("share OID"))
        .collect();
    assert!(
        parse_failures.len() <= 3,
        "the parser is failing on more of the corpus than it used to: {parse_failures:#?}"
    );
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out.sort();
    out
}
