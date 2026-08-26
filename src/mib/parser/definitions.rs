use super::Parser;
use crate::mib::lexer::Token;
use crate::mib::{
    Access, Definition, NodeDef, NodeFlavour, NotificationDef, ObjectDef, OidComponent, OidExpr,
    Status, Syntax, TypeDef, TypeDefKind,
};

// The SMI definition macros: OBJECT-TYPE, MODULE-IDENTITY, OBJECT-IDENTITY,
// NOTIFICATION-TYPE, TRAP-TYPE and plain type assignments.
impl Parser<'_> {
    pub(super) fn parse_oid_node(
        &mut self,
        name: String,
        flavour: NodeFlavour,
        line: usize,
    ) -> Option<Definition> {
        let mut status = None;
        let mut description = None;

        if flavour != NodeFlavour::ObjectIdentifier {
            loop {
                match self.peek_word() {
                    Some("STATUS") => {
                        self.advance();
                        status = self.take_text().as_deref().and_then(Status::parse);
                    }
                    Some("DESCRIPTION") => {
                        self.advance();
                        let text = self.take_text();
                        // MODULE-IDENTITY repeats DESCRIPTION per REVISION; keep the first.
                        description = description.or(text);
                    }
                    Some("LAST-UPDATED") | Some("ORGANIZATION") | Some("CONTACT-INFO")
                    | Some("REFERENCE") | Some("REVISION") => {
                        self.advance();
                        self.take_text();
                    }
                    _ => break,
                }
            }
        }

        if !self.expect_assignment(line, &name) {
            return None;
        }
        let oid = self.parse_oid_value()?;
        Some(Definition::Node(NodeDef {
            name,
            flavour,
            oid,
            status,
            description,
            line,
        }))
    }

    pub(super) fn parse_object_type(&mut self, name: String, line: usize) -> Option<Definition> {
        let mut syntax = None;
        let mut max_access = None;
        let mut status = None;
        let mut description = None;
        let mut reference = None;
        let mut units = None;
        let mut index = Vec::new();
        let mut augments = None;
        let mut defval = None;

        loop {
            match self.peek_word() {
                Some("SYNTAX") => {
                    self.advance();
                    syntax = self.parse_syntax();
                }
                Some("UNITS") => {
                    self.advance();
                    units = self.take_text();
                }
                // SMIv1 (RFC 1212) spells it ACCESS.
                Some("MAX-ACCESS") | Some("ACCESS") => {
                    self.advance();
                    let word = self.take_text();
                    max_access = word.as_deref().and_then(Access::parse);
                    if max_access.is_none() {
                        let what = word.unwrap_or_default();
                        self.diagnose(line, format!("{name}: unknown access '{what}'"));
                    }
                }
                Some("STATUS") => {
                    self.advance();
                    let word = self.take_text();
                    status = word.as_deref().and_then(Status::parse);
                    if status.is_none() {
                        let what = word.unwrap_or_default();
                        self.diagnose(line, format!("{name}: unknown status '{what}'"));
                    }
                }
                Some("DESCRIPTION") => {
                    self.advance();
                    description = self.take_text();
                }
                Some("REFERENCE") => {
                    self.advance();
                    reference = self.take_text();
                }
                Some("INDEX") => {
                    self.advance();
                    index = self.parse_index();
                }
                Some("AUGMENTS") => {
                    self.advance();
                    augments = self.parse_index().into_iter().next().map(|f| f.name);
                }
                Some("DEFVAL") => {
                    self.advance();
                    defval = self.parse_defval();
                }
                _ => break,
            }
        }

        if !self.expect_assignment(line, &name) {
            return None;
        }
        let oid = self.parse_oid_value()?;

        let syntax = syntax.unwrap_or(Syntax::Named {
            name: "OBJECT IDENTIFIER".to_string(),
            constraint: None,
            enums: Vec::new(),
        });

        Some(Definition::Object(Box::new(ObjectDef {
            name,
            syntax,
            max_access: max_access.unwrap_or_default(),
            status: status.unwrap_or_default(),
            description,
            reference,
            units,
            index,
            augments,
            defval,
            oid,
            line,
        })))
    }

    pub(super) fn parse_notification(
        &mut self,
        name: String,
        line: usize,
        is_v1_trap: bool,
    ) -> Option<Definition> {
        let mut objects = Vec::new();
        let mut status = None;
        let mut description = None;
        let mut enterprise = None;

        loop {
            match self.peek_word() {
                // RFC 1215 spells the object list VARIABLES.
                Some("OBJECTS") | Some("VARIABLES") => {
                    self.advance();
                    objects = self.parse_index().into_iter().map(|f| f.name).collect();
                }
                Some("ENTERPRISE") => {
                    self.advance();
                    enterprise = match self.peek() {
                        Some(Token::LBrace) => self.parse_oid_value().and_then(first_name),
                        _ => self.take_text(),
                    };
                }
                Some("STATUS") => {
                    self.advance();
                    status = self.take_text().as_deref().and_then(Status::parse);
                }
                Some("DESCRIPTION") => {
                    self.advance();
                    description = self.take_text();
                }
                Some("REFERENCE") => {
                    self.advance();
                    self.take_text();
                }
                _ => break,
            }
        }

        if !self.expect_assignment(line, &name) {
            return None;
        }

        let oid = if is_v1_trap {
            // RFC 2576 §3.1: an SMIv1 trap maps to the notification OID
            // `<enterprise>.0.<specific-trap>`.
            let specific = match self.peek() {
                Some(Token::Number(n)) => {
                    let n = *n;
                    self.advance();
                    n.try_into().unwrap_or(0)
                }
                _ => {
                    self.diagnose(line, format!("{name}: TRAP-TYPE without a trap number"));
                    return None;
                }
            };
            let Some(enterprise) = enterprise else {
                self.diagnose(line, format!("{name}: TRAP-TYPE without ENTERPRISE"));
                return None;
            };
            OidExpr {
                components: vec![
                    OidComponent::Name(enterprise),
                    OidComponent::Number(0),
                    OidComponent::Number(specific),
                ],
            }
        } else {
            self.parse_oid_value()?
        };

        Some(Definition::Notification(NotificationDef {
            name,
            objects,
            status,
            description,
            oid,
            line,
        }))
    }

    pub(super) fn parse_type_assignment(
        &mut self,
        name: String,
        line: usize,
    ) -> Option<Definition> {
        if self.eat_word("TEXTUAL-CONVENTION") {
            let mut display_hint = None;
            let mut status = None;
            let mut description = None;
            let mut syntax = None;

            loop {
                match self.peek_word() {
                    Some("DISPLAY-HINT") => {
                        self.advance();
                        display_hint = self.take_text();
                    }
                    Some("STATUS") => {
                        self.advance();
                        status = self.take_text().as_deref().and_then(Status::parse);
                    }
                    Some("DESCRIPTION") => {
                        self.advance();
                        description = self.take_text();
                    }
                    Some("REFERENCE") => {
                        self.advance();
                        self.take_text();
                    }
                    Some("SYNTAX") => {
                        self.advance();
                        syntax = self.parse_syntax();
                        break;
                    }
                    _ => break,
                }
            }

            let Some(syntax) = syntax else {
                self.diagnose(line, format!("{name}: TEXTUAL-CONVENTION without SYNTAX"));
                return None;
            };
            return Some(Definition::Type(TypeDef {
                name,
                kind: TypeDefKind::TextualConvention {
                    display_hint,
                    status,
                    description,
                    syntax,
                },
                line,
            }));
        }

        let syntax = self.parse_syntax()?;
        Some(Definition::Type(TypeDef {
            name,
            kind: TypeDefKind::Alias(syntax),
            line,
        }))
    }

    pub(super) fn expect_assignment(&mut self, line: usize, name: &str) -> bool {
        if self.eat(&Token::Assign) {
            return true;
        }
        self.diagnose(line, format!("{name}: expected ::= before the OID"));
        self.skip_to_assignment()
    }
}

fn first_name(expr: OidExpr) -> Option<String> {
    expr.components.into_iter().find_map(|c| match c {
        OidComponent::Name(n) | OidComponent::NamedNumber(n, _) => Some(n),
        OidComponent::Number(_) => None,
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{parse_one, wrap};
    use crate::mib::{Access, Definition, NodeFlavour, OidComponent, Status, TypeDefKind};

    #[test]
    fn test_parses_object_identifier_assignment() {
        let m = parse_one(&wrap("mib-2 OBJECT IDENTIFIER ::= { mgmt 1 }"));
        match &m.definitions[0] {
            Definition::Node(n) => {
                assert_eq!(n.name, "mib-2");
                assert_eq!(n.flavour, NodeFlavour::ObjectIdentifier);
                assert_eq!(
                    n.oid.components,
                    vec![OidComponent::Name("mgmt".into()), OidComponent::Number(1)]
                );
            }
            other => panic!("expected a node, got {other:?}"),
        }
    }

    #[test]
    fn test_parses_object_type_with_every_clause() {
        let m = parse_one(&wrap(
            r#"ifSpeed OBJECT-TYPE
                SYNTAX      Gauge32
                UNITS       "bits per second"
                MAX-ACCESS  read-only
                STATUS      current
                DESCRIPTION "An estimate."
                REFERENCE   "RFC 2863"
                ::= { ifEntry 5 }"#,
        ));
        let Definition::Object(o) = &m.definitions[0] else {
            panic!("expected an object")
        };
        assert_eq!(o.name, "ifSpeed");
        assert_eq!(o.syntax.type_name(), "Gauge32");
        assert_eq!(o.units.as_deref(), Some("bits per second"));
        assert_eq!(o.max_access, Access::ReadOnly);
        assert_eq!(o.status, Status::Current);
        assert_eq!(o.description.as_deref(), Some("An estimate."));
        assert_eq!(o.reference.as_deref(), Some("RFC 2863"));
    }

    #[test]
    fn test_parses_augments() {
        let m = parse_one(&wrap(
            r#"x OBJECT-TYPE SYNTAX X MAX-ACCESS not-accessible STATUS current
                 AUGMENTS { ifEntry } ::= { t 1 }"#,
        ));
        let Definition::Object(o) = &m.definitions[0] else {
            panic!()
        };
        assert_eq!(o.augments.as_deref(), Some("ifEntry"));
        assert!(o.index.is_empty());
    }

    #[test]
    fn test_parses_textual_convention() {
        let m = parse_one(&wrap(
            r#"DateAndTime ::= TEXTUAL-CONVENTION
                 DISPLAY-HINT "2d-1d-1d,1d:1d:1d.1d,1a1d:1d"
                 STATUS       current
                 DESCRIPTION  "A date-time specification."
                 SYNTAX       OCTET STRING (SIZE (8 | 11))"#,
        ));
        let Definition::Type(ty) = &m.definitions[0] else {
            panic!()
        };
        let TypeDefKind::TextualConvention {
            display_hint,
            syntax,
            status,
            ..
        } = &ty.kind
        else {
            panic!("expected a textual convention")
        };
        assert_eq!(
            display_hint.as_deref(),
            Some("2d-1d-1d,1d:1d:1d.1d,1a1d:1d")
        );
        assert_eq!(*status, Some(Status::Current));
        assert_eq!(syntax.type_name(), "OCTET STRING");
    }

    #[test]
    fn test_parses_notification_type() {
        let m = parse_one(&wrap(
            r#"linkDown NOTIFICATION-TYPE
                 OBJECTS { ifIndex, ifAdminStatus }
                 STATUS  current
                 DESCRIPTION "A linkDown trap."
                 ::= { snmpTraps 3 }"#,
        ));
        let Definition::Notification(n) = &m.definitions[0] else {
            panic!()
        };
        assert_eq!(n.name, "linkDown");
        assert_eq!(n.objects, vec!["ifIndex", "ifAdminStatus"]);
    }

    #[test]
    fn test_smiv1_trap_maps_to_notification_oid() {
        // RFC 2576 §3.1: enterprise . 0 . specific
        let m = parse_one(&wrap(
            r#"whooshTrap TRAP-TYPE
                 ENTERPRISE whoosh
                 VARIABLES  { ifIndex }
                 DESCRIPTION "Something happened."
                 ::= 7"#,
        ));
        let Definition::Notification(n) = &m.definitions[0] else {
            panic!()
        };
        assert_eq!(
            n.oid.components,
            vec![
                OidComponent::Name("whoosh".into()),
                OidComponent::Number(0),
                OidComponent::Number(7),
            ]
        );
        assert_eq!(n.objects, vec!["ifIndex"]);
    }

    #[test]
    fn test_smiv1_access_and_status_keywords() {
        let m = parse_one(&wrap(
            r#"sysDescr OBJECT-TYPE
                 SYNTAX  OCTET STRING
                 ACCESS  read-only
                 STATUS  mandatory
                 DESCRIPTION "A description."
                 ::= { system 1 }"#,
        ));
        let Definition::Object(o) = &m.definitions[0] else {
            panic!()
        };
        assert_eq!(o.max_access, Access::ReadOnly);
        assert_eq!(o.status, Status::Mandatory);
    }

    #[test]
    fn test_unknown_access_is_diagnosed_but_object_survives() {
        let m = parse_one(&wrap(
            r#"x OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-sideways STATUS current ::= { y 1 }"#,
        ));
        assert_eq!(m.definitions.len(), 1);
        assert!(
            m.diagnostics
                .iter()
                .any(|d| d.message.contains("read-sideways"))
        );
    }
}
