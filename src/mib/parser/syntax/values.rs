use super::super::{Parser, clamp_subid};
use crate::mib::lexer::Token;
use crate::mib::{IndexField, OidComponent, OidExpr};

// The values that follow `::=`, plus the brace-delimited lists that
// INDEX, AUGMENTS, OBJECTS and DEFVAL share.
impl Parser<'_> {
    pub(in crate::mib::parser) fn parse_oid_value(&mut self) -> Option<OidExpr> {
        if !self.eat(&Token::LBrace) {
            let line = self.line();
            self.diagnose(line, "expected { after ::=");
            return None;
        }
        let mut components = Vec::new();
        loop {
            match self.peek() {
                None => break,
                Some(Token::RBrace) => {
                    self.advance();
                    break;
                }
                Some(Token::Number(n)) => {
                    let n = *n;
                    self.advance();
                    components.push(OidComponent::Number(clamp_subid(n)));
                }
                Some(Token::Word(w)) => {
                    let label = w.clone();
                    self.advance();
                    if self.eat(&Token::LParen) {
                        let value = match self.peek() {
                            Some(Token::Number(n)) => {
                                let n = *n;
                                self.advance();
                                clamp_subid(n)
                            }
                            _ => 0,
                        };
                        self.eat(&Token::RParen);
                        components.push(OidComponent::NamedNumber(label, value));
                    } else {
                        components.push(OidComponent::Name(label));
                    }
                }
                Some(_) => self.advance(),
            }
        }
        Some(OidExpr { components })
    }

    pub(in crate::mib::parser) fn parse_index(&mut self) -> Vec<IndexField> {
        let mut fields = Vec::new();
        if !self.eat(&Token::LBrace) {
            return fields;
        }
        let mut implied = false;
        loop {
            match self.peek() {
                None => break,
                Some(Token::RBrace) => {
                    self.advance();
                    break;
                }
                Some(Token::Word(w)) if w == "IMPLIED" => {
                    self.advance();
                    implied = true;
                }
                Some(Token::Word(w)) => {
                    let name = w.clone();
                    self.advance();
                    fields.push(IndexField { name, implied });
                    implied = false;
                }
                Some(_) => self.advance(),
            }
        }
        fields
    }

    pub(in crate::mib::parser) fn parse_defval(&mut self) -> Option<String> {
        if !self.eat(&Token::LBrace) {
            return None;
        }
        let mut parts: Vec<String> = Vec::new();
        let mut depth = 1usize;
        while let Some(token) = self.peek() {
            match token {
                Token::LBrace => {
                    depth += 1;
                    parts.push("{".into());
                }
                Token::RBrace => {
                    depth -= 1;
                    if depth == 0 {
                        self.advance();
                        break;
                    }
                    parts.push("}".into());
                }
                Token::Word(w) => parts.push(w.clone()),
                Token::Number(n) => parts.push(n.to_string()),
                Token::Text(s) => parts.push(format!("\"{s}\"")),
                Token::Bytes(b) => parts.push(b.iter().map(|x| format!("{x:02X}")).collect()),
                Token::Comma => parts.push(",".into()),
                _ => {}
            }
            self.advance();
        }
        Some(parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use crate::mib::parser::test_support::{parse_one, wrap};
    use crate::mib::{Definition, IndexField, OidComponent};

    #[test]
    fn test_parses_named_number_oid_components() {
        let m = parse_one(&wrap(
            "internet OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 }",
        ));
        let Definition::Node(n) = &m.definitions[0] else {
            panic!("expected a node")
        };
        assert_eq!(
            n.oid.components,
            vec![
                OidComponent::Name("iso".into()),
                OidComponent::NamedNumber("org".into(), 3),
                OidComponent::NamedNumber("dod".into(), 6),
                OidComponent::Number(1),
            ]
        );
    }

    #[test]
    fn test_parses_defval() {
        let m = parse_one(&wrap(
            r#"x OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-write STATUS current
                 DEFVAL { 42 } ::= { y 1 }"#,
        ));
        let Definition::Object(o) = &m.definitions[0] else {
            panic!()
        };
        assert_eq!(o.defval.as_deref(), Some("42"));
    }

    #[test]
    fn test_parses_implied_index() {
        let m = parse_one(&wrap(
            r#"e OBJECT-TYPE SYNTAX E MAX-ACCESS not-accessible STATUS current
                 INDEX { a, IMPLIED b } ::= { t 1 }"#,
        ));
        let Definition::Object(o) = &m.definitions[0] else {
            panic!()
        };
        assert_eq!(
            o.index,
            vec![
                IndexField {
                    name: "a".into(),
                    implied: false
                },
                IndexField {
                    name: "b".into(),
                    implied: true
                },
            ]
        );
    }
}
