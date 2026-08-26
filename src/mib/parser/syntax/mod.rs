mod values;

use super::Parser;
use crate::mib::lexer::Token;
use crate::mib::{Constraint, NamedNumber, Range, SequenceField, Syntax};

// SYNTAX clauses, subtype constraints and the values that follow `::=`.
// Module framing and the definition macros stay in the parent module.
impl Parser<'_> {
    pub(super) fn parse_syntax(&mut self) -> Option<Syntax> {
        // `[APPLICATION n] IMPLICIT` — a wire detail the MIB layer does not model.
        if self.peek() == Some(&Token::Other('[')) {
            while self.peek().is_some() && !self.eat(&Token::Other(']')) {
                self.advance();
            }
            self.eat_word("IMPLICIT");
            self.eat_word("EXPLICIT");
        }

        let name = match self.peek() {
            Some(Token::Word(w)) => w.clone(),
            _ => {
                let line = self.line();
                self.diagnose(line, "expected a type name in SYNTAX");
                return None;
            }
        };
        self.advance();

        match name.as_str() {
            "SEQUENCE" => {
                if self.eat_word("OF") {
                    let row = match self.peek() {
                        Some(Token::Word(w)) => w.clone(),
                        _ => return None,
                    };
                    self.advance();
                    return Some(Syntax::SequenceOf(row));
                }
                return Some(Syntax::Sequence(self.parse_sequence_fields()));
            }
            // CHOICE only appears in SMIv1 plumbing types.
            "CHOICE" => {
                self.skip_braces();
                return Some(Syntax::Named {
                    name,
                    constraint: None,
                    enums: Vec::new(),
                });
            }
            _ => {}
        }

        // Two grammar words, one type.
        let name = match name.as_str() {
            "OCTET" if self.peek_word() == Some("STRING") => {
                self.advance();
                "OCTET STRING".to_string()
            }
            "OBJECT" if self.peek_word() == Some("IDENTIFIER") => {
                self.advance();
                "OBJECT IDENTIFIER".to_string()
            }
            _ => name,
        };

        let enums = if self.peek() == Some(&Token::LBrace) {
            self.parse_named_numbers()
        } else {
            Vec::new()
        };

        let constraint = if self.peek() == Some(&Token::LParen) {
            self.parse_constraint()
        } else {
            None
        };

        Some(Syntax::Named {
            name,
            constraint,
            enums,
        })
    }

    pub(super) fn parse_sequence_fields(&mut self) -> Vec<SequenceField> {
        let mut fields = Vec::new();
        if !self.eat(&Token::LBrace) {
            return fields;
        }
        loop {
            match self.peek() {
                None => break,
                Some(Token::RBrace) => {
                    self.advance();
                    break;
                }
                Some(Token::Comma) => self.advance(),
                Some(Token::Word(w)) => {
                    let name = w.clone();
                    self.advance();
                    match self.parse_syntax() {
                        Some(syntax) => fields.push(SequenceField { name, syntax }),
                        // One bad field must not cost the rest of the row.
                        None => {
                            if !self.skip_to_next_field() {
                                break;
                            }
                        }
                    }
                }
                Some(_) => self.advance(),
            }
        }
        fields
    }

    pub(super) fn skip_to_next_field(&mut self) -> bool {
        let mut depth = 0usize;
        while let Some(token) = self.peek() {
            match token {
                Token::LBrace | Token::LParen => depth += 1,
                Token::RParen => depth = depth.saturating_sub(1),
                Token::RBrace => {
                    if depth == 0 {
                        self.advance();
                        return false;
                    }
                    depth -= 1;
                }
                Token::Comma if depth == 0 => {
                    self.advance();
                    return true;
                }
                Token::Assign if depth == 0 => return false,
                _ => {}
            }
            self.advance();
        }
        false
    }

    pub(super) fn skip_value(&mut self) {
        if self.peek() == Some(&Token::LBrace) {
            self.skip_braces();
        } else {
            self.advance();
        }
    }

    pub(super) fn parse_named_numbers(&mut self) -> Vec<NamedNumber> {
        let mut out = Vec::new();
        if !self.eat(&Token::LBrace) {
            return out;
        }
        loop {
            match self.peek() {
                None => break,
                Some(Token::RBrace) => {
                    self.advance();
                    break;
                }
                Some(Token::Word(w)) => {
                    let name = w.clone();
                    self.advance();
                    if self.eat(&Token::LParen) {
                        if let Some(Token::Number(n)) = self.peek() {
                            let value = *n;
                            self.advance();
                            out.push(NamedNumber {
                                name,
                                value: value.try_into().unwrap_or(0),
                            });
                        }
                        self.eat(&Token::RParen);
                    }
                }
                Some(_) => self.advance(),
            }
        }
        out
    }

    pub(super) fn parse_constraint(&mut self) -> Option<Constraint> {
        self.advance();
        let mut depth = 1usize;
        let mut is_size = false;
        let mut ranges: Vec<Range> = Vec::new();
        let mut pending: Option<i128> = None;
        let mut in_range = false;

        while depth > 0 {
            match self.peek() {
                None => break,
                Some(Token::LParen) => {
                    depth += 1;
                    self.advance();
                }
                Some(Token::RParen) => {
                    depth -= 1;
                    self.advance();
                }
                Some(Token::Word(w)) if w == "SIZE" => {
                    is_size = true;
                    self.advance();
                }
                Some(Token::Number(n)) => {
                    let n = *n;
                    self.advance();
                    if in_range {
                        in_range = false;
                        if let Some(low) = pending.take() {
                            ranges.push(Range { low, high: n });
                        }
                    } else {
                        if let Some(low) = pending.take() {
                            ranges.push(Range { low, high: low });
                        }
                        pending = Some(n);
                    }
                }
                Some(Token::Range) => {
                    in_range = true;
                    self.advance();
                }
                Some(_) => self.advance(),
            }
        }
        if let Some(low) = pending {
            ranges.push(Range { low, high: low });
        }

        if ranges.is_empty() {
            return None;
        }
        Some(if is_size {
            Constraint::Size(ranges)
        } else {
            Constraint::Range(ranges)
        })
    }

    pub(super) fn skip_braces(&mut self) {
        if !self.eat(&Token::LBrace) {
            return;
        }
        let mut depth = 1usize;
        while let Some(token) = self.peek() {
            match token {
                Token::LBrace => depth += 1,
                Token::RBrace => {
                    depth -= 1;
                    if depth == 0 {
                        self.advance();
                        return;
                    }
                }
                _ => {}
            }
            self.advance();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mib::parser::test_support::{parse_one, wrap};
    use crate::mib::{Constraint, Definition, IndexField, NamedNumber, Range, Syntax, TypeDefKind};

    #[test]
    fn test_parses_enumeration_labels() {
        let m = parse_one(&wrap(
            r#"ifAdminStatus OBJECT-TYPE
                SYNTAX  INTEGER { up(1), down(2), testing(3) }
                MAX-ACCESS read-write
                STATUS current
                ::= { ifEntry 7 }"#,
        ));
        let Definition::Object(o) = &m.definitions[0] else {
            panic!("expected an object")
        };
        let Syntax::Named { enums, .. } = &o.syntax else {
            panic!("expected a named syntax")
        };
        assert_eq!(enums.len(), 3);
        assert_eq!(
            enums[0],
            NamedNumber {
                name: "up".into(),
                value: 1
            }
        );
        assert_eq!(enums[2].name, "testing");
    }

    #[test]
    fn test_parses_size_and_range_constraints() {
        let m = parse_one(&wrap(
            r#"a OBJECT-TYPE SYNTAX DisplayString (SIZE (0..255)) MAX-ACCESS read-only STATUS current ::= { x 1 }
               b OBJECT-TYPE SYNTAX Integer32 (1..2147483647) MAX-ACCESS read-only STATUS current ::= { x 2 }
               c OBJECT-TYPE SYNTAX OCTET STRING (SIZE (0 | 4 | 16)) MAX-ACCESS read-only STATUS current ::= { x 3 }"#,
        ));
        let syntaxes: Vec<&Syntax> = m
            .definitions
            .iter()
            .filter_map(|d| match d {
                Definition::Object(o) => Some(&o.syntax),
                _ => None,
            })
            .collect();

        let Syntax::Named { constraint, .. } = syntaxes[0] else {
            panic!()
        };
        assert_eq!(
            constraint.as_ref(),
            Some(&Constraint::Size(vec![Range { low: 0, high: 255 }]))
        );

        let Syntax::Named { constraint, .. } = syntaxes[1] else {
            panic!()
        };
        assert_eq!(
            constraint.as_ref(),
            Some(&Constraint::Range(vec![Range {
                low: 1,
                high: 2147483647
            }]))
        );

        let Syntax::Named {
            constraint, name, ..
        } = syntaxes[2]
        else {
            panic!()
        };
        assert_eq!(name, "OCTET STRING");
        assert_eq!(
            constraint.as_ref(),
            Some(&Constraint::Size(vec![
                Range { low: 0, high: 0 },
                Range { low: 4, high: 4 },
                Range { low: 16, high: 16 },
            ]))
        );
    }

    #[test]
    fn test_parses_table_row_and_index() {
        let m = parse_one(&wrap(
            r#"ifTable OBJECT-TYPE
                 SYNTAX SEQUENCE OF IfEntry
                 MAX-ACCESS not-accessible
                 STATUS current
                 ::= { interfaces 2 }
               ifEntry OBJECT-TYPE
                 SYNTAX IfEntry
                 MAX-ACCESS not-accessible
                 STATUS current
                 INDEX { ifIndex }
                 ::= { ifTable 1 }
               IfEntry ::= SEQUENCE { ifIndex Integer32, ifDescr DisplayString }"#,
        ));
        let Definition::Object(table) = &m.definitions[0] else {
            panic!()
        };
        assert_eq!(table.syntax, Syntax::SequenceOf("IfEntry".into()));

        let Definition::Object(row) = &m.definitions[1] else {
            panic!()
        };
        assert_eq!(
            row.index,
            vec![IndexField {
                name: "ifIndex".into(),
                implied: false
            }]
        );

        let Definition::Type(ty) = &m.definitions[2] else {
            panic!()
        };
        let TypeDefKind::Alias(Syntax::Sequence(fields)) = &ty.kind else {
            panic!("expected a SEQUENCE alias")
        };
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "ifIndex");
        assert_eq!(fields[1].syntax.type_name(), "DisplayString");
    }

    #[test]
    fn test_a_bad_sequence_field_does_not_leak_the_rest_to_the_top_level() {
        let m = parse_one(&wrap(
            "IfEntry ::= SEQUENCE { ifIndex Integer32, , Counter32, ifDescr DisplayString }\n\
             after OBJECT IDENTIFIER ::= { z 1 }",
        ));
        let Definition::Type(ty) = &m.definitions[0] else {
            panic!("expected the row type")
        };
        let TypeDefKind::Alias(Syntax::Sequence(fields)) = &ty.kind else {
            panic!("expected a SEQUENCE")
        };
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["ifIndex", "ifDescr"]);
        assert_eq!(m.definitions[1].name(), "after");
    }

    #[test]
    fn test_parses_application_tagged_type_assignment() {
        let m = parse_one(&wrap(
            "Counter ::= [APPLICATION 1] IMPLICIT INTEGER (0..4294967295)",
        ));
        let Definition::Type(ty) = &m.definitions[0] else {
            panic!()
        };
        let TypeDefKind::Alias(syntax) = &ty.kind else {
            panic!()
        };
        assert_eq!(syntax.type_name(), "INTEGER");
    }
}
