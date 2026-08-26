mod definitions;
mod syntax;

use super::lexer::{SpannedToken, Token, tokenize};
use super::{Definition, Diagnostic, Import, MibError, MibModule, NodeFlavour};

const CONFORMANCE_MACROS: &[&str] = &[
    "MODULE-COMPLIANCE",
    "OBJECT-GROUP",
    "NOTIFICATION-GROUP",
    "AGENT-CAPABILITIES",
];

// Spots where an IMPORTS list ended when its `;` is missing.
const DEFINITION_MACROS: &[&str] = &[
    "OBJECT-TYPE",
    "MODULE-IDENTITY",
    "OBJECT-IDENTITY",
    "NOTIFICATION-TYPE",
    "TRAP-TYPE",
    "MACRO",
    "MODULE-COMPLIANCE",
    "OBJECT-GROUP",
    "NOTIFICATION-GROUP",
    "AGENT-CAPABILITIES",
];

pub fn parse_modules(source: &str, origin: &str) -> Result<Vec<MibModule>, MibError> {
    let tokens = tokenize(source)?;
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
        module: origin.to_string(),
        diagnostics: Vec::new(),
    };
    Ok(parser.run())
}

struct Parser<'a> {
    tokens: &'a [SpannedToken],
    pos: usize,
    module: String,
    diagnostics: Vec<Diagnostic>,
}

impl Parser<'_> {
    fn run(&mut self) -> Vec<MibModule> {
        let mut modules = Vec::new();
        while let Some(name) = self.find_module_header() {
            self.module = name.clone();
            self.diagnostics.clear();
            let (imports, definitions) = self.parse_body();
            modules.push(MibModule {
                name,
                imports,
                definitions,
                diagnostics: std::mem::take(&mut self.diagnostics),
            });
        }
        modules
    }

    fn token_at(&self, index: usize) -> Option<&Token> {
        self.tokens.get(index).map(|t| &t.token)
    }

    fn peek(&self) -> Option<&Token> {
        self.token_at(self.pos)
    }

    fn peek_word(&self) -> Option<&str> {
        match self.peek() {
            Some(Token::Word(w)) => Some(w.as_str()),
            _ => None,
        }
    }

    fn word_at(&self, index: usize) -> Option<&str> {
        match self.token_at(index) {
            Some(Token::Word(w)) => Some(w.as_str()),
            _ => None,
        }
    }

    fn advance(&mut self) {
        self.pos += 1;
    }

    fn eat(&mut self, token: &Token) -> bool {
        if self.peek() == Some(token) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn eat_word(&mut self, word: &str) -> bool {
        if self.peek_word() == Some(word) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn line(&self) -> usize {
        self.tokens
            .get(self.pos.min(self.tokens.len().saturating_sub(1)))
            .map(|t| t.line)
            .unwrap_or(0)
    }

    fn diagnose(&mut self, line: usize, message: impl Into<String>) {
        let module = self.module.clone();
        self.diagnostics
            .push(Diagnostic::new(module, line, message));
    }

    fn take_text(&mut self) -> Option<String> {
        match self.peek() {
            Some(Token::Text(s)) => {
                let s = s.clone();
                self.advance();
                Some(s)
            }
            // Some vendor MIBs write a bare word where a string belongs.
            Some(Token::Word(w)) => {
                let w = w.clone();
                self.advance();
                Some(w)
            }
            _ => None,
        }
    }

    fn find_module_header(&mut self) -> Option<String> {
        while self.pos < self.tokens.len() {
            if self.word_at(self.pos + 1) == Some("DEFINITIONS") {
                let name = self.word_at(self.pos)?.to_string();
                self.pos += 2;
                while self.pos < self.tokens.len() && self.peek() != Some(&Token::Assign) {
                    self.advance();
                }
                self.eat(&Token::Assign);
                self.eat_word("BEGIN");
                return Some(name);
            }
            self.advance();
        }
        None
    }

    fn parse_body(&mut self) -> (Vec<Import>, Vec<Definition>) {
        let mut imports = Vec::new();
        let mut definitions = Vec::new();

        loop {
            if self.peek().is_none() {
                let line = self.line();
                self.diagnose(line, "module ended without END");
                break;
            }
            match self.peek_word() {
                Some("END") => {
                    self.advance();
                    break;
                }
                Some("IMPORTS") => {
                    self.advance();
                    imports.extend(self.parse_imports());
                }
                Some("EXPORTS") => {
                    while self.peek().is_some() && !self.eat(&Token::Semicolon) {
                        self.advance();
                    }
                }
                Some(_) => {
                    if let Some(def) = self.parse_definition() {
                        definitions.push(def);
                    }
                }
                None => self.advance(),
            }
        }
        (imports, definitions)
    }

    fn parse_imports(&mut self) -> Vec<Import> {
        let mut imports = Vec::new();
        let mut symbols = Vec::new();
        let mut after_from = false;

        loop {
            match self.peek() {
                None => break,
                Some(Token::Semicolon) => {
                    self.advance();
                    break;
                }
                Some(Token::Comma) => self.advance(),
                Some(Token::Word(w)) if w == "FROM" => {
                    self.advance();
                    match self.peek() {
                        Some(Token::Word(module)) => {
                            let module = module.clone();
                            self.advance();
                            imports.push(Import {
                                module,
                                symbols: std::mem::take(&mut symbols),
                            });
                            after_from = true;
                        }
                        _ => {
                            let line = self.line();
                            self.diagnose(line, "IMPORTS: FROM without a module name");
                            symbols.clear();
                        }
                    }
                }
                Some(Token::Word(w)) => {
                    let symbol = w.clone();
                    // DPI20-MIB and friends leave the terminating `;` off.
                    if after_from && self.starts_definition() {
                        break;
                    }
                    symbols.push(symbol);
                    self.advance();
                    after_from = false;
                }
                Some(_) => break,
            }
        }
        imports
    }

    fn starts_definition(&self) -> bool {
        match self.word_at(self.pos + 1) {
            Some("OBJECT") => self.word_at(self.pos + 2) == Some("IDENTIFIER"),
            Some(word) => DEFINITION_MACROS.contains(&word),
            None => self.token_at(self.pos + 1) == Some(&Token::Assign),
        }
    }

    fn parse_definition(&mut self) -> Option<Definition> {
        let line = self.line();
        let name = self.peek_word()?.to_string();
        self.advance();

        if self.eat(&Token::Assign) {
            return self.parse_type_assignment(name, line);
        }

        let keyword = self.peek_word().map(str::to_string).unwrap_or_default();
        let object_identifier =
            keyword == "OBJECT" && self.word_at(self.pos + 1) == Some("IDENTIFIER");

        match keyword.as_str() {
            "MACRO" => {
                self.skip_macro();
                None
            }
            "OBJECT" if object_identifier => {
                self.pos += 2;
                self.parse_oid_node(name, NodeFlavour::ObjectIdentifier, line)
            }
            "OBJECT-TYPE" => {
                self.advance();
                self.parse_object_type(name, line)
            }
            "MODULE-IDENTITY" => {
                self.advance();
                self.parse_oid_node(name, NodeFlavour::ModuleIdentity, line)
            }
            "OBJECT-IDENTITY" => {
                self.advance();
                self.parse_oid_node(name, NodeFlavour::ObjectIdentity, line)
            }
            "NOTIFICATION-TYPE" | "TRAP-TYPE" => {
                let is_v1_trap = keyword == "TRAP-TYPE";
                self.advance();
                self.parse_notification(name, line, is_v1_trap)
            }
            other if CONFORMANCE_MACROS.contains(&other) => {
                self.advance();
                self.skip_to_assignment();
                self.parse_oid_value();
                None
            }
            // ASN.1 value assignment, e.g. SNMPv2-PDU's `max-bindings INTEGER ::= ...`
            _ if self.token_at(self.pos + 1) == Some(&Token::Assign) => {
                self.pos += 2;
                self.skip_value();
                None
            }
            _ => {
                self.diagnose(line, format!("unrecognised definition: {name}"));
                self.recover();
                None
            }
        }
    }

    // Macro bodies are grammar, not data.
    fn skip_macro(&mut self) {
        self.advance();
        self.eat(&Token::Assign);
        let mut depth = 0usize;
        while let Some(token) = self.peek() {
            match token {
                Token::Word(w) if w == "BEGIN" => depth += 1,
                Token::Word(w) if w == "END" => {
                    self.advance();
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return;
                    }
                    continue;
                }
                _ => {}
            }
            self.advance();
        }
    }

    fn skip_to_assignment(&mut self) -> bool {
        let mut depth = 0usize;
        while let Some(token) = self.peek() {
            match token {
                Token::LBrace | Token::LParen => depth += 1,
                Token::RBrace | Token::RParen => depth = depth.saturating_sub(1),
                Token::Word(w) if w == "END" && depth == 0 => return false,
                Token::Assign if depth == 0 => {
                    self.advance();
                    return true;
                }
                _ => {}
            }
            self.advance();
        }
        false
    }

    fn recover(&mut self) {
        if self.skip_to_assignment() {
            self.parse_oid_value();
        }
    }
}

// RFC 2578 §7.1.3: sub-identifiers are 32-bit unsigned.
fn clamp_subid(n: i128) -> u32 {
    n.try_into().unwrap_or(0)
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;

    pub(crate) fn parse_one(src: &str) -> MibModule {
        let mut modules = parse_modules(src, "test").expect("lexes");
        assert_eq!(modules.len(), 1, "expected exactly one module");
        modules.remove(0)
    }

    pub(crate) fn wrap(body: &str) -> String {
        format!("TEST-MIB DEFINITIONS ::= BEGIN\n{body}\nEND\n")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{parse_one, wrap};
    use super::*;

    #[test]
    fn test_parses_module_name_and_imports() {
        let m = parse_one(&wrap(
            "IMPORTS\n  OBJECT-TYPE, mib-2 FROM SNMPv2-SMI\n  DisplayString FROM SNMPv2-TC;",
        ));
        assert_eq!(m.name, "TEST-MIB");
        assert_eq!(m.imports.len(), 2);
        assert_eq!(m.imports[0].module, "SNMPv2-SMI");
        assert_eq!(m.imports[0].symbols, vec!["OBJECT-TYPE", "mib-2"]);
        assert_eq!(m.imports[1].symbols, vec!["DisplayString"]);
    }

    #[test]
    fn test_skips_macro_definitions() {
        let m = parse_one(&wrap(
            "OBJECT-TYPE MACRO ::= BEGIN\n  TYPE NOTATION ::= \"SYNTAX\" type\nEND\n\
             x OBJECT IDENTIFIER ::= { y 1 }",
        ));
        assert_eq!(m.definitions.len(), 1);
        assert_eq!(m.definitions[0].name(), "x");
    }

    #[test]
    fn test_discards_conformance_macros() {
        let m = parse_one(&wrap(
            r#"ifGroup OBJECT-GROUP
                 OBJECTS { ifIndex, ifDescr }
                 STATUS current
                 DESCRIPTION "The interface group."
                 ::= { ifGroups 1 }
               after OBJECT IDENTIFIER ::= { z 9 }"#,
        ));
        assert_eq!(m.definitions.len(), 1);
        assert_eq!(m.definitions[0].name(), "after");
    }

    #[test]
    fn test_bad_definition_is_skipped_with_a_diagnostic() {
        let m = parse_one(&wrap(
            r#"broken WIDGET-TYPE
                 NONSENSE here
                 ::= { x 1 }
               good OBJECT IDENTIFIER ::= { x 2 }"#,
        ));
        assert_eq!(m.definitions.len(), 1);
        assert_eq!(m.definitions[0].name(), "good");
        assert_eq!(m.diagnostics.len(), 1);
        assert!(m.diagnostics[0].message.contains("broken"));
    }

    #[test]
    fn test_parses_several_modules_from_one_file() {
        let second = "OTHER-MIB DEFINITIONS ::= BEGIN\nb OBJECT IDENTIFIER ::= { y 2 }\nEND\n";
        let src = wrap("a OBJECT IDENTIFIER ::= { x 1 }") + second;
        let modules = parse_modules(&src, "test").unwrap();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name, "TEST-MIB");
        assert_eq!(modules[1].name, "OTHER-MIB");
    }

    #[test]
    fn test_handles_implicit_tags_header() {
        let m = parse_one("TEST-MIB DEFINITIONS IMPLICIT TAGS ::= BEGIN\nEND\n");
        assert_eq!(m.name, "TEST-MIB");
    }

    #[test]
    fn test_imports_without_a_terminating_semicolon() {
        let m = parse_one(&wrap(
            "IMPORTS\n  OBJECT-TYPE, enterprises FROM SNMPv2-SMI\n\n\
             ibm OBJECT IDENTIFIER ::= { enterprises 2 }\n\
             ibmDPI OBJECT IDENTIFIER ::= { ibm 2 }",
        ));
        assert_eq!(m.imports.len(), 1);
        assert_eq!(m.imports[0].symbols, vec!["OBJECT-TYPE", "enterprises"]);
        let names: Vec<&str> = m.definitions.iter().map(|d| d.name()).collect();
        assert_eq!(names, vec!["ibm", "ibmDPI"]);
        assert!(m.diagnostics.is_empty(), "{:?}", m.diagnostics);
    }

    #[test]
    fn test_multi_group_imports_still_end_at_the_semicolon() {
        let m = parse_one(&wrap(
            "IMPORTS\n  OBJECT-TYPE FROM SNMPv2-SMI\n  DisplayString FROM SNMPv2-TC\n\
             \x20 snmpTraps FROM SNMPv2-MIB;\nx OBJECT IDENTIFIER ::= { y 1 }",
        ));
        assert_eq!(m.imports.len(), 3);
        assert_eq!(m.imports[2].symbols, vec!["snmpTraps"]);
        assert_eq!(m.definitions.len(), 1);
    }

    #[test]
    fn test_asn1_value_assignments_are_skipped_quietly() {
        let m = parse_one(&wrap(
            "max-bindings INTEGER ::= 2147483647\nx OBJECT IDENTIFIER ::= { y 1 }",
        ));
        assert_eq!(m.definitions.len(), 1);
        assert_eq!(m.definitions[0].name(), "x");
        assert!(m.diagnostics.is_empty(), "{:?}", m.diagnostics);
    }
}
