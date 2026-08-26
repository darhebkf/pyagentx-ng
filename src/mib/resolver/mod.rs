mod build;

use std::collections::HashMap;

use super::{Access, BaseType, Constraint, Diagnostic, IndexField, MibModule, NamedNumber, Status};
use crate::oid::Oid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Node,
    Scalar,
    Table,
    Row,
    Column,
    Notification,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::Node => "node",
            NodeKind::Scalar => "scalar",
            NodeKind::Table => "table",
            NodeKind::Row => "row",
            NodeKind::Column => "column",
            NodeKind::Notification => "notification",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSyntax {
    pub declared: String,
    pub base: Option<BaseType>,
    pub display_hint: Option<String>,
    pub enums: Vec<NamedNumber>,
    pub constraint: Option<Constraint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MibNode {
    pub name: String,
    pub module: String,
    pub oid: Oid,
    pub kind: NodeKind,
    pub syntax: Option<ResolvedSyntax>,
    pub max_access: Option<Access>,
    pub status: Option<Status>,
    pub description: Option<String>,
    pub reference: Option<String>,
    pub units: Option<String>,
    pub defval: Option<String>,
    pub index: Vec<IndexField>,
    pub augments: Option<String>,
    pub row_type: Option<String>,
    pub objects: Vec<String>,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
}

impl MibNode {
    pub fn base_type(&self) -> Option<BaseType> {
        self.syntax.as_ref().and_then(|s| s.base)
    }

    pub fn display_hint(&self) -> Option<&str> {
        self.syntax.as_ref()?.display_hint.as_deref()
    }

    pub fn enums(&self) -> &[NamedNumber] {
        self.syntax
            .as_ref()
            .map(|s| s.enums.as_slice())
            .unwrap_or(&[])
    }
}

#[derive(Debug, Clone, Default)]
pub struct Registry {
    nodes: Vec<MibNode>,
    by_name: HashMap<String, usize>,
    by_oid: HashMap<Vec<u32>, usize>,
    roots: Vec<usize>,
    module_names: Vec<String>,
    diagnostics: Vec<Diagnostic>,
}

impl Registry {
    pub fn build(modules: &[MibModule]) -> Self {
        build::Builder::new(modules).run()
    }

    pub fn nodes(&self) -> &[MibNode] {
        &self.nodes
    }

    pub fn node(&self, index: usize) -> Option<&MibNode> {
        self.nodes.get(index)
    }

    pub fn roots(&self) -> &[usize] {
        &self.roots
    }

    pub fn module_names(&self) -> &[String] {
        &self.module_names
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn index_of_name(&self, name: &str) -> Option<usize> {
        self.by_name.get(name).copied()
    }

    pub fn lookup(&self, key: &str) -> Option<&MibNode> {
        self.index_of(key).map(|i| &self.nodes[i])
    }

    pub fn index_of(&self, key: &str) -> Option<usize> {
        let key = key.trim();
        let bare = key.rsplit("::").next().unwrap_or(key);
        if let Some(i) = self.by_name.get(bare) {
            return Some(*i);
        }
        let oid: Oid = key.parse().ok()?;
        self.by_oid.get(oid.parts()).copied()
    }

    pub fn nearest(&self, oid: &Oid) -> Option<(&MibNode, Vec<u32>)> {
        let parts = oid.parts();
        let index = self.nearest_index(oid)?;
        let depth = self.nodes[index].oid.parts().len();
        Some((&self.nodes[index], parts[depth..].to_vec()))
    }

    pub fn nearest_index(&self, oid: &Oid) -> Option<usize> {
        let parts = oid.parts();
        for cut in (1..=parts.len()).rev() {
            if let Some(&i) = self.by_oid.get(&parts[..cut]) {
                return Some(i);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mib::parse_modules;

    fn registry(src: &str) -> Registry {
        let modules = parse_modules(src, "test").expect("lexes");
        Registry::build(&modules)
    }

    const SMI: &str = r#"
SNMPv2-SMI DEFINITIONS ::= BEGIN
org OBJECT IDENTIFIER ::= { iso 3 }
dod OBJECT IDENTIFIER ::= { org 6 }
internet OBJECT IDENTIFIER ::= { dod 1 }
mgmt OBJECT IDENTIFIER ::= { internet 2 }
mib-2 OBJECT IDENTIFIER ::= { mgmt 1 }
END
"#;

    #[test]
    fn test_resolves_the_path_to_mib_2() {
        let reg = registry(SMI);
        assert_eq!(reg.lookup("mib-2").unwrap().oid.to_string(), "1.3.6.1.2.1");
        assert_eq!(reg.lookup("iso").unwrap().oid.to_string(), "1");
    }

    #[test]
    fn test_looks_up_by_oid_and_by_module_qualified_name() {
        let reg = registry(SMI);
        assert_eq!(reg.lookup("1.3.6.1.2.1").unwrap().name, "mib-2");
        assert_eq!(reg.lookup(".1.3.6.1.2.1").unwrap().name, "mib-2");
        assert_eq!(reg.lookup("SNMPv2-SMI::mib-2").unwrap().name, "mib-2");
    }

    #[test]
    fn test_resolves_named_number_components() {
        let reg = registry(
            "T DEFINITIONS ::= BEGIN\ninternet OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 }\nEND",
        );
        assert_eq!(reg.lookup("internet").unwrap().oid.to_string(), "1.3.6.1");
    }

    #[test]
    fn test_unknown_parent_is_diagnosed_not_fatal() {
        let reg = registry(
            "T DEFINITIONS ::= BEGIN\n\
             a OBJECT IDENTIFIER ::= { nowhere 1 }\n\
             b OBJECT IDENTIFIER ::= { iso 9 }\n\
             END",
        );
        assert!(reg.lookup("a").is_none());
        assert_eq!(reg.lookup("b").unwrap().oid.to_string(), "1.9");
        assert!(
            reg.diagnostics()
                .iter()
                .any(|d| d.message.contains("nowhere"))
        );
    }

    #[test]
    fn test_circular_oid_definitions_terminate() {
        let reg = registry(
            "T DEFINITIONS ::= BEGIN\n\
             a OBJECT IDENTIFIER ::= { b 1 }\n\
             b OBJECT IDENTIFIER ::= { a 1 }\n\
             END",
        );
        assert!(reg.lookup("a").is_none());
        assert!(reg.lookup("b").is_none());
    }

    #[test]
    fn test_nearest_splits_an_instance_suffix() {
        let reg = registry(SMI);
        let oid: Oid = "1.3.6.1.2.1.99.4".parse().unwrap();
        let (node, suffix) = reg.nearest(&oid).unwrap();
        assert_eq!(node.name, "mib-2");
        assert_eq!(suffix, vec![99, 4]);
    }
}
