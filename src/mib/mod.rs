pub mod bindings;
mod display;
mod lexer;
mod parser;
mod resolver;

pub use display::{format_integer, format_octets};
pub use lexer::{Token, tokenize};
pub use parser::parse_modules;
pub use resolver::{MibNode, NodeKind, Registry, ResolvedSyntax};

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub module: String,
    pub line: usize,
    pub message: String,
}

impl Diagnostic {
    pub fn new(module: impl Into<String>, line: usize, message: impl Into<String>) -> Self {
        Self {
            module: module.into(),
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.module, self.line, self.message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MibError {
    Lex { line: usize, message: String },
    NoModule,
    Io(String),
}

impl fmt::Display for MibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MibError::Lex { line, message } => write!(f, "line {line}: {message}"),
            MibError::NoModule => write!(f, "no MIB module definition found"),
            MibError::Io(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for MibError {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MibModule {
    pub name: String,
    pub imports: Vec<Import>,
    pub definitions: Vec<Definition>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub module: String,
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Definition {
    Node(NodeDef),
    Object(Box<ObjectDef>),
    Notification(NotificationDef),
    Type(TypeDef),
}

impl Definition {
    pub fn name(&self) -> &str {
        match self {
            Definition::Node(d) => &d.name,
            Definition::Object(d) => &d.name,
            Definition::Notification(d) => &d.name,
            Definition::Type(d) => &d.name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeFlavour {
    ObjectIdentifier,
    ModuleIdentity,
    ObjectIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDef {
    pub name: String,
    pub flavour: NodeFlavour,
    pub oid: OidExpr,
    pub status: Option<Status>,
    pub description: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDef {
    pub name: String,
    pub syntax: Syntax,
    pub max_access: Access,
    pub status: Status,
    pub description: Option<String>,
    pub reference: Option<String>,
    pub units: Option<String>,
    pub index: Vec<IndexField>,
    pub augments: Option<String>,
    pub defval: Option<String>,
    pub oid: OidExpr,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexField {
    pub name: String,
    // RFC 2578 §7.7: `IMPLIED` on the last index means it is not length-prefixed.
    pub implied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationDef {
    pub name: String,
    pub objects: Vec<String>,
    pub status: Option<Status>,
    pub description: Option<String>,
    pub oid: OidExpr,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeDef {
    pub name: String,
    pub kind: TypeDefKind,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeDefKind {
    TextualConvention {
        display_hint: Option<String>,
        status: Option<Status>,
        description: Option<String>,
        syntax: Syntax,
    },
    Alias(Syntax),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Syntax {
    Named {
        name: String,
        constraint: Option<Constraint>,
        enums: Vec<NamedNumber>,
    },
    // Marks a conceptual table.
    SequenceOf(String),
    Sequence(Vec<SequenceField>),
}

impl Syntax {
    pub fn type_name(&self) -> &str {
        match self {
            Syntax::Named { name, .. } => name,
            Syntax::SequenceOf(row) => row,
            Syntax::Sequence(_) => "SEQUENCE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceField {
    pub name: String,
    pub syntax: Syntax,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedNumber {
    pub name: String,
    pub value: i64,
}

// Bounds are i128: Counter64's range does not fit in i64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    Size(Vec<Range>),
    Range(Vec<Range>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub low: i128,
    pub high: i128,
}

// RFC 2578 §7.3, plus SMIv1's ACCESS values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Access {
    #[default]
    NotAccessible,
    AccessibleForNotify,
    ReadOnly,
    ReadWrite,
    ReadCreate,
    // SMIv1 only; RFC 2578 §7.3 dropped it.
    WriteOnly,
}

impl Access {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "not-accessible" => Access::NotAccessible,
            "accessible-for-notify" => Access::AccessibleForNotify,
            "read-only" => Access::ReadOnly,
            "read-write" => Access::ReadWrite,
            "read-create" => Access::ReadCreate,
            "write-only" => Access::WriteOnly,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Access::NotAccessible => "not-accessible",
            Access::AccessibleForNotify => "accessible-for-notify",
            Access::ReadOnly => "read-only",
            Access::ReadWrite => "read-write",
            Access::ReadCreate => "read-create",
            Access::WriteOnly => "write-only",
        }
    }

    pub fn is_readable(self) -> bool {
        matches!(
            self,
            Access::ReadOnly | Access::ReadWrite | Access::ReadCreate
        )
    }

    pub fn is_writable(self) -> bool {
        matches!(
            self,
            Access::ReadWrite | Access::ReadCreate | Access::WriteOnly
        )
    }
}

// RFC 2578 §7.4, plus SMIv1's mandatory/optional
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    Current,
    Deprecated,
    Obsolete,
    Mandatory,
    Optional,
}

impl Status {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "current" => Status::Current,
            "deprecated" => Status::Deprecated,
            "obsolete" => Status::Obsolete,
            "mandatory" => Status::Mandatory,
            "optional" => Status::Optional,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Current => "current",
            Status::Deprecated => "deprecated",
            Status::Obsolete => "obsolete",
            Status::Mandatory => "mandatory",
            Status::Optional => "optional",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OidExpr {
    pub components: Vec<OidComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidComponent {
    Number(u32),
    Name(String),
    // `dod(6)`
    NamedNumber(String, u32),
}

// RFC 2578 §7.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseType {
    Integer32,
    OctetString,
    ObjectIdentifier,
    IpAddress,
    Counter32,
    Gauge32,
    Unsigned32,
    TimeTicks,
    Opaque,
    Counter64,
    Bits,
    Null,
}

impl BaseType {
    // SMIv1 spellings, so old vendor MIBs resolve without RFC1155-SMI loaded.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "INTEGER" | "Integer32" => BaseType::Integer32,
            "OCTET STRING" => BaseType::OctetString,
            "OBJECT IDENTIFIER" => BaseType::ObjectIdentifier,
            "IpAddress" | "NetworkAddress" => BaseType::IpAddress,
            "Counter32" | "Counter" => BaseType::Counter32,
            "Gauge32" | "Gauge" => BaseType::Gauge32,
            "Unsigned32" => BaseType::Unsigned32,
            "TimeTicks" => BaseType::TimeTicks,
            "Opaque" => BaseType::Opaque,
            "Counter64" => BaseType::Counter64,
            "BITS" => BaseType::Bits,
            "NULL" => BaseType::Null,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BaseType::Integer32 => "Integer32",
            BaseType::OctetString => "OCTET STRING",
            BaseType::ObjectIdentifier => "OBJECT IDENTIFIER",
            BaseType::IpAddress => "IpAddress",
            BaseType::Counter32 => "Counter32",
            BaseType::Gauge32 => "Gauge32",
            BaseType::Unsigned32 => "Unsigned32",
            BaseType::TimeTicks => "TimeTicks",
            BaseType::Opaque => "Opaque",
            BaseType::Counter64 => "Counter64",
            BaseType::Bits => "BITS",
            BaseType::Null => "NULL",
        }
    }

    pub fn is_string_like(self) -> bool {
        matches!(
            self,
            BaseType::OctetString | BaseType::Opaque | BaseType::Bits
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_roundtrip() {
        for a in [
            Access::NotAccessible,
            Access::AccessibleForNotify,
            Access::ReadOnly,
            Access::ReadWrite,
            Access::ReadCreate,
            Access::WriteOnly,
        ] {
            assert_eq!(Access::parse(a.as_str()), Some(a));
        }
        assert_eq!(Access::parse("nonsense"), None);
    }

    #[test]
    fn test_status_roundtrip() {
        for s in [
            Status::Current,
            Status::Deprecated,
            Status::Obsolete,
            Status::Mandatory,
            Status::Optional,
        ] {
            assert_eq!(Status::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn test_smiv1_type_names_are_builtins() {
        assert_eq!(BaseType::parse("Counter"), Some(BaseType::Counter32));
        assert_eq!(BaseType::parse("Gauge"), Some(BaseType::Gauge32));
        assert_eq!(BaseType::parse("NetworkAddress"), Some(BaseType::IpAddress));
        assert_eq!(BaseType::parse("DisplayString"), None);
    }
}
