use std::sync::Arc;

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use crate::mib::BaseType;
use crate::mib::display::{format_integer, format_octets};
use crate::mib::resolver::{MibNode, NodeKind, Registry};
use crate::types::Value;

/// One object in the MIB tree.
#[pyclass(name = "MibNode")]
pub struct PyMibNode {
    registry: Arc<Registry>,
    index: usize,
}

impl PyMibNode {
    pub(super) fn new(registry: Arc<Registry>, index: usize) -> Self {
        Self { registry, index }
    }

    fn node(&self) -> &MibNode {
        // The index came from this registry and neither is ever mutated.
        &self.registry.nodes()[self.index]
    }

    fn wrap(&self, index: usize) -> PyMibNode {
        PyMibNode {
            registry: Arc::clone(&self.registry),
            index,
        }
    }
}

#[pymethods]
impl PyMibNode {
    #[getter]
    fn name(&self) -> String {
        self.node().name.clone()
    }

    #[getter]
    fn module(&self) -> String {
        self.node().module.clone()
    }

    #[getter]
    fn oid(&self) -> String {
        self.node().oid.to_string()
    }

    #[getter]
    fn numeric_oid(&self) -> Vec<u32> {
        self.node().oid.parts().to_vec()
    }

    /// One of `node`, `scalar`, `table`, `row`, `column`, `notification`.
    #[getter]
    fn kind(&self) -> &'static str {
        self.node().kind.as_str()
    }

    /// The type as the MIB wrote it, e.g. `InterfaceIndex`.
    #[getter]
    fn syntax(&self) -> Option<String> {
        Some(self.node().syntax.as_ref()?.declared.clone())
    }

    /// The type the syntax resolves to after following textual conventions.
    #[getter]
    fn base_type(&self) -> Option<&'static str> {
        Some(self.node().base_type()?.as_str())
    }

    #[getter]
    fn max_access(&self) -> Option<&'static str> {
        Some(self.node().max_access?.as_str())
    }

    #[getter]
    fn status(&self) -> Option<&'static str> {
        Some(self.node().status?.as_str())
    }

    #[getter]
    fn description(&self) -> Option<String> {
        self.node().description.clone()
    }

    #[getter]
    fn reference(&self) -> Option<String> {
        self.node().reference.clone()
    }

    #[getter]
    fn units(&self) -> Option<String> {
        self.node().units.clone()
    }

    #[getter]
    fn defval(&self) -> Option<String> {
        self.node().defval.clone()
    }

    #[getter]
    fn display_hint(&self) -> Option<String> {
        self.node().display_hint().map(str::to_string)
    }

    /// Enumeration labels as `{label: value}`, or None.
    #[getter]
    fn enums<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        let enums = self.node().enums();
        if enums.is_empty() {
            return Ok(None);
        }
        let dict = PyDict::new(py);
        for entry in enums {
            dict.set_item(&entry.name, entry.value)?;
        }
        Ok(Some(dict))
    }

    /// On a conceptual row, the column names that form the instance identifier.
    #[getter]
    fn index(&self) -> Vec<String> {
        self.node().index.iter().map(|f| f.name.clone()).collect()
    }

    /// RFC 2578 §7.7: whether the last index column is `IMPLIED`.
    #[getter]
    fn implied(&self) -> bool {
        self.node().index.last().is_some_and(|f| f.implied)
    }

    #[getter]
    fn augments(&self) -> Option<String> {
        self.node().augments.clone()
    }

    /// On a table, the name of its row type, e.g. `IfEntry`.
    #[getter]
    fn row_type(&self) -> Option<String> {
        self.node().row_type.clone()
    }

    /// On a notification, the objects it carries.
    #[getter]
    fn objects(&self) -> Vec<String> {
        self.node().objects.clone()
    }

    #[getter]
    fn is_table(&self) -> bool {
        self.node().kind == NodeKind::Table
    }

    #[getter]
    fn is_row(&self) -> bool {
        self.node().kind == NodeKind::Row
    }

    #[getter]
    fn is_column(&self) -> bool {
        self.node().kind == NodeKind::Column
    }

    #[getter]
    fn is_scalar(&self) -> bool {
        self.node().kind == NodeKind::Scalar
    }

    #[getter]
    fn parent(&self) -> Option<PyMibNode> {
        Some(self.wrap(self.node().parent?))
    }

    #[getter]
    fn children(&self) -> Vec<PyMibNode> {
        self.node()
            .children
            .iter()
            .map(|index| self.wrap(*index))
            .collect()
    }

    /// The columns of a table or of a row. Empty for anything else.
    #[getter]
    fn columns(&self) -> Vec<PyMibNode> {
        let node = self.node();
        let row = match node.kind {
            // A row's own children are its columns.
            NodeKind::Row => self.index,
            // A table has exactly one child, the row.
            NodeKind::Table => match node.children.first() {
                Some(row) => *row,
                None => return Vec::new(),
            },
            _ => return Vec::new(),
        };
        self.registry.nodes()[row]
            .children
            .iter()
            .map(|index| self.wrap(*index))
            .collect()
    }

    /// The label for an enumerated value.
    fn enum_name(&self, value: i64) -> Option<String> {
        self.node()
            .enums()
            .iter()
            .find(|e| e.value == value)
            .map(|e| e.name.clone())
    }

    /// The value behind an enumeration label.
    fn enum_value(&self, name: &str) -> Option<i64> {
        self.node()
            .enums()
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.value)
    }

    /// Renders an int, bytes, str or Value per RFC 2579 §3.1.
    fn format(&self, value: &Bound<'_, PyAny>) -> PyResult<String> {
        match Scalar::extract(value)? {
            Scalar::Int(v) => Ok(self.format_int(v)),
            Scalar::Bytes(v) => Ok(self.format_bytes(&v)),
            Scalar::Text(v) => Ok(v),
        }
    }

    fn __repr__(&self) -> String {
        let node = self.node();
        format!("MibNode({}::{}, {})", node.module, node.name, node.oid)
    }

    fn __str__(&self) -> String {
        let node = self.node();
        if node.module.is_empty() {
            node.name.clone()
        } else {
            format!("{}::{}", node.module, node.name)
        }
    }
}

impl PyMibNode {
    fn format_int(&self, value: i64) -> String {
        if let Some(label) = self.enum_name(value) {
            return label;
        }
        self.node()
            .display_hint()
            .and_then(|hint| format_integer(hint, value))
            .unwrap_or_else(|| value.to_string())
    }

    fn format_bytes(&self, octets: &[u8]) -> String {
        if self.node().base_type() == Some(BaseType::Bits) {
            let labels = bit_labels(self.node(), octets);
            if !labels.is_empty() {
                return labels.join(" ");
            }
        }
        if let Some(rendered) = self
            .node()
            .display_hint()
            .and_then(|hint| format_octets(hint, octets))
        {
            return rendered;
        }
        // No hint: printable text as-is, anything else as hex.
        if octets.iter().all(|b| !b.is_ascii_control()) {
            String::from_utf8_lossy(octets).into_owned()
        } else {
            octets
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        }
    }
}

// RFC 2578 §7.1.4: bit zero is the MSB of the first octet.
fn bit_labels(node: &MibNode, octets: &[u8]) -> Vec<String> {
    node.enums()
        .iter()
        .filter(|entry| {
            let bit = entry.value;
            if bit < 0 {
                return false;
            }
            let (byte, offset) = ((bit / 8) as usize, (bit % 8) as u32);
            octets
                .get(byte)
                .is_some_and(|b| b & (0x80u8 >> offset) != 0)
        })
        .map(|entry| entry.name.clone())
        .collect()
}

// The shapes MibNode.format knows how to render.
enum Scalar {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
}

impl Scalar {
    fn extract(value: &Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(bytes) = value.cast::<PyBytes>() {
            return Ok(Scalar::Bytes(bytes.as_bytes().to_vec()));
        }
        if let Ok(text) = value.extract::<String>() {
            return Ok(Scalar::Bytes(text.into_bytes()));
        }
        if let Ok(v) = value.extract::<i64>() {
            return Ok(Scalar::Int(v));
        }
        if let Ok(v) = value.extract::<Value>() {
            return Ok(Self::from_value(v));
        }
        Err(PyTypeError::new_err(
            "expected an int, bytes, str or snmpkit.core.Value",
        ))
    }

    fn from_value(value: Value) -> Self {
        match value {
            Value::Integer(v) => Scalar::Int(i64::from(v)),
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => {
                Scalar::Int(i64::from(v))
            }
            Value::Counter64(v) => Scalar::Int(v as i64),
            Value::OctetString(v) | Value::Opaque(v) => Scalar::Bytes(v),
            Value::ObjectIdentifier(o) => Scalar::Text(o.to_string()),
            Value::IpAddress(a, b, c, d) => Scalar::Text(format!("{a}.{b}.{c}.{d}")),
            other => Scalar::Text(other.type_name().to_string()),
        }
    }
}
