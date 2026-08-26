mod node;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use pyo3::exceptions::{PyKeyError, PyValueError};
use pyo3::prelude::*;

use super::MibModule;
use super::parser::parse_modules;
use super::resolver::Registry;
use crate::oid::Oid;

pub use node::PyMibNode;

/// A set of loaded MIB modules, resolved into one browsable OID tree.
#[pyclass(name = "MibTree")]
pub struct PyMibTree {
    modules: Vec<MibModule>,
    // Built on first query, dropped when more modules are loaded.
    registry: Option<Arc<Registry>>,
    load_errors: Vec<String>,
}

impl PyMibTree {
    fn registry(&mut self) -> Arc<Registry> {
        match &self.registry {
            Some(registry) => Arc::clone(registry),
            None => {
                let registry = Arc::new(Registry::build(&self.modules));
                self.registry = Some(Arc::clone(&registry));
                registry
            }
        }
    }

    fn take(&mut self, parsed: Vec<MibModule>) -> usize {
        self.registry = None;
        let count = parsed.len();
        self.modules.extend(parsed);
        count
    }

    fn load_path(&mut self, path: &Path) -> usize {
        let Ok(bytes) = fs::read(path) else {
            self.load_errors
                .push(format!("{}: cannot read", path.display()));
            return 0;
        };
        // Vendor MIBs are frequently Latin-1 rather than UTF-8.
        let text = String::from_utf8_lossy(&bytes);
        if !text.contains("DEFINITIONS") {
            return 0;
        }
        match parse_modules(&text, &path.display().to_string()) {
            Ok(parsed) => self.take(parsed),
            Err(e) => {
                self.load_errors.push(format!("{}: {e}", path.display()));
                0
            }
        }
    }

    fn load_tree(&mut self, dir: &Path, recursive: bool) -> usize {
        let Ok(entries) = fs::read_dir(dir) else {
            self.load_errors
                .push(format!("{}: cannot list directory", dir.display()));
            return 0;
        };
        // Sorted so that a duplicate symbol always resolves the same way.
        let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();

        let mut count = 0;
        for path in paths {
            if path.is_dir() {
                if recursive {
                    count += self.load_tree(&path, true);
                }
            } else {
                count += self.load_path(&path);
            }
        }
        count
    }
}

#[pymethods]
impl PyMibTree {
    #[new]
    fn new() -> Self {
        Self {
            modules: Vec::new(),
            registry: None,
            load_errors: Vec::new(),
        }
    }

    /// Parses one file. Returns the number of modules it contained.
    fn load_file(&mut self, path: &str) -> PyResult<usize> {
        let path = Path::new(path);
        if !path.is_file() {
            return Err(PyValueError::new_err(format!(
                "{}: not a file",
                path.display()
            )));
        }
        Ok(self.load_path(path))
    }

    /// Parses every MIB under a directory. Files that are not MIBs are skipped.
    #[pyo3(signature = (path, recursive = true))]
    fn load_dir(&mut self, path: &str, recursive: bool) -> PyResult<usize> {
        let dir = Path::new(path);
        if !dir.is_dir() {
            return Err(PyValueError::new_err(format!(
                "{}: not a directory",
                dir.display()
            )));
        }
        Ok(self.load_tree(dir, recursive))
    }

    /// Parses MIB text that is already in memory.
    #[pyo3(signature = (text, origin = "<string>"))]
    fn load_str(&mut self, text: &str, origin: &str) -> PyResult<usize> {
        let parsed =
            parse_modules(text, origin).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(self.take(parsed))
    }

    /// Finds a node by name, `MODULE::name`, or numeric OID.
    fn lookup(&mut self, key: &str) -> Option<PyMibNode> {
        let registry = self.registry();
        let index = registry.index_of(key)?;
        Some(PyMibNode::new(registry, index))
    }

    /// Names a numeric OID, keeping any instance suffix: `IF-MIB::ifDescr.1`.
    fn translate(&mut self, oid: &str) -> Option<String> {
        let registry = self.registry();
        let oid: Oid = oid.parse().ok()?;
        let (node, suffix) = registry.nearest(&oid)?;
        let mut out = if node.module.is_empty() {
            node.name.clone()
        } else {
            format!("{}::{}", node.module, node.name)
        };
        for part in suffix {
            out.push('.');
            out.push_str(&part.to_string());
        }
        Some(out)
    }

    /// The deepest node at or above an OID, ignoring any instance suffix.
    fn nearest(&mut self, oid: &str) -> Option<PyMibNode> {
        let registry = self.registry();
        let oid: Oid = oid.parse().ok()?;
        let index = registry.nearest_index(&oid)?;
        Some(PyMibNode::new(registry, index))
    }

    /// The direct children of a node, in OID order.
    fn children(&mut self, key: &str) -> PyResult<Vec<PyMibNode>> {
        let registry = self.registry();
        let index = registry
            .index_of(key)
            .ok_or_else(|| PyKeyError::new_err(key.to_string()))?;
        let children = registry
            .node(index)
            .map(|n| n.children.clone())
            .unwrap_or_default();
        Ok(children
            .into_iter()
            .map(|index| PyMibNode::new(Arc::clone(&registry), index))
            .collect())
    }

    /// Every node at or below `key`, depth-first in OID order; all if omitted.
    #[pyo3(signature = (key = None))]
    fn walk(&mut self, key: Option<&str>) -> PyResult<Vec<PyMibNode>> {
        let registry = self.registry();
        let start: Vec<usize> = match key {
            Some(key) => vec![
                registry
                    .index_of(key)
                    .ok_or_else(|| PyKeyError::new_err(key.to_string()))?,
            ],
            None => registry.roots().to_vec(),
        };

        let mut out = Vec::new();
        let mut stack: Vec<usize> = start.into_iter().rev().collect();
        while let Some(index) = stack.pop() {
            out.push(PyMibNode::new(Arc::clone(&registry), index));
            if let Some(node) = registry.node(index) {
                stack.extend(node.children.iter().rev());
            }
        }
        Ok(out)
    }

    /// The top of the tree — normally just `iso`.
    #[getter]
    fn roots(&mut self) -> Vec<PyMibNode> {
        let registry = self.registry();
        registry
            .roots()
            .iter()
            .map(|index| PyMibNode::new(Arc::clone(&registry), *index))
            .collect()
    }

    #[getter]
    fn modules(&mut self) -> Vec<String> {
        self.registry().module_names().to_vec()
    }

    /// Problems found while loading; a non-empty list is normal.
    #[getter]
    fn diagnostics(&mut self) -> Vec<String> {
        let mut out = self.load_errors.clone();
        out.extend(self.registry().diagnostics().iter().map(|d| d.to_string()));
        out
    }

    fn __len__(&mut self) -> usize {
        self.registry().len()
    }

    fn __contains__(&mut self, key: &str) -> bool {
        self.registry().index_of(key).is_some()
    }

    fn __getitem__(&mut self, key: &str) -> PyResult<PyMibNode> {
        self.lookup(key)
            .ok_or_else(|| PyKeyError::new_err(key.to_string()))
    }

    fn __repr__(&mut self) -> String {
        let registry = self.registry();
        format!(
            "MibTree({} modules, {} nodes)",
            registry.module_names().len(),
            registry.len()
        )
    }
}
