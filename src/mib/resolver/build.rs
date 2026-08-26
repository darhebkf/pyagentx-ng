use std::collections::{HashMap, HashSet};

use super::{MibNode, NodeKind, Registry, ResolvedSyntax};
use crate::mib::{
    BaseType, Definition, Diagnostic, MibModule, NodeFlavour, OidComponent, OidExpr, Syntax,
    TypeDefKind,
};
use crate::oid::Oid;

// ITU-T X.660 root arcs; no MIB defines them.
pub(super) const ROOT_ARCS: &[(&str, u32)] = &[("ccitt", 0), ("iso", 1), ("joint-iso-ccitt", 2)];

// Guards against a MIB whose OID or type chain refers back to itself.
const MAX_CHAIN_DEPTH: usize = 64;

type DefRef = (usize, usize);

pub(super) struct Builder<'a> {
    modules: &'a [MibModule],
    oid_defs: HashMap<String, DefRef>,
    type_defs: HashMap<String, DefRef>,
    oid_cache: HashMap<String, Option<Vec<u32>>>,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Builder<'a> {
    pub(super) fn new(modules: &'a [MibModule]) -> Self {
        let mut builder = Self {
            modules,
            oid_defs: HashMap::new(),
            type_defs: HashMap::new(),
            oid_cache: HashMap::new(),
            diagnostics: Vec::new(),
        };
        for module in modules {
            builder
                .diagnostics
                .extend(module.diagnostics.iter().cloned());
        }
        builder.index_definitions();
        builder
    }

    fn index_definitions(&mut self) {
        for (mi, module) in self.modules.iter().enumerate() {
            for (di, def) in module.definitions.iter().enumerate() {
                let name = def.name().to_string();
                let table = match def {
                    Definition::Type(_) => &mut self.type_defs,
                    _ => &mut self.oid_defs,
                };
                if let Some(&(prev_mi, prev_di)) = table.get(&name) {
                    // Overlapping standard MIBs redefine symbols identically all the time.
                    let previous = &self.modules[prev_mi].definitions[prev_di];
                    if previous != def {
                        self.diagnostics.push(Diagnostic::new(
                            module.name.clone(),
                            def_line(def),
                            format!(
                                "{name} is already defined in {}; keeping the first",
                                self.modules[prev_mi].name
                            ),
                        ));
                    }
                    continue;
                }
                table.insert(name, (mi, di));
            }
        }
    }

    pub(super) fn run(mut self) -> Registry {
        let mut nodes: Vec<MibNode> = Vec::new();
        let mut by_oid: HashMap<Vec<u32>, usize> = HashMap::new();
        let mut by_name: HashMap<String, usize> = HashMap::new();

        for (name, arc) in ROOT_ARCS {
            let Ok(oid) = Oid::new(vec![*arc]) else {
                continue;
            };
            let index = nodes.len();
            nodes.push(root_node(name, oid));
            by_oid.insert(vec![*arc], index);
            by_name.insert((*name).to_string(), index);
        }

        let mut names: Vec<String> = self.oid_defs.keys().cloned().collect();
        names.sort();

        for name in names {
            let Some(parts) = self.resolve_name(&name, 0) else {
                continue;
            };
            let (mi, di) = self.oid_defs[&name];
            let module = &self.modules[mi];
            let def = &module.definitions[di];

            let Ok(oid) = Oid::new(parts.clone()) else {
                self.diagnostics.push(Diagnostic::new(
                    module.name.clone(),
                    def_line(def),
                    format!("{name}: empty OID"),
                ));
                continue;
            };

            if by_oid.contains_key(&parts) {
                // Two names on one OID: keep the first.
                let other = &nodes[by_oid[&parts]].name;
                if other != &name {
                    self.diagnostics.push(Diagnostic::new(
                        module.name.clone(),
                        def_line(def),
                        format!("{name} and {other} share OID {oid}"),
                    ));
                }
                continue;
            }

            let node = self.make_node(module.name.clone(), oid, def);
            let index = nodes.len();
            by_name.insert(name, index);
            by_oid.insert(parts, index);
            nodes.push(node);
        }

        link_tree(&mut nodes, &by_oid);
        classify(&mut nodes);
        inherit_augmented_indexes(&mut nodes, &by_name);

        let roots = (0..nodes.len())
            .filter(|i| nodes[*i].parent.is_none())
            .collect();

        Registry {
            nodes,
            by_name,
            by_oid,
            roots,
            module_names: self.modules.iter().map(|m| m.name.clone()).collect(),
            diagnostics: self.diagnostics,
        }
    }

    fn make_node(&self, module: String, oid: Oid, def: &Definition) -> MibNode {
        let mut node = MibNode {
            name: def.name().to_string(),
            module,
            oid,
            kind: NodeKind::Node,
            syntax: None,
            max_access: None,
            status: None,
            description: None,
            reference: None,
            units: None,
            defval: None,
            index: Vec::new(),
            augments: None,
            row_type: None,
            objects: Vec::new(),
            parent: None,
            children: Vec::new(),
        };

        match def {
            Definition::Node(n) => {
                node.status = n.status;
                node.description = n.description.clone();
                if n.flavour == NodeFlavour::ModuleIdentity {
                    node.reference = Some(format!("MODULE-IDENTITY of {}", node.module));
                }
            }
            Definition::Object(o) => {
                node.syntax = Some(self.resolve_syntax(&o.syntax));
                if let Syntax::SequenceOf(row) = &o.syntax {
                    node.row_type = Some(row.clone());
                }
                node.max_access = Some(o.max_access);
                node.status = Some(o.status);
                node.description = o.description.clone();
                node.reference = o.reference.clone();
                node.units = o.units.clone();
                node.defval = o.defval.clone();
                node.index = o.index.clone();
                node.augments = o.augments.clone();
            }
            Definition::Notification(n) => {
                node.kind = NodeKind::Notification;
                node.status = n.status;
                node.description = n.description.clone();
                node.objects = n.objects.clone();
            }
            Definition::Type(_) => {}
        }
        node
    }

    // RFC 2579 §3.5 forbids TC-of-TC, but vendor MIBs do it; walk the chain.
    fn resolve_syntax(&self, syntax: &Syntax) -> ResolvedSyntax {
        let declared = syntax.type_name().to_string();
        let mut resolved = ResolvedSyntax {
            declared,
            base: None,
            display_hint: None,
            enums: Vec::new(),
            constraint: None,
        };

        let mut current = syntax.clone();
        let mut seen: HashSet<String> = HashSet::new();

        for _ in 0..MAX_CHAIN_DEPTH {
            let Syntax::Named {
                name,
                constraint,
                enums,
            } = &current
            else {
                return resolved;
            };

            if resolved.enums.is_empty() {
                resolved.enums = enums.clone();
            }
            if resolved.constraint.is_none() {
                resolved.constraint = constraint.clone();
            }
            if let Some(base) = BaseType::parse(name) {
                resolved.base = Some(base);
                return resolved;
            }
            if !seen.insert(name.clone()) {
                return resolved;
            }

            let Some(&(mi, di)) = self.type_defs.get(name) else {
                return resolved;
            };
            let Definition::Type(type_def) = &self.modules[mi].definitions[di] else {
                return resolved;
            };
            current = match &type_def.kind {
                TypeDefKind::TextualConvention {
                    display_hint,
                    syntax,
                    ..
                } => {
                    if resolved.display_hint.is_none() {
                        resolved.display_hint = display_hint.clone();
                    }
                    syntax.clone()
                }
                TypeDefKind::Alias(syntax) => syntax.clone(),
            };
        }
        resolved
    }

    fn resolve_name(&mut self, name: &str, depth: usize) -> Option<Vec<u32>> {
        if let Some((_, arc)) = ROOT_ARCS.iter().find(|(n, _)| *n == name) {
            return Some(vec![*arc]);
        }
        if let Some(cached) = self.oid_cache.get(name) {
            return cached.clone();
        }
        if depth >= MAX_CHAIN_DEPTH {
            self.diagnostics.push(Diagnostic::new(
                "",
                0,
                format!("{name}: OID definition is circular"),
            ));
            return None;
        }

        let &(mi, di) = self.oid_defs.get(name)?;
        // Claim the name before recursing so a cycle terminates.
        self.oid_cache.insert(name.to_string(), None);

        let module_name = self.modules[mi].name.clone();
        let def = &self.modules[mi].definitions[di];
        let (expr, line) = match def {
            Definition::Node(n) => (n.oid.clone(), n.line),
            Definition::Object(o) => (o.oid.clone(), o.line),
            Definition::Notification(n) => (n.oid.clone(), n.line),
            Definition::Type(_) => return None,
        };

        let resolved = self.resolve_expr(&module_name, name, line, &expr, depth);
        self.oid_cache.insert(name.to_string(), resolved.clone());
        resolved
    }

    fn resolve_expr(
        &mut self,
        module: &str,
        owner: &str,
        line: usize,
        expr: &OidExpr,
        depth: usize,
    ) -> Option<Vec<u32>> {
        if expr.components.is_empty() {
            return None;
        }
        let mut parts: Vec<u32> = Vec::with_capacity(expr.components.len());

        for (i, component) in expr.components.iter().enumerate() {
            match component {
                OidComponent::Number(n) => parts.push(*n),
                // Past position 0 the explicit sub-identifier wins; that is the `dod(6)` form.
                OidComponent::NamedNumber(_, n) if i > 0 => parts.push(*n),
                OidComponent::NamedNumber(label, n) => match self.resolve_name(label, depth + 1) {
                    Some(base) => parts.extend_from_slice(&base),
                    None => parts.push(*n),
                },
                OidComponent::Name(label) => {
                    let Some(base) = self.resolve_name(label, depth + 1) else {
                        self.diagnostics.push(Diagnostic::new(
                            module.to_string(),
                            line,
                            format!("{owner}: unknown parent '{label}'"),
                        ));
                        return None;
                    };
                    if i == 0 {
                        parts.extend_from_slice(&base);
                    } else if base.len() > parts.len() && base.starts_with(&parts) {
                        parts.extend_from_slice(&base[parts.len()..]);
                    } else {
                        self.diagnostics.push(Diagnostic::new(
                            module.to_string(),
                            line,
                            format!("{owner}: '{label}' is not below the preceding arcs"),
                        ));
                        return None;
                    }
                }
            }
        }
        Some(parts)
    }
}

fn root_node(name: &str, oid: Oid) -> MibNode {
    MibNode {
        name: name.to_string(),
        module: String::new(),
        oid,
        kind: NodeKind::Node,
        syntax: None,
        max_access: None,
        status: None,
        description: None,
        reference: None,
        units: None,
        defval: None,
        index: Vec::new(),
        augments: None,
        row_type: None,
        objects: Vec::new(),
        parent: None,
        children: Vec::new(),
    }
}

fn def_line(def: &Definition) -> usize {
    match def {
        Definition::Node(n) => n.line,
        Definition::Object(o) => o.line,
        Definition::Notification(n) => n.line,
        Definition::Type(t) => t.line,
    }
}

// Links each node to the deepest defined ancestor.
// Gaps are not filled with placeholder nodes: an enterprise OID that skips
// three undefined arcs simply hangs off the last named node above it, which
// is more useful to browse than a run of bare numbers.
fn link_tree(nodes: &mut [MibNode], by_oid: &HashMap<Vec<u32>, usize>) {
    for i in 0..nodes.len() {
        let parts = nodes[i].oid.parts().to_vec();
        let mut parent = None;
        for cut in (1..parts.len()).rev() {
            if let Some(&p) = by_oid.get(&parts[..cut]) {
                parent = Some(p);
                break;
            }
        }
        nodes[i].parent = parent;
        if let Some(p) = parent {
            nodes[p].children.push(i);
        }
    }
    // Children read best in OID order.
    let order: Vec<Vec<u32>> = nodes.iter().map(|n| n.oid.parts().to_vec()).collect();
    for node in nodes.iter_mut() {
        node.children.sort_by(|a, b| order[*a].cmp(&order[*b]));
    }
}

// RFC 2578 §7.1.12: a `SEQUENCE OF` object is a conceptual table, its child is
// the row, and the row's children are the columns.
fn classify(nodes: &mut [MibNode]) {
    let mut kinds: Vec<NodeKind> = nodes
        .iter()
        .map(|n| match n.kind {
            NodeKind::Notification => NodeKind::Notification,
            _ if n.syntax.is_some() => NodeKind::Scalar,
            _ => NodeKind::Node,
        })
        .collect();

    let tables: Vec<usize> = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.row_type.is_some())
        .map(|(i, _)| i)
        .collect();

    for table in tables {
        kinds[table] = NodeKind::Table;
        for &row in &nodes[table].children {
            kinds[row] = NodeKind::Row;
            for &column in &nodes[row].children {
                kinds[column] = NodeKind::Column;
            }
        }
    }

    for (node, kind) in nodes.iter_mut().zip(kinds) {
        node.kind = kind;
    }
}

// RFC 2578 §7.8.1: an augmenting row is indexed exactly like the row it
// augments, following a chain if one row augments another.
fn inherit_augmented_indexes(nodes: &mut [MibNode], by_name: &HashMap<String, usize>) {
    let augmenting: Vec<usize> = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.augments.is_some() && n.index.is_empty())
        .map(|(i, _)| i)
        .collect();

    for i in augmenting {
        let mut cursor = i;
        let mut index = Vec::new();
        for _ in 0..MAX_CHAIN_DEPTH {
            let Some(base_name) = nodes[cursor].augments.clone() else {
                break;
            };
            let Some(&base) = by_name.get(&base_name) else {
                break;
            };
            if base == cursor {
                break;
            }
            if !nodes[base].index.is_empty() {
                index = nodes[base].index.clone();
                break;
            }
            cursor = base;
        }
        nodes[i].index = index;
    }
}
