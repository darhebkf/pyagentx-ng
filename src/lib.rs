use pyo3::prelude::*;

pub mod agentx;
pub mod oid;
pub mod types;

#[pymodule(name = "core")]
fn snmpkit_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<oid::Oid>()?;
    m.add_class::<types::Value>()?;
    m.add_class::<agentx::pdu::VarBind>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_version() {
        assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
    }
}
