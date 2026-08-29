use pyo3::prelude::*;

pub mod agentx;
pub mod asn1;
pub mod mib;
pub mod oid;
pub mod snmp;
pub mod types;

#[pymodule(name = "core")]
fn snmpkit_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<oid::Oid>()?;
    m.add_class::<types::Value>()?;
    m.add_class::<agentx::pdu::VarBind>()?;

    // AgentX protocol bindings
    m.add_class::<agentx::bindings::AgentXHeader>()?;
    m.add_class::<agentx::bindings::AgentXResponse>()?;
    m.add_class::<agentx::bindings::AgentXGet>()?;
    m.add_class::<agentx::bindings::AgentXGetBulk>()?;
    m.add_class::<agentx::bindings::AgentXTestSet>()?;
    m.add_class::<agentx::bindings::PduTypes>()?;
    m.add_class::<agentx::bindings::CloseReasons>()?;
    m.add_class::<agentx::bindings::ResponseErrors>()?;

    m.add_function(pyo3::wrap_pyfunction!(
        agentx::bindings::encode_open_pdu,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        agentx::bindings::encode_close_pdu,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        agentx::bindings::encode_register_pdu,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        agentx::bindings::encode_unregister_pdu,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        agentx::bindings::encode_response_pdu,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        agentx::bindings::encode_notify_pdu,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        agentx::bindings::encode_ping_pdu,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(agentx::bindings::decode_header, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        agentx::bindings::decode_response_pdu,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(agentx::bindings::decode_get_pdu, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        agentx::bindings::decode_getbulk_pdu,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        agentx::bindings::decode_testset_pdu,
        m
    )?)?;

    m.add("HEADER_SIZE", agentx::bindings::HEADER_SIZE_PY)?;

    // SNMP protocol bindings
    m.add_class::<snmp::bindings::PySnmpVarBind>()?;
    m.add_class::<snmp::bindings::PySnmpResponse>()?;
    m.add_class::<snmp::bindings::SnmpVersion>()?;
    m.add_class::<snmp::bindings::SnmpErrorStatus>()?;

    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_get_v1,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_getnext_v1,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_get_v2c,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_getnext_v2c,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_getbulk_v2c,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_set_v2c,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_get_v3,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_getbulk_v3,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::decode_snmp_response,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::peek_correlation_id,
        m
    )?)?;

    // SNMPv1 Trap
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_trap_v1,
        m
    )?)?;

    // Trap/Inform/Response v2c
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_trap_v2c,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_inform_v2c,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_response_v2c,
        m
    )?)?;

    // SNMPv3 USM crypto bindings
    m.add_function(pyo3::wrap_pyfunction!(snmp::bindings::password_to_key, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(snmp::bindings::localize_key, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::password_to_localized_key,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::password_to_privacy_key,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encrypt_scoped_pdu,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::decrypt_scoped_pdu,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_get_v3_secure,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_getnext_v3_secure,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_getbulk_v3_secure,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_set_v3_secure,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::decode_snmp_v3_response,
        m
    )?)?;

    // Trap/Inform/Response v3 secure
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_trap_v3_secure,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_inform_v3_secure,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::encode_snmp_response_v3_secure,
        m
    )?)?;

    // MIB parsing (RFC 2578/2579, SMIv1)
    m.add_class::<mib::bindings::PyMibTree>()?;
    m.add_class::<mib::bindings::PyMibNode>()?;

    // Generic message decoder
    m.add_class::<snmp::bindings::PySnmpMessage>()?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::decode_snmp_message,
        m
    )?)?;
    m.add_function(pyo3::wrap_pyfunction!(
        snmp::bindings::decode_snmp_v3_message,
        m
    )?)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_version() {
        assert_eq!(env!("CARGO_PKG_VERSION"), "1.8.0");
    }
}
