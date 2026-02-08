use pyo3::prelude::*;
use pyo3::types::PyBytes;

use super::message::{MessageV1, MessageV2c};
use super::pdu::{BulkPdu, ErrorStatus, Pdu, VarBind, VarBindValue};
use super::usm::UsmSecurityParameters;
use super::v3::{MessageV3, MsgFlags, ScopedPdu, ScopedPduData};
use crate::oid::Oid;
use crate::types::Value;

#[derive(Debug, Clone, PartialEq)]
#[pyclass(name = "SnmpVarBind")]
pub struct PySnmpVarBind {
    #[pyo3(get)]
    pub oid: Oid,
    #[pyo3(get)]
    pub value: Value,
}

#[pymethods]
impl PySnmpVarBind {
    #[new]
    pub fn new(oid: Oid, value: Value) -> Self {
        Self { oid, value }
    }

    fn __repr__(&self) -> String {
        format!("SnmpVarBind({}, {})", self.oid, self.value)
    }
}

impl From<VarBind> for PySnmpVarBind {
    fn from(vb: VarBind) -> Self {
        let value = match vb.value {
            VarBindValue::Value(v) => v,
            VarBindValue::Unspecified => Value::Null(),
            VarBindValue::NoSuchObject => Value::NoSuchObject(),
            VarBindValue::NoSuchInstance => Value::NoSuchInstance(),
            VarBindValue::EndOfMibView => Value::EndOfMibView(),
        };
        Self {
            oid: vb.name,
            value,
        }
    }
}

impl From<&PySnmpVarBind> for VarBind {
    fn from(vb: &PySnmpVarBind) -> Self {
        Self {
            name: vb.oid.clone(),
            value: VarBindValue::Value(vb.value.clone()),
        }
    }
}

#[derive(Debug, Clone)]
#[pyclass(name = "SnmpResponse")]
pub struct PySnmpResponse {
    #[pyo3(get)]
    pub request_id: i32,
    #[pyo3(get)]
    pub error_status: i32,
    #[pyo3(get)]
    pub error_index: i32,
    #[pyo3(get)]
    pub varbinds: Vec<PySnmpVarBind>,
}

#[pymethods]
impl PySnmpResponse {
    #[getter]
    fn is_error(&self) -> bool {
        self.error_status != 0
    }

    #[getter]
    fn error_message(&self) -> &'static str {
        match ErrorStatus::try_from(self.error_status) {
            Ok(e) => match e {
                ErrorStatus::NoError => "No error",
                ErrorStatus::TooBig => "Response too big",
                ErrorStatus::NoSuchName => "No such name",
                ErrorStatus::BadValue => "Bad value",
                ErrorStatus::ReadOnly => "Read only",
                ErrorStatus::GenErr => "General error",
                ErrorStatus::NoAccess => "No access",
                ErrorStatus::WrongType => "Wrong type",
                ErrorStatus::WrongLength => "Wrong length",
                ErrorStatus::WrongEncoding => "Wrong encoding",
                ErrorStatus::WrongValue => "Wrong value",
                ErrorStatus::NoCreation => "No creation",
                ErrorStatus::InconsistentValue => "Inconsistent value",
                ErrorStatus::ResourceUnavailable => "Resource unavailable",
                ErrorStatus::CommitFailed => "Commit failed",
                ErrorStatus::UndoFailed => "Undo failed",
                ErrorStatus::AuthorizationError => "Authorization error",
                ErrorStatus::NotWritable => "Not writable",
                ErrorStatus::InconsistentName => "Inconsistent name",
            },
            Err(_) => "Unknown error",
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "SnmpResponse(request_id={}, error={}, varbinds={})",
            self.request_id,
            self.error_status,
            self.varbinds.len()
        )
    }
}

// Encoding functions

#[pyfunction]
pub fn encode_snmp_get_v1(
    py: Python<'_>,
    community: &str,
    request_id: i32,
    oids: Vec<Oid>,
) -> PyResult<Py<PyBytes>> {
    let msg = MessageV1::get_request(community.as_bytes(), request_id, oids);
    let mut buf = Vec::new();
    msg.encode(&mut buf)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &buf).into())
}

#[pyfunction]
pub fn encode_snmp_getnext_v1(
    py: Python<'_>,
    community: &str,
    request_id: i32,
    oids: Vec<Oid>,
) -> PyResult<Py<PyBytes>> {
    let msg = MessageV1::get_next_request(community.as_bytes(), request_id, oids);
    let mut buf = Vec::new();
    msg.encode(&mut buf)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &buf).into())
}

#[pyfunction]
pub fn encode_snmp_get_v2c(
    py: Python<'_>,
    community: &str,
    request_id: i32,
    oids: Vec<Oid>,
) -> PyResult<Py<PyBytes>> {
    let msg = MessageV2c::get_request(community.as_bytes(), request_id, oids);
    let mut buf = Vec::new();
    msg.encode(&mut buf)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &buf).into())
}

#[pyfunction]
pub fn encode_snmp_getnext_v2c(
    py: Python<'_>,
    community: &str,
    request_id: i32,
    oids: Vec<Oid>,
) -> PyResult<Py<PyBytes>> {
    let msg = MessageV2c::get_next_request(community.as_bytes(), request_id, oids);
    let mut buf = Vec::new();
    msg.encode(&mut buf)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &buf).into())
}

#[pyfunction]
pub fn encode_snmp_getbulk_v2c(
    py: Python<'_>,
    community: &str,
    request_id: i32,
    non_repeaters: i32,
    max_repetitions: i32,
    oids: Vec<Oid>,
) -> PyResult<Py<PyBytes>> {
    let msg = MessageV2c::get_bulk_request(
        community.as_bytes(),
        request_id,
        non_repeaters,
        max_repetitions,
        oids,
    );
    let mut buf = Vec::new();
    msg.encode(&mut buf)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &buf).into())
}

#[pyfunction]
pub fn encode_snmp_set_v2c(
    py: Python<'_>,
    community: &str,
    request_id: i32,
    varbinds: Vec<PySnmpVarBind>,
) -> PyResult<Py<PyBytes>> {
    let internal_varbinds: Vec<VarBind> = varbinds.iter().map(|vb| vb.into()).collect();
    let msg = MessageV2c::set_request(community.as_bytes(), request_id, internal_varbinds);
    let mut buf = Vec::new();
    msg.encode(&mut buf)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &buf).into())
}

#[pyfunction]
#[pyo3(signature = (msg_id, request_id, oids, engine_id, engine_boots, engine_time, user_name, auth=false, priv_=false))]
#[allow(clippy::too_many_arguments)]
pub fn encode_snmp_get_v3(
    py: Python<'_>,
    msg_id: i32,
    request_id: i32,
    oids: Vec<Oid>,
    engine_id: Vec<u8>,
    engine_boots: i32,
    engine_time: i32,
    user_name: &str,
    auth: bool,
    priv_: bool,
) -> PyResult<Py<PyBytes>> {
    let pdu = Pdu::get_request(request_id, oids);
    let usm_params = UsmSecurityParameters::new(
        engine_id.clone(),
        engine_boots,
        engine_time,
        user_name.as_bytes(),
    );
    let security_params = usm_params
        .to_bytes()
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    let flags = MsgFlags::new(auth, priv_, true);
    let msg = MessageV3::new(msg_id, flags, security_params, engine_id, vec![], pdu);

    let mut buf = Vec::new();
    msg.encode(&mut buf)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &buf).into())
}

#[pyfunction]
#[pyo3(signature = (msg_id, request_id, non_repeaters, max_repetitions, oids, engine_id, engine_boots, engine_time, user_name, auth=false, priv_=false))]
#[allow(clippy::too_many_arguments)]
pub fn encode_snmp_getbulk_v3(
    py: Python<'_>,
    msg_id: i32,
    request_id: i32,
    non_repeaters: i32,
    max_repetitions: i32,
    oids: Vec<Oid>,
    engine_id: Vec<u8>,
    engine_boots: i32,
    engine_time: i32,
    user_name: &str,
    auth: bool,
    priv_: bool,
) -> PyResult<Py<PyBytes>> {
    let pdu = BulkPdu::new(request_id, non_repeaters, max_repetitions, oids);
    let usm_params = UsmSecurityParameters::new(
        engine_id.clone(),
        engine_boots,
        engine_time,
        user_name.as_bytes(),
    );
    let security_params = usm_params
        .to_bytes()
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    let flags = MsgFlags::new(auth, priv_, true);
    let msg = MessageV3::with_bulk(msg_id, flags, security_params, engine_id, vec![], pdu);

    let mut buf = Vec::new();
    msg.encode(&mut buf)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &buf).into())
}

// Decoding

#[pyfunction]
pub fn decode_snmp_response(data: &[u8]) -> PyResult<PySnmpResponse> {
    if data.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("Empty data"));
    }

    if data[0] != 0x30 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Invalid SNMP message: expected SEQUENCE",
        ));
    }

    // Try v2c first (most common)
    if let Ok((msg, _)) = MessageV2c::decode(data) {
        return match msg {
            MessageV2c::Standard { pdu, .. } => Ok(PySnmpResponse {
                request_id: pdu.request_id,
                error_status: pdu.error_status as i32,
                error_index: pdu.error_index,
                varbinds: pdu.varbinds.into_iter().map(|vb| vb.into()).collect(),
            }),
            MessageV2c::Bulk { pdu, .. } => Ok(PySnmpResponse {
                request_id: pdu.request_id,
                error_status: 0,
                error_index: 0,
                varbinds: pdu.varbinds.into_iter().map(|vb| vb.into()).collect(),
            }),
        };
    }

    // Try v1
    if let Ok((msg, _)) = MessageV1::decode(data) {
        return Ok(PySnmpResponse {
            request_id: msg.pdu.request_id,
            error_status: msg.pdu.error_status as i32,
            error_index: msg.pdu.error_index,
            varbinds: msg.pdu.varbinds.into_iter().map(|vb| vb.into()).collect(),
        });
    }

    // Try v3
    if let Ok((msg, _)) = MessageV3::decode(data) {
        return match msg.scoped_pdu {
            ScopedPdu::Plaintext { pdu, .. } => match pdu {
                ScopedPduData::Standard(p) => Ok(PySnmpResponse {
                    request_id: p.request_id,
                    error_status: p.error_status as i32,
                    error_index: p.error_index,
                    varbinds: p.varbinds.into_iter().map(|vb| vb.into()).collect(),
                }),
                ScopedPduData::Bulk(p) => Ok(PySnmpResponse {
                    request_id: p.request_id,
                    error_status: 0,
                    error_index: 0,
                    varbinds: p.varbinds.into_iter().map(|vb| vb.into()).collect(),
                }),
            },
            ScopedPdu::Encrypted(_) => Err(pyo3::exceptions::PyValueError::new_err(
                "Encrypted PDU - decryption not implemented",
            )),
        };
    }

    Err(pyo3::exceptions::PyValueError::new_err(
        "Failed to decode SNMP message",
    ))
}

// Constants

#[pyclass]
pub struct SnmpVersion;

#[pymethods]
impl SnmpVersion {
    #[classattr]
    const V1: i32 = 0;
    #[classattr]
    const V2C: i32 = 1;
    #[classattr]
    const V3: i32 = 3;
}

#[pyclass]
pub struct SnmpErrorStatus;

#[pymethods]
impl SnmpErrorStatus {
    #[classattr]
    const NO_ERROR: i32 = 0;
    #[classattr]
    const TOO_BIG: i32 = 1;
    #[classattr]
    const NO_SUCH_NAME: i32 = 2;
    #[classattr]
    const BAD_VALUE: i32 = 3;
    #[classattr]
    const READ_ONLY: i32 = 4;
    #[classattr]
    const GEN_ERR: i32 = 5;
    #[classattr]
    const NO_ACCESS: i32 = 6;
    #[classattr]
    const WRONG_TYPE: i32 = 7;
    #[classattr]
    const WRONG_LENGTH: i32 = 8;
    #[classattr]
    const WRONG_ENCODING: i32 = 9;
    #[classattr]
    const WRONG_VALUE: i32 = 10;
    #[classattr]
    const NO_CREATION: i32 = 11;
    #[classattr]
    const INCONSISTENT_VALUE: i32 = 12;
    #[classattr]
    const RESOURCE_UNAVAILABLE: i32 = 13;
    #[classattr]
    const COMMIT_FAILED: i32 = 14;
    #[classattr]
    const UNDO_FAILED: i32 = 15;
    #[classattr]
    const AUTHORIZATION_ERROR: i32 = 16;
    #[classattr]
    const NOT_WRITABLE: i32 = 17;
    #[classattr]
    const INCONSISTENT_NAME: i32 = 18;
}
