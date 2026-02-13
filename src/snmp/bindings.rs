use pyo3::prelude::*;
use pyo3::types::PyBytes;

use super::auth;
use super::message::{MessageV1, MessageV2c};
use super::pdu::{BulkPdu, ErrorStatus, Pdu, VarBind, VarBindValue};
use super::privacy;
use super::usm::{AuthProtocol, PrivProtocol, UsmSecurityParameters};
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

// SNMPv3 USM crypto functions

fn parse_auth_protocol(name: &str) -> PyResult<AuthProtocol> {
    match name.to_uppercase().as_str() {
        "MD5" => Ok(AuthProtocol::Md5),
        "SHA" | "SHA1" => Ok(AuthProtocol::Sha),
        "SHA224" => Ok(AuthProtocol::Sha224),
        "SHA256" => Ok(AuthProtocol::Sha256),
        "SHA384" => Ok(AuthProtocol::Sha384),
        "SHA512" => Ok(AuthProtocol::Sha512),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown auth protocol: {name}"
        ))),
    }
}

fn parse_priv_protocol(name: &str) -> PyResult<PrivProtocol> {
    match name.to_uppercase().as_str() {
        "DES" => Ok(PrivProtocol::Des),
        "AES" | "AES128" => Ok(PrivProtocol::Aes128),
        "AES192" => Ok(PrivProtocol::Aes192),
        "AES256" => Ok(PrivProtocol::Aes256),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown priv protocol: {name}"
        ))),
    }
}

#[pyfunction]
pub fn password_to_key(py: Python<'_>, password: &str, protocol: &str) -> PyResult<Py<PyBytes>> {
    let auth = parse_auth_protocol(protocol)?;
    let key = auth::password_to_key(password.as_bytes(), auth)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &key).into())
}

#[pyfunction]
pub fn localize_key(
    py: Python<'_>,
    key: &[u8],
    engine_id: &[u8],
    protocol: &str,
) -> PyResult<Py<PyBytes>> {
    let auth = parse_auth_protocol(protocol)?;
    let localized = auth::localize_key(key, engine_id, auth)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &localized).into())
}

#[pyfunction]
pub fn password_to_localized_key(
    py: Python<'_>,
    password: &str,
    engine_id: &[u8],
    protocol: &str,
) -> PyResult<Py<PyBytes>> {
    let auth = parse_auth_protocol(protocol)?;
    let key = auth::password_to_localized_key(password.as_bytes(), engine_id, auth)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &key).into())
}

#[pyfunction]
pub fn encrypt_scoped_pdu(
    py: Python<'_>,
    plaintext: &[u8],
    key: &[u8],
    engine_boots: i32,
    engine_time: i32,
    protocol: &str,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let priv_proto = parse_priv_protocol(protocol)?;
    let (ciphertext, priv_params) =
        privacy::encrypt_scoped_pdu(plaintext, key, engine_boots, engine_time, priv_proto)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok((
        PyBytes::new(py, &ciphertext).into(),
        PyBytes::new(py, &priv_params).into(),
    ))
}

#[pyfunction]
pub fn decrypt_scoped_pdu(
    py: Python<'_>,
    ciphertext: &[u8],
    key: &[u8],
    priv_parameters: &[u8],
    engine_boots: i32,
    engine_time: i32,
    protocol: &str,
) -> PyResult<Py<PyBytes>> {
    let priv_proto = parse_priv_protocol(protocol)?;
    let plaintext = privacy::decrypt_scoped_pdu(
        ciphertext,
        key,
        priv_parameters,
        engine_boots,
        engine_time,
        priv_proto,
    )
    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

// Encode SNMPv3 message with auth and/or priv
#[pyfunction]
#[pyo3(signature = (msg_id, request_id, oids, engine_id, engine_boots, engine_time, user_name, context_name=vec![], auth_protocol=None, auth_key=None, priv_protocol=None, priv_key=None))]
#[allow(clippy::too_many_arguments)]
pub fn encode_snmp_get_v3_secure(
    py: Python<'_>,
    msg_id: i32,
    request_id: i32,
    oids: Vec<Oid>,
    engine_id: Vec<u8>,
    engine_boots: i32,
    engine_time: i32,
    user_name: &str,
    context_name: Vec<u8>,
    auth_protocol: Option<&str>,
    auth_key: Option<Vec<u8>>,
    priv_protocol: Option<&str>,
    priv_key: Option<Vec<u8>>,
) -> PyResult<Py<PyBytes>> {
    let pdu = Pdu::get_request(request_id, oids);
    encode_v3_message(
        py,
        msg_id,
        V3PduData::Standard(pdu),
        engine_id,
        engine_boots,
        engine_time,
        user_name,
        context_name,
        auth_protocol,
        auth_key,
        priv_protocol,
        priv_key,
    )
}

#[pyfunction]
#[pyo3(signature = (msg_id, request_id, oids, engine_id, engine_boots, engine_time, user_name, context_name=vec![], auth_protocol=None, auth_key=None, priv_protocol=None, priv_key=None))]
#[allow(clippy::too_many_arguments)]
pub fn encode_snmp_getnext_v3_secure(
    py: Python<'_>,
    msg_id: i32,
    request_id: i32,
    oids: Vec<Oid>,
    engine_id: Vec<u8>,
    engine_boots: i32,
    engine_time: i32,
    user_name: &str,
    context_name: Vec<u8>,
    auth_protocol: Option<&str>,
    auth_key: Option<Vec<u8>>,
    priv_protocol: Option<&str>,
    priv_key: Option<Vec<u8>>,
) -> PyResult<Py<PyBytes>> {
    let pdu = Pdu::get_next_request(request_id, oids);
    encode_v3_message(
        py,
        msg_id,
        V3PduData::Standard(pdu),
        engine_id,
        engine_boots,
        engine_time,
        user_name,
        context_name,
        auth_protocol,
        auth_key,
        priv_protocol,
        priv_key,
    )
}

#[pyfunction]
#[pyo3(signature = (msg_id, request_id, non_repeaters, max_repetitions, oids, engine_id, engine_boots, engine_time, user_name, context_name=vec![], auth_protocol=None, auth_key=None, priv_protocol=None, priv_key=None))]
#[allow(clippy::too_many_arguments)]
pub fn encode_snmp_getbulk_v3_secure(
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
    context_name: Vec<u8>,
    auth_protocol: Option<&str>,
    auth_key: Option<Vec<u8>>,
    priv_protocol: Option<&str>,
    priv_key: Option<Vec<u8>>,
) -> PyResult<Py<PyBytes>> {
    let pdu = BulkPdu::new(request_id, non_repeaters, max_repetitions, oids);
    encode_v3_message(
        py,
        msg_id,
        V3PduData::Bulk(pdu),
        engine_id,
        engine_boots,
        engine_time,
        user_name,
        context_name,
        auth_protocol,
        auth_key,
        priv_protocol,
        priv_key,
    )
}

#[pyfunction]
#[pyo3(signature = (msg_id, request_id, varbinds, engine_id, engine_boots, engine_time, user_name, context_name=vec![], auth_protocol=None, auth_key=None, priv_protocol=None, priv_key=None))]
#[allow(clippy::too_many_arguments)]
pub fn encode_snmp_set_v3_secure(
    py: Python<'_>,
    msg_id: i32,
    request_id: i32,
    varbinds: Vec<PySnmpVarBind>,
    engine_id: Vec<u8>,
    engine_boots: i32,
    engine_time: i32,
    user_name: &str,
    context_name: Vec<u8>,
    auth_protocol: Option<&str>,
    auth_key: Option<Vec<u8>>,
    priv_protocol: Option<&str>,
    priv_key: Option<Vec<u8>>,
) -> PyResult<Py<PyBytes>> {
    let internal_varbinds: Vec<VarBind> = varbinds.iter().map(|vb| vb.into()).collect();
    let pdu = Pdu::set_request(request_id, internal_varbinds);
    encode_v3_message(
        py,
        msg_id,
        V3PduData::Standard(pdu),
        engine_id,
        engine_boots,
        engine_time,
        user_name,
        context_name,
        auth_protocol,
        auth_key,
        priv_protocol,
        priv_key,
    )
}

// Decode SNMPv3 response with decryption and auth verification
#[pyfunction]
#[pyo3(signature = (data, auth_protocol=None, auth_key=None, priv_protocol=None, priv_key=None, engine_boots=0, engine_time=0))]
pub fn decode_snmp_v3_response(
    data: &[u8],
    auth_protocol: Option<&str>,
    auth_key: Option<Vec<u8>>,
    priv_protocol: Option<&str>,
    priv_key: Option<Vec<u8>>,
    engine_boots: i32,
    engine_time: i32,
) -> PyResult<PySnmpResponse> {
    let (msg, _) = MessageV3::decode(data)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    // Verify authentication if configured
    if let (Some(proto_name), Some(key)) = (&auth_protocol, &auth_key) {
        let proto = parse_auth_protocol(proto_name)?;
        // Find auth_parameters offset in raw message
        if let Some(offset) = find_auth_params_offset(data) {
            auth::verify_authentication(data, offset, key, proto)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        }
    }

    match msg.scoped_pdu {
        ScopedPdu::Plaintext { pdu, .. } => decode_scoped_pdu_data(pdu),
        ScopedPdu::Encrypted(encrypted) => {
            let proto_name = priv_protocol.ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("encrypted PDU but no priv_protocol")
            })?;
            let key = priv_key.ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("encrypted PDU but no priv_key")
            })?;
            let proto = parse_priv_protocol(proto_name)?;

            // Get priv_parameters from USM
            let (usm, _) = UsmSecurityParameters::decode(&msg.security_parameters)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

            let plaintext = privacy::decrypt_scoped_pdu(
                &encrypted,
                &key,
                &usm.priv_parameters,
                engine_boots,
                engine_time,
                proto,
            )
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

            // Parse decrypted ScopedPDU
            let (inner, _) = crate::asn1::ber::decode_sequence(&plaintext)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

            let mut pos = 0;
            let (_, cei_len) = crate::asn1::ber::decode_octet_string(inner)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            pos += cei_len;
            let (_, cn_len) = crate::asn1::ber::decode_octet_string(&inner[pos..])
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            pos += cn_len;

            let pdu_data = &inner[pos..];
            let pdu = if !pdu_data.is_empty()
                && pdu_data[0] == super::pdu::PduType::GetBulkRequest as u8
            {
                let (p, _) = BulkPdu::decode(pdu_data)
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
                ScopedPduData::Bulk(p)
            } else {
                let (p, _) = Pdu::decode(pdu_data)
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
                ScopedPduData::Standard(p)
            };

            decode_scoped_pdu_data(pdu)
        }
    }
}

// Internal helpers

enum V3PduData {
    Standard(Pdu),
    Bulk(BulkPdu),
}

#[allow(clippy::too_many_arguments)]
fn encode_v3_message(
    py: Python<'_>,
    msg_id: i32,
    pdu_data: V3PduData,
    engine_id: Vec<u8>,
    engine_boots: i32,
    engine_time: i32,
    user_name: &str,
    context_name: Vec<u8>,
    auth_protocol: Option<&str>,
    auth_key: Option<Vec<u8>>,
    priv_protocol: Option<&str>,
    priv_key: Option<Vec<u8>>,
) -> PyResult<Py<PyBytes>> {
    let has_auth = auth_protocol.is_some() && auth_key.is_some();
    let has_priv = priv_protocol.is_some() && priv_key.is_some();
    let flags = MsgFlags::new(has_auth, has_priv, true);

    let auth_proto = auth_protocol.map(parse_auth_protocol).transpose()?;

    // Build USM params with placeholder auth_parameters
    let digest_len = auth_proto.map_or(0, |p| p.digest_length());
    let usm_params = UsmSecurityParameters::new(
        engine_id.clone(),
        engine_boots,
        engine_time,
        user_name.as_bytes(),
    )
    .with_auth(vec![0u8; digest_len]);

    if has_priv {
        // Encrypt scoped PDU
        let proto = parse_priv_protocol(priv_protocol.unwrap())?;
        let key = priv_key.as_ref().unwrap();

        // Encode scoped PDU to bytes
        let mut scoped_bytes = Vec::new();
        crate::asn1::ber::encode_octet_string(&mut scoped_bytes, &engine_id)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        crate::asn1::ber::encode_octet_string(&mut scoped_bytes, &context_name)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        match &pdu_data {
            V3PduData::Standard(pdu) => pdu
                .encode(&mut scoped_bytes)
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?,
            V3PduData::Bulk(pdu) => pdu
                .encode(&mut scoped_bytes)
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?,
        }
        let mut scoped_seq = Vec::new();
        crate::asn1::ber::encode_sequence(&mut scoped_seq, &scoped_bytes)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        let (ciphertext, priv_params) =
            privacy::encrypt_scoped_pdu(&scoped_seq, key, engine_boots, engine_time, proto)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let usm_with_priv = usm_params.with_priv(priv_params);
        let security_params = usm_with_priv
            .to_bytes()
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        let msg = MessageV3::encrypted(msg_id, flags, security_params, ciphertext);

        let mut buf = Vec::new();
        msg.encode(&mut buf)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        // Apply authentication if configured
        if has_auth {
            let key = auth_key.as_ref().unwrap();
            let proto = auth_proto.unwrap();
            if let Some(offset) = find_auth_params_offset(&buf) {
                auth::authenticate_message(&mut buf, offset, key, proto)
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            }
        }

        Ok(PyBytes::new(py, &buf).into())
    } else {
        // No encryption - plaintext
        let security_params = usm_params
            .to_bytes()
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        let msg = match pdu_data {
            V3PduData::Standard(pdu) => {
                MessageV3::new(msg_id, flags, security_params, engine_id, context_name, pdu)
            }
            V3PduData::Bulk(pdu) => {
                MessageV3::with_bulk(msg_id, flags, security_params, engine_id, context_name, pdu)
            }
        };

        let mut buf = Vec::new();
        msg.encode(&mut buf)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        // Apply authentication if configured
        if has_auth {
            let key = auth_key.as_ref().unwrap();
            let proto = auth_proto.unwrap();
            if let Some(offset) = find_auth_params_offset(&buf) {
                auth::authenticate_message(&mut buf, offset, key, proto)
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            }
        }

        Ok(PyBytes::new(py, &buf).into())
    }
}

fn decode_scoped_pdu_data(pdu: ScopedPduData) -> PyResult<PySnmpResponse> {
    match pdu {
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
    }
}

// Find the offset of authenticationParameters in the raw SNMPv3 message.
//
// The auth_parameters field is inside msgSecurityParameters (OCTET STRING),
// which contains a BER-encoded USM SEQUENCE. We scan for the user_name
// OCTET STRING then skip past it to find the auth_parameters OCTET STRING.
fn find_auth_params_offset(data: &[u8]) -> Option<usize> {
    // msgSecurityParameters is the 3rd field in the outer SEQUENCE.
    // Parse: SEQUENCE { version, headerData(SEQUENCE), securityParams(OCTET STRING), ... }
    let (outer, _) = crate::asn1::ber::decode_sequence(data).ok()?;
    let mut pos = 0;

    // Skip version (INTEGER)
    let (_, ver_len) = crate::asn1::ber::decode_integer(outer).ok()?;
    pos += ver_len;

    // Skip headerData (SEQUENCE)
    let (_, hd_len) = crate::asn1::ber::decode_sequence(&outer[pos..]).ok()?;
    pos += hd_len;

    // msgSecurityParameters (OCTET STRING) - get its raw position in data
    if outer.len() <= pos || outer[pos] != 0x04 {
        return None;
    }
    let (sp_len, sp_len_bytes) = crate::asn1::ber::decode_length(&outer[pos + 1..]).ok()?;
    let sp_content_start = pos + 1 + sp_len_bytes;

    // Parse USM SEQUENCE inside the security parameters
    let sp_data = &outer[sp_content_start..sp_content_start + sp_len];
    let (usm_inner, _) = crate::asn1::ber::decode_sequence(sp_data).ok()?;
    let mut usm_pos = 0;

    // Skip engineID (OCTET STRING)
    let (_, eid_len) = crate::asn1::ber::decode_octet_string(usm_inner).ok()?;
    usm_pos += eid_len;

    // Skip engineBoots (INTEGER)
    let (_, eb_len) = crate::asn1::ber::decode_integer(&usm_inner[usm_pos..]).ok()?;
    usm_pos += eb_len;

    // Skip engineTime (INTEGER)
    let (_, et_len) = crate::asn1::ber::decode_integer(&usm_inner[usm_pos..]).ok()?;
    usm_pos += et_len;

    // Skip userName (OCTET STRING)
    let (_, un_len) = crate::asn1::ber::decode_octet_string(&usm_inner[usm_pos..]).ok()?;
    usm_pos += un_len;

    // authenticationParameters (OCTET STRING) - this is what we want
    // Its content starts after tag (0x04) + length bytes
    if usm_inner.len() <= usm_pos || usm_inner[usm_pos] != 0x04 {
        return None;
    }
    let (_, auth_len_bytes) = crate::asn1::ber::decode_length(&usm_inner[usm_pos + 1..]).ok()?;

    // Calculate absolute offset in the original data
    // outer starts at: tag(1) + length_bytes of outer sequence
    let (_, outer_len_bytes) = crate::asn1::ber::decode_length(&data[1..]).ok()?;
    let outer_start = 1 + outer_len_bytes;

    // USM inner starts at: sp_content_start + SEQUENCE tag(1) + SEQUENCE length_bytes
    let (_, usm_seq_len_bytes) = crate::asn1::ber::decode_length(&sp_data[1..]).ok()?;
    let usm_inner_start = sp_content_start + 1 + usm_seq_len_bytes;

    Some(outer_start + usm_inner_start + usm_pos + 1 + auth_len_bytes)
}
