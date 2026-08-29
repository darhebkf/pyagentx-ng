"""Connection details for the net-snmp agent running in this container."""

HOST = "127.0.0.1"
PORT = 11161
COMMUNITY = "public"
RW_COMMUNITY = "private"
TRAP_PORT = 11162
AGENTX_SOCKET = "/var/agentx/master"
MIB_DIR = "/src/tests/mibs/smiv2"

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# net-snmp spells SHA-256; snmpkit spells SHA256.
V3_USERS = [
    ("authOnlyUser", "SHA", "authonlypass123", None, None),
    ("authPrivAesUser", "SHA", "authprivpass123", "AES", "privpass123456"),
    ("authPrivDesUser", "MD5", "md5despass123", "DES", "despass123456"),
    ("sha256User", "SHA256", "sha256pass123", "AES", "privpass123456"),
    ("aes192User", "SHA", "aes192pass123", "AES192", "privpass123456"),
    ("aes256User", "SHA", "aes256pass123", "AES256", "privpass123456"),
]
