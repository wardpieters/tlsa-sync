import socket
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from main import Settings, synchronize_all


@pytest.fixture
def ssl_dir(tmp_path, monkeypatch):
    directory = tmp_path / "mailcow-ssl"
    directory.mkdir()
    monkeypatch.setenv("MAILCOW_SSL_DIR", str(directory))
    monkeypatch.delenv("MAILCOW_INSTALL_DIR", raising=False)
    monkeypatch.setenv("DOMAIN_LIST", "mail.example.com,smtp.example.com")
    monkeypatch.setenv("DESEC_ZONE", "example.com")
    monkeypatch.setenv("DESEC_TOKEN", "test-token")
    monkeypatch.delenv("DNS_SERVER", raising=False)
    return directory


def certificate_and_key():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.com")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM), key


def write_ssl_files(directory):
    certificate, key = certificate_and_key()
    additional_certificate, _ = certificate_and_key()
    (directory / "nochain.pem").write_bytes(certificate)
    (directory / "cert.pem").write_bytes(certificate + additional_certificate)
    (directory / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_key = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return (f"3 1 1 {sha256(public_key).hexdigest()}",)


def test_sync_reads_current_pems_without_dns(ssl_dir, monkeypatch):
    def reject_lookup(*args, **kwargs):
        pytest.fail("TLSA generation attempted DNS resolution")

    monkeypatch.setattr(socket, "getaddrinfo", reject_lookup)
    settings = Settings.from_environment()
    client = Mock()

    previous = None
    for _ in range(2):
        records = write_ssl_files(ssl_dir)
        assert records != previous
        synchronize_all(settings, client)
        assert [call.args for call in client.upsert_rrset.call_args_list] == [
            ("example.com", "_25._tcp.mail", records, settings.desec_ttl),
            ("example.com", "_25._tcp.smtp", records, settings.desec_ttl),
        ]
        previous = records
        client.reset_mock()


@pytest.mark.parametrize("filename", ["nochain.pem", "key.pem", "cert.pem"])
def test_sync_skips_inconsistent_pems(ssl_dir, filename):
    settings = Settings.from_environment()
    write_ssl_files(ssl_dir)
    original = (ssl_dir / filename).read_bytes()
    write_ssl_files(ssl_dir)
    (ssl_dir / filename).write_bytes(original)
    client = Mock()

    synchronize_all(settings, client)

    client.upsert_rrset.assert_not_called()


def test_sync_skips_missing_leaf(ssl_dir):
    settings = Settings.from_environment()
    write_ssl_files(ssl_dir)
    (ssl_dir / "nochain.pem").unlink()
    client = Mock()

    synchronize_all(settings, client)

    client.upsert_rrset.assert_not_called()
