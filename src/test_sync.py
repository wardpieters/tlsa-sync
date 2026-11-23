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


def certificate_and_key(common_name="mail.example.com", issuer=None, *, ca=False):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer_name, signing_key = (name, key) if issuer is None else (issuer[0].subject, issuer[1])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(signing_key, hashes.SHA256())
    )
    return certificate, key


def write_ssl_files(directory, issuer=None, chain=()):
    certificate, key = certificate_and_key(issuer=issuer)
    fullchain = b"".join(
        cert.public_bytes(serialization.Encoding.PEM) for cert in (certificate, *chain)
    )
    (directory / "cert.pem").write_bytes(fullchain)
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
    anchor, anchor_key = certificate_and_key("Test root CA", ca=True)
    unrelated_ca, _ = certificate_and_key("Test root CA", ca=True)
    backup = f"2 0 1 {anchor.fingerprint(hashes.SHA256()).hex()}"

    previous = None
    for _ in range(2):
        issuer = certificate_and_key("Test intermediate", issuer=(anchor, anchor_key), ca=True)
        records = (*write_ssl_files(ssl_dir, issuer, (issuer[0], anchor, unrelated_ca)), backup)
        assert records != previous
        synchronize_all(settings, client)
        assert [call.args for call in client.upsert_rrset.call_args_list] == [
            ("example.com", "_25._tcp.mail", records, settings.desec_ttl),
            ("example.com", "_25._tcp.smtp", records, settings.desec_ttl),
        ]
        previous = records
        client.reset_mock()


@pytest.mark.parametrize("include_unrelated_ca", [False, True], ids=["leaf-only", "unrelated-ca"])
def test_sync_uses_leaf_only_without_a_usable_ca(ssl_dir, include_unrelated_ca):
    settings = Settings.from_environment()
    unrelated_ca, _ = certificate_and_key("Unrelated CA", ca=True)
    chain = (unrelated_ca,) if include_unrelated_ca else ()
    records = write_ssl_files(ssl_dir, chain=chain)
    client = Mock()

    synchronize_all(settings, client)

    assert [call.args[2] for call in client.upsert_rrset.call_args_list] == [records, records]


@pytest.mark.parametrize("filename", ["key.pem", "cert.pem"])
def test_sync_skips_inconsistent_pems(ssl_dir, filename):
    settings = Settings.from_environment()
    write_ssl_files(ssl_dir)
    original = (ssl_dir / filename).read_bytes()
    write_ssl_files(ssl_dir)
    (ssl_dir / filename).write_bytes(original)
    client = Mock()

    synchronize_all(settings, client)

    client.upsert_rrset.assert_not_called()


@pytest.mark.parametrize("filename", ["key.pem", "cert.pem"])
def test_sync_skips_missing_pem(ssl_dir, filename):
    settings = Settings.from_environment()
    write_ssl_files(ssl_dir)
    (ssl_dir / filename).unlink()
    client = Mock()

    synchronize_all(settings, client)

    client.upsert_rrset.assert_not_called()
