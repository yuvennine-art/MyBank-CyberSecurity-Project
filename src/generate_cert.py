import os
import ipaddress
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_self_signed_cert():
    # Create a directory to store certificates
    certs_dir = "certs"
    if not os.path.exists(certs_dir):
        os.makedirs(certs_dir)

    now = datetime.datetime.now(datetime.timezone.utc)

    # ---------------------------------
    # 1. Generate CA Private Key and Self-Signed Certificate
    # ---------------------------------
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    ca_subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.POSTAL_CODE, u"CV12JN"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Coventry"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyBank CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"MyBank CA"),
    ])
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256())

    with open(os.path.join(certs_dir, "ca.crt"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(certs_dir, "ca.key"), "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("CA certificate and private key generated.")

    # ---------------------------------
    # 2. Generate `main.py` Client Certificate and Private Key
    # ---------------------------------
    main_client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    main_client_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.POSTAL_CODE, u"CV12JN"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Coventry"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyBank Main Client"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"main.mybank.example.com"),
    ])
    main_client_cert = x509.CertificateBuilder().subject_name(
        main_client_subject
    ).issuer_name(
        ca_subject  # Signed by CA
    ).public_key(
        main_client_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256())

    with open(os.path.join(certs_dir, "main_client.crt"), "wb") as f:
        f.write(main_client_cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(certs_dir, "main_client.key"), "wb") as f:
        f.write(main_client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("Main client certificate and private key generated.")

    # ---------------------------------
    # 3. Generate Server Certificate and Private Key
    # ---------------------------------
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.POSTAL_CODE, u"CV12JN"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Coventry"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyBank Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"server.mybank.example.com"),
    ])
    server_cert = x509.CertificateBuilder().subject_name(
        server_subject
    ).issuer_name(
        ca_subject  # Signed by CA
    ).public_key(
        server_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        ]),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256())

    with open(os.path.join(certs_dir, "server.crt"), "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(certs_dir, "server.key"), "wb") as f:
        f.write(server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("Server certificate and private key generated.")

if __name__ == "__main__":
    generate_self_signed_cert()
