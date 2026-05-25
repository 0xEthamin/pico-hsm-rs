#!/usr/bin/env python3
"""Verify the ATECC608B signature off-chip."""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, Prehashed
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Public key from the LATEST get-pubkey --slot 0 call
# REPLACE WITH ACTUAL VALUES.
PUBKEY_X_HEX = "789B31D34359CE3E0A7A264279C1045EE536938B5B0F2A3FB462BD162627BD6D"   # 32 bytes hex
PUBKEY_Y_HEX = "80F0426F0D83CDF44750840B812E4B34708B19635CC4AE7CB57E044B76F89772"   # 32 bytes hex

# Signature components from the sign command output.
R_HEX = "2FE2092F6DA92DBA413E57F23769B5B874A406CA4DCB062236D347BED51378FB"
S_HEX = "A67C45B7EB1BE3A07847283A8C1C3705FAD4D2AA72865E814B1503968155160D"

# The 32-byte challenge that was signed.
CHALLENGE_HEX = "1ac33b35378d30afebb68902d1e8132b9c057f4f7bce7d8a7655057136e90b08"  # 64 hex chars

def main():
    x = int(PUBKEY_X_HEX, 16)
    y = int(PUBKEY_Y_HEX, 16)
    r = int(R_HEX, 16)
    s = int(S_HEX, 16)
    challenge = bytes.fromhex(CHALLENGE_HEX)

    pubkey = ec.EllipticCurvePublicNumbers(
        x, y, ec.SECP256R1()
    ).public_key()

    der_sig = encode_dss_signature(r, s)

    try:
        pubkey.verify(der_sig, challenge,
                      ec.ECDSA(Prehashed(hashes.SHA256())))
        print("Signature VALID")
    except InvalidSignature:
        print("Signature INVALID")

if __name__ == "__main__":
    from cryptography.hazmat.primitives import hashes
    main()
