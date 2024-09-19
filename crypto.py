# pip install ecdsa hashlib logging subprocess
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from ecdsa.util import sigencode_string, sigdecode_string
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256
import hashlib
import logging
import subprocess

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


## BbsBlsSignature[Proof]2020 Status: "unstable" (deprecated)!
## https://github.com/mattrglobal/jsonld-signatures-bbs/issues/93
## https://identity.foundation/bbs-signature/draft-blind-bbs-signatures.html
## https://github.com/mattrglobal/jsonld-signatures-bbs/blob/master/sample/ts-node/src/data/bbs.json#L7C15-L7C60
class BoundBBSSignature:

    def sign(self, message, key):
        # Implement BoundBBS signing
        # This is a placeholder implementation
        return "BoundBBS_" + message.encode('utf-8').hex()

    def verify(self, message, signature, public_key):
        # Implement BoundBBS verification
        # This is a placeholder implementation
        return signature.startswith(
            "BoundBBS_") and signature[9:] == message.encode('utf-8').hex()


## https://github.com/hyperledger-archives/indy-anoncreds/blob/master/anoncreds/test/test_anoncred_usage.py
## https://github.com/hyperledger-archives/indy-anoncreds/blob/master/anoncreds/protocol/wallet/wallet.py
class CLSignature:

    def sign(self, message, key):
        hash = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(key).sign(hash)
        return signature.hex()

    def verify(self, message, signature, public_key):
        hash = SHA256.new(message.encode('utf-8'))
        try:
            pkcs1_15.new(RSA.import_key(public_key)).verify(
                hash, bytes.fromhex(signature))
            return True
        except (ValueError, TypeError):
            return False


class SchnorrSignature:

    def sign(self, message, private_key_hex):
        message_hash = hashlib.sha256(message.encode('utf-8')).digest()

        # Extract the 32-byte private key from the DER format
        private_key_bytes = bytes.fromhex(private_key_hex)
        if len(private_key_bytes) != 32:
            der = ECC.import_key(private_key_bytes)
            private_key_bytes = der.d.to_bytes(32, 'big')

        sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        signature = sk.sign(message_hash)

        logger.debug("Message to sign: %s", message)
        logger.debug("Generated hash: %s", message_hash.hex())
        logger.debug("Private key length: %d", len(private_key_bytes))
        logger.debug("Schnorr Signature generated for message: %s", message)
        logger.debug("Signature: %s", signature.hex())

        return signature.hex()

    def verify(self, message, signature_hex, public_key_hex):
        message_hash = hashlib.sha256(message.encode('utf-8')).digest()

        vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex),
                                      curve=SECP256k1)

        logger.debug("Message to verify: %s", message)
        logger.debug("Generated hash: %s", message_hash.hex())
        logger.debug("Public key used for verification: %s", public_key_hex)
        logger.debug("Signature to verify: %s", signature_hex)

        try:
            vk.verify(bytes.fromhex(signature_hex), message_hash)
            logger.debug(
                "Schnorr Signature verified successfully for message: %s",
                message)
            return True
        except BadSignatureError as e:
            logger.error(
                "Schnorr Signature verification failed for message: %s",
                message)
            logger.error("Error: %s", str(e))
            return False


# ECDSA (curve=SECP256k1) # !(FIPS-186-3)
class ECDSASignature:

    # def sign(self, message, private_key_hex):
    def sign(self, message, private_key):
        # Create a hash of the message
        message_hash = hashlib.sha256(message.encode('utf-8')).digest()

        # Generate a signing key from the private key
        # sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        # Convert EccKey to ecdsa SigningKey
        sk = SigningKey.from_string(private_key.d.to_bytes(32, 'big'),
                                    curve=SECP256k1)

        # Sign the hash
        # signature = sk.sign(message_hash)
        signature = sk.sign(message_hash, sigencode=sigencode_string)

        logger.debug("Message to sign: %s", message)
        logger.debug("Generated hash: %s", message_hash.hex())
        logger.debug("ECDSA Signature generated for message: %s", message)
        logger.debug("Signature: %s", signature.hex())

        return signature.hex()

    # def verify(self, message, signature_hex, public_key_hex):
    def verify(self, message, signature_hex, public_key):
        # Create a hash of the message
        message_hash = hashlib.sha256(message.encode('utf-8')).digest()

        # Generate a verifying key from the public key
        # vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
        # Convert EccKey to ecdsa VerifyingKey
        vk = VerifyingKey.from_string(
            public_key.point.x().to_bytes(32, 'big') +
            public_key.point.y().to_bytes(32, 'big'),
            curve=SECP256k1)

        logger.debug("Message to verify: %s", message)
        logger.debug("Generated hash: %s", message_hash.hex())
        # logger.debug("Public key used for verification: %s", public_key_hex)
        logger.debug("Signature to verify: %s", signature_hex)

        try:
            # Verify the signature
            # vk.verify(bytes.fromhex(signature_hex), message_hash)
            vk.verify(bytes.fromhex(signature_hex),
                      message_hash,
                      sigdecode=sigdecode_string)
            logger.debug(
                "ECDSA Signature verified successfully for message: %s",
                message)
            return True
        except BadSignatureError as e:
            logger.error("ECDSA Signature verification failed for message: %s",
                         message)
            logger.error("Error: %s", str(e))
            return False


# Example usage:
# ecdsa_sig = ECDSASignature()
# private_key = ECC.generate(curve='P-256')
# public_key = private_key.public_key()
# signed_message = ecdsa_sig.sign('Hello World', private_key)
# is_verified = ecdsa_sig.verify('Hello World', signed_message, public_key)

# # ECDSA (FIPS-186-3) # !(curve=SECP256k1)
# class ECDSASignature:
# def sign(self, message, key):
# hash = SHA256.new(message.encode('utf-8'))
# signer = DSS.new(key, 'fips-186-3')
# signature = signer.sign(hash)
# logger.debug("Message to sign: %s", message)
# logger.debug("Generated hash: %s", hash.hexdigest())
# logger.debug("Public key used for signing: %s", key.public_key().export_key(format='PEM'))
# logger.debug("ECDSA Signature generated for message: %s", message)
# logger.debug("Signature: %s", signature.hex())
# return signature.hex()

# def verify(self, message, signature, public_key):
# hash = SHA256.new(message.encode('utf-8'))
# verifier = DSS.new(ECC.import_key(public_key), 'fips-186-3')
# logger.debug("Message to verify: %s", message)
# logger.debug("Generated hash: %s", hash.hexdigest())
# logger.debug("Public key used for verification: %s", public_key)
# logger.debug("Signature to verify: %s", signature)
# try:
# verifier.verify(hash, bytes.fromhex(signature))
# logger.debug("ECDSA Signature verified successfully for message: %s", message)
# return True
# except ValueError as e:
# logger.error("ECDSA Signature verification failed for message: %s", message)
# logger.error("Error: %s", str(e))
# return False
