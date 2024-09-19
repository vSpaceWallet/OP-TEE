import json
from pyld import jsonld
from crypto import CLSignature, BoundBBSSignature, ECDSASignature, SchnorrSignature
from credential_schemas import validate_credential_subject, get_credential_types
from key_manager import KeyManager
import logging
from Crypto.PublicKey import RSA, ECC

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Wallet:
    def __init__(self):
        self.credentials = []
        self.key_manager = KeyManager()
        self.cl_signature = CLSignature()
        self.bound_bbs_signature = BoundBBSSignature()
        self.ecdsa_signature = ECDSASignature()
        self.schnorr_signature = SchnorrSignature()

    def issue_credential(self, data, signature_type="Certifiable Schnorr"):
        if not validate_credential_subject(data["type"], data["credentialSubject"]):
            raise ValueError("Invalid credential subject data")

        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": ["VerifiableCredential", data["type"]],
            "issuer": "https://example.edu/issuers/14",
            "issuanceDate": data["issuanceDate"],
            "credentialSubject": data["credentialSubject"]
        }

        key_type = 'RSA' if signature_type in ['CL', 'BoundBBS'] else 'ECC'
        key_id = self.key_manager.generate_key(key_type)
        key = self.key_manager.get_key(key_id)

        if signature_type == "CL":
            signature = self.cl_signature.sign(json.dumps(credential), key)
            proof_type = "CLSignature2019"
        elif signature_type == "BoundBBS":
            signature = self.bound_bbs_signature.sign(json.dumps(credential), key)
            proof_type = "BoundBBSSignature2020"
        elif signature_type == "ECDSA":
            signature = self.ecdsa_signature.sign(json.dumps(credential), key)
            proof_type = "EcdsaSecp256k1Signature2019"
        elif signature_type == "Certifiable Schnorr":
            private_key_bytes = key.export_key(format='DER')
            private_key_hex = private_key_bytes.hex()
            signature = self.schnorr_signature.sign(json.dumps(credential), private_key_hex)
            proof_type = "CertifiableSchnorrSignature2021"
        else:
            raise ValueError("Unsupported signature type")

        credential["proof"] = {
            "type": proof_type,
            "created": data["issuanceDate"],
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"https://example.edu/issuers/14#{key_id}",
            "signatureValue": signature
        }

        self.credentials.append(credential)
        return credential

    def verify_credential(self, credential):
        signature = credential["proof"]["signatureValue"]
        credential_without_proof = credential.copy()
        del credential_without_proof["proof"]
        
        signature_type = credential["proof"]["type"]
        logger.debug("Verifying credential with signature type: %s", signature_type)
        logger.debug("Full credential to verify: %s", json.dumps(credential, indent=2))
        logger.debug("Signature to verify: %s", signature)

        key_id = credential["proof"]["verificationMethod"].split('#')[-1]
        public_key = self.key_manager.get_public_key(key_id)

        if signature_type == "CLSignature2019":
            is_valid = self.cl_signature.verify(json.dumps(credential_without_proof), signature, public_key)
        elif signature_type == "BoundBBSSignature2020":
            is_valid = self.bound_bbs_signature.verify(json.dumps(credential_without_proof), signature, public_key)
        elif signature_type == "EcdsaSecp256k1Signature2019":
            is_valid = self.ecdsa_signature.verify(json.dumps(credential_without_proof), signature, public_key)
        elif signature_type == "CertifiableSchnorrSignature2021":
            public_key_bytes = public_key.export_key(format='DER')
            public_key_hex = public_key_bytes.hex()
            is_valid = self.schnorr_signature.verify(json.dumps(credential_without_proof), signature, public_key_hex)
        else:
            raise ValueError("Unsupported signature type")

        logger.debug("Signature verification result: %s", is_valid)

        if is_valid:
            expanded = jsonld.expand(credential)
            compacted = jsonld.compact(expanded, "https://www.w3.org/2018/credentials/v1")
            
            is_valid = (compacted == credential)
            logger.debug("JSON-LD validation result: %s", is_valid)

            credential_type = credential["type"][1] if len(credential["type"]) > 1 else None
            if credential_type:
                schema_valid = validate_credential_subject(credential_type, credential["credentialSubject"])
                is_valid = is_valid and schema_valid
                logger.debug("Schema validation result: %s", schema_valid)

        return {"verified": is_valid}

    def get_credentials(self):
        return self.credentials

    def get_credential_types(self):
        return get_credential_types()

    def get_credential_by_id(self, credential_id):
        if 0 <= credential_id < len(self.credentials):
            return self.credentials[credential_id]
        return None

    def test_all_signatures(self):
        logger.debug("Testing all signature types")
        test_message = "Test message for all signature types"
        results = {}

        for signature_type in ["CL", "BoundBBS", "ECDSA", "Certifiable Schnorr"]:
            logger.debug(f"Testing {signature_type} signature")
            key_type = 'RSA' if signature_type in ['CL', 'BoundBBS'] else 'ECC'
            key_id = self.key_manager.generate_key(key_type)
            key = self.key_manager.get_key(key_id)
            public_key = self.key_manager.get_public_key(key_id)

            try:
                if signature_type == "CL":
                    signature = self.cl_signature.sign(test_message, key)
                    verification_result = self.cl_signature.verify(test_message, signature, public_key)
                elif signature_type == "BoundBBS":
                    signature = self.bound_bbs_signature.sign(test_message, key)
                    verification_result = self.bound_bbs_signature.verify(test_message, signature, public_key)
                elif signature_type == "ECDSA":
                    signature = self.ecdsa_signature.sign(test_message, key)
                    verification_result = self.ecdsa_signature.verify(test_message, signature, public_key)
                elif signature_type == "Certifiable Schnorr":
                    private_key_bytes = key.export_key(format='DER')
                    private_key_hex = private_key_bytes.hex()
                    public_key_bytes = public_key.export_key(format='DER')
                    public_key_hex = public_key_bytes.hex()
                    signature = self.schnorr_signature.sign(test_message, private_key_hex)
                    verification_result = self.schnorr_signature.verify(test_message, signature, public_key_hex)

                logger.debug(f"Test message: {test_message}")
                logger.debug(f"Generated signature: {signature}")
                logger.debug(f"Verification result: {verification_result}")
                results[signature_type] = verification_result
            except Exception as e:
                logger.error(f"Error testing {signature_type} signature: {str(e)}")
                results[signature_type] = False

        return results
