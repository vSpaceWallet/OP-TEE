from flask import Flask, render_template, request, jsonify, session, send_file
from wallet import Wallet
import json
import qrcode
from io import BytesIO
import logging
from webauthn import generate_registration_options, verify_registration_response
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement, PublicKeyCredentialCreationOptions
import base64
import os
import secrets

app = Flask(__name__)
app.secret_key = os.urandom(24)
wallet = Wallet()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/passkey_auth')
def passkey_auth():
    return render_template('passkey_auth.html')

@app.route('/issue', methods=['POST'])
def issue_credential():
    data = request.json
    try:
        signature_type = data.get('signatureType', 'Certifiable Schnorr')
        logger.info(f"Issuing credential with signature type: {signature_type}")
        
        if signature_type == "Certifiable Schnorr":
            logger.debug("Starting Certifiable Schnorr signature process")
            try:
                credential = wallet.issue_credential(data, signature_type)
                logger.debug("Certifiable Schnorr signature created successfully")
            except Exception as e:
                logger.error(f"Error creating Certifiable Schnorr signature: {str(e)}", exc_info=True)
                return jsonify({"error": f"Error creating Certifiable Schnorr signature: {str(e)}"}), 500
        else:
            credential = wallet.issue_credential(data, signature_type)
        
        logger.info("Credential issued successfully")
        return jsonify(credential)
    except Exception as e:
        logger.error(f"Error issuing credential: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/get_credentials', methods=['GET'])
def get_credentials():
    credentials = wallet.get_credentials()
    return jsonify(credentials)

@app.route('/get_credential_types', methods=['GET'])
def get_credential_types():
    types = wallet.get_credential_types()
    return jsonify(types)

@app.route('/get_signature_types', methods=['GET'])
def get_signature_types():
    signature_types = ["Certifiable Schnorr", "BoundBBS", "CL", "ECDSA"]
    return jsonify(signature_types)

@app.route('/generate_qr/<int:credential_id>')
def generate_qr(credential_id):
    try:
        credential = wallet.get_credential_by_id(credential_id)
        if not credential:
            return jsonify({"error": "Credential not found"}), 404
        
        target_size = 288  # 3 inches at 96 DPI
        qr = qrcode.QRCode(version=None, box_size=10, border=4)
        qr.add_data(json.dumps(credential))
        qr.make(fit=True)
        
        size = (qr.modules_count + qr.border * 2) * qr.box_size
        if size > target_size:
            scale_factor = target_size / size
            new_box_size = max(1, int(qr.box_size * scale_factor))
            new_border = max(0, int(qr.border * scale_factor))
            qr = qrcode.QRCode(version=None, box_size=new_box_size, border=new_border)
            qr.add_data(json.dumps(credential))
            qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        return send_file(img_io, mimetype='image/png')
    except Exception as e:
        logger.error(f"Error generating QR code: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to generate QR code"}), 500

@app.route('/generate-registration-options', methods=['POST'])
def generate_registration_options_route():
    try:
        username = request.json.get('username')
        if not username:
            logger.error("Username is required but not provided")
            return jsonify({"error": "Username is required"}), 400

        logger.info(f"Generating registration options for user: {username}")
        
        options = generate_registration_options(
            rp_id=request.host.split(':')[0],
            rp_name="W3C Verifiable Credentials Wallet",
            user_id=secrets.token_bytes(32),
            user_name=username,
            user_display_name=username,
            attestation="direct",
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED
            ),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
            ]
        )

        logger.debug(f"Generated options: {options}")
        
        session['registration_challenge'] = options.challenge

        options_dict = {
            'rp': {
                'name': options.rp.name,
                'id': options.rp.id
            },
            'user': {
                'id': base64.b64encode(options.user.id).decode('utf-8'),
                'name': options.user.name,
                'displayName': options.user.display_name
            },
            'challenge': base64.b64encode(options.challenge).decode('utf-8'),
            'pubKeyCredParams': [{'type': 'public-key', 'alg': alg} for alg in options.pub_key_cred_params],
            'timeout': options.timeout,
            'excludeCredentials': options.exclude_credentials,
            'authenticatorSelection': {
                'requireResidentKey': options.authenticator_selection.require_resident_key,
                'userVerification': options.authenticator_selection.user_verification
            },
            'attestation': options.attestation
        }

        logger.info("Registration options generated successfully")
        return jsonify(options_dict)
    except Exception as e:
        logger.error(f"Error generating registration options: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route('/verify-registration', methods=['POST'])
def verify_registration_route():
    try:
        credential = request.json
        challenge = session.get('registration_challenge')
        
        if not challenge:
            logger.error("No challenge found in session")
            return jsonify({"error": "No challenge found"}), 400

        logger.info(f"Verifying registration for credential: {credential['id']}")

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=f"{request.scheme}://{request.host}",
            expected_rp_id=request.host.split(':')[0]
        )

        logger.info(f"Verification result: {verification}")
        
        # Here you would typically store the verified credential
        # For this demo, we'll just return a success message
        return jsonify({"success": True, "message": "Registration successful"})
    except Exception as e:
        logger.error(f"Error in verify_registration: {str(e)}")
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    signature_test_results = wallet.test_all_signatures()
    logger.debug(f"Signature Test Results: {signature_test_results}")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
