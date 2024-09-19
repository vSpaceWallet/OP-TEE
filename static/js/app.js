document.addEventListener('DOMContentLoaded', () => {
    const issueForm = document.getElementById('issueForm');
    const credentialsList = document.getElementById('credentialsList');
    const credentialTypeSelect = document.getElementById('credentialType');
    const signatureTypeSelect = document.getElementById('signatureType');
    const credentialSubjectTextarea = document.getElementById('credentialSubject');

    const mVACSampleJSON = {
        voterID: "V123456789",
        electionAuthority: "National Election Commission",
        expirationDate: "2025-12-31"
    };

    async function loadCredentialTypes() {
        const response = await fetch('/get_credential_types');
        const types = await response.json();
        const sortedTypes = ['mVAC', 'mDL', 'eID', ...types.filter(type => !['mVAC', 'mDL', 'eID'].includes(type))];
        credentialTypeSelect.innerHTML = sortedTypes.map(type => `<option value="${type}">${type}</option>`).join('');
        
        updateCredentialSubjectPlaceholder();
    }

    function updateCredentialSubjectPlaceholder() {
        if (credentialTypeSelect.value === 'mVAC') {
            credentialSubjectTextarea.value = JSON.stringify(mVACSampleJSON, null, 2);
        } else {
            credentialSubjectTextarea.value = '';
            credentialSubjectTextarea.placeholder = 'Enter credential subject JSON here';
        }
    }

    credentialTypeSelect.addEventListener('change', updateCredentialSubjectPlaceholder);

    async function loadSignatureTypes() {
        const response = await fetch('/get_signature_types');
        const types = await response.json();
        signatureTypeSelect.innerHTML = types.map(type => `<option value="${type}"${type === 'ECDSA' ? ' selected' : ''}>${type}</option>`).join('');
    }

    issueForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const type = credentialTypeSelect.value;
        const signatureType = signatureTypeSelect.value;
        const subject = credentialSubjectTextarea.value;

        try {
            const response = await fetch('/issue', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    type: type,
                    signatureType: signatureType,
                    issuanceDate: new Date().toISOString(),
                    credentialSubject: JSON.parse(subject),
                }),
            });

            const result = await response.json();
            if (result.error) {
                alert(`Error: ${result.error}`);
            } else {
                alert('Credential issued successfully!');
                updateCredentialsList();
            }
        } catch (error) {
            alert(`Error: ${error.message}`);
        }
    });

    async function updateCredentialsList() {
        const response = await fetch('/get_credentials');
        const credentials = await response.json();

        credentialsList.innerHTML = '';
        credentials.forEach((credential, index) => {
            const credentialElement = document.createElement('div');
            credentialElement.classList.add('credential');
            credentialElement.innerHTML = `
                <h3>Credential ${index + 1}</h3>
                <p><strong>Type:</strong> ${credential.type[1]}</p>
                <p><strong>Signature Type:</strong> ${credential.proof.type}</p>
                <pre>${JSON.stringify(credential, null, 2)}</pre>
                <img src="/generate_qr/${index}" alt="Credential QR Code" style="max-width: 100%; height: auto;">
            `;
            credentialsList.appendChild(credentialElement);
        });
    }

    loadCredentialTypes();
    loadSignatureTypes();
    updateCredentialsList();

    const html5QrCode = new Html5Qrcode("qr-reader");
    const qrCodeSuccessCallback = (decodedText, decodedResult) => {
        try {
            const jsonData = JSON.parse(decodedText);
            if (jsonData.credentialSubject) {
                credentialSubjectTextarea.value = JSON.stringify(jsonData.credentialSubject, null, 2);
            } else {
                credentialSubjectTextarea.value = decodedText;
            }
            html5QrCode.stop();
        } catch (error) {
            console.error("Error parsing QR code data:", error);
            alert("Invalid QR code data");
        }
    };
    const config = { fps: 10, qrbox: { width: 250, height: 250 } };

    document.getElementById('scanQRCode').addEventListener('click', () => {
        html5QrCode.start({ facingMode: "environment" }, config, qrCodeSuccessCallback);
    });
});
