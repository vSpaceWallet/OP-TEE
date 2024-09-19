// Check for WebAuthn support
if (!window.PublicKeyCredential) {
    console.error('WebAuthn is not supported in this browser.');
    alert('WebAuthn is not supported in this browser. Please use a modern browser that supports WebAuthn.');
}

async function registerPasskey() {
    try {
        const username = prompt("Enter your username:");
        if (!username) {
            console.error("Username is required");
            throw new Error("Username is required");
        }

        console.log("Requesting registration options from server...");
        const response = await fetch('/generate-registration-options', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username }),
        });

        if (!response.ok) {
            console.error(`Server responded with status: ${response.status}`);
            throw new Error(`Server responded with status: ${response.status}`);
        }

        const options = await response.json();
        console.log("Received registration options:", options);

        options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
        options.user.id = Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0));

        console.log("Creating credentials...");
        const abortController = new AbortController();
        const timeoutId = setTimeout(() => abortController.abort(), 60000); // 60 second timeout

        const credential = await navigator.credentials.create({
            publicKey: options,
            signal: abortController.signal
        }).finally(() => clearTimeout(timeoutId));

        console.log("Credentials created:", credential);

        const credentialResponse = {
            id: credential.id,
            rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.rawId))),
            response: {
                clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.response.clientDataJSON))),
                attestationObject: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.response.attestationObject))),
            },
            type: credential.type,
        };

        console.log("Sending credential to server for verification...");
        const verificationResponse = await fetch('/verify-registration', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(credentialResponse),
        });

        if (!verificationResponse.ok) {
            console.error(`Server responded with status: ${verificationResponse.status}`);
            throw new Error(`Server responded with status: ${verificationResponse.status}`);
        }

        const verificationResult = await verificationResponse.json();
        if (verificationResult.success) {
            console.log("Passkey registered successfully!");
            alert('Passkey registered successfully!');
        } else {
            console.error('Failed to verify the registration');
            throw new Error('Failed to verify the registration');
        }
    } catch (error) {
        console.error('Error during registration:', error);
        alert(`Registration failed: ${error.message}`);
    }
}

document.getElementById('register').addEventListener('click', registerPasskey);

document.getElementById('login').addEventListener('click', () => {
    console.log('Login button clicked');
    alert('Login functionality not implemented yet');
});
