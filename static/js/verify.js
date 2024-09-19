document.addEventListener('DOMContentLoaded', () => {
    const verifyForm = document.getElementById('verifyForm');
    const verificationResult = document.getElementById('verificationResult');

    verifyForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const credential = document.getElementById('verifyCredential').value;

        try {
            const response = await fetch('/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: credential,
            });

            const result = await response.json();
            verificationResult.innerHTML = `<p>Credential verification result: ${result.verified ? 'Valid' : 'Invalid'}</p>`;
            verificationResult.style.color = result.verified ? 'green' : 'red';
        } catch (error) {
            verificationResult.innerHTML = `<p>Error: ${error.message}</p>`;
            verificationResult.style.color = 'red';
        }
    });
});
