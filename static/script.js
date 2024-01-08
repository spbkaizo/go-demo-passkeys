// Utility functions for encoding and decoding ArrayBuffer to Base64
function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)));
}

function bufferDecode(value) {
    // Convert URL-safe base64 to regular base64
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if necessary
    const padding = '='.repeat((4 - base64.length % 4) % 4);
    const paddedBase64 = base64 + padding;

    // Decode base64 string
    const rawData = window.atob(paddedBase64);
    const outputArray = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray.buffer;
}

// Register a new WebAuthn credential
async function register() {
    try {
        const response = await fetch('/register');
        const options = await response.json();

        console.log("Received registration options:", options);

        // Extracting publicKey options
        const publicKeyOptions = options.publicKey;

        if (!publicKeyOptions.challenge) {
            console.error("Challenge is undefined", publicKeyOptions);
            return; // Stop further execution if challenge is undefined
        }

        if (!publicKeyOptions.user || !publicKeyOptions.user.id) {
            console.error("User ID is undefined", publicKeyOptions);
            return; // Stop further execution if user ID is undefined
        }

        console.log("Decoding challenge:", publicKeyOptions.challenge);
        publicKeyOptions.challenge = bufferDecode(publicKeyOptions.challenge);

        console.log("Decoding user ID:", publicKeyOptions.user.id);
        publicKeyOptions.user.id = bufferDecode(publicKeyOptions.user.id);

        // Call WebAuthn API
        const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });

        // Convert credential into a format that can be sent to the server
        const credentialForServer = {
            id: credential.id,
            rawId: bufferEncode(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferEncode(credential.response.attestationObject),
                clientDataJSON: bufferEncode(credential.response.clientDataJSON)
            }
        };

        // Send the credential to the server for verification and storage
        await fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(credentialForServer)
        });

        alert('Registration successful');
    } catch (err) {
        console.error(err);
        alert('Registration failed');
    }
}

// Login using an existing WebAuthn credential
async function login() {
    try {
        const response = await fetch('/login');
        const options = await response.json();

        console.log("Received login options:", options);

        const publicKeyOptions = options.publicKey;

        if (!publicKeyOptions.challenge) {
            console.error("Challenge is undefined", publicKeyOptions);
            return; // Stop further execution if challenge is undefined
        }

        // Convert challenge from Base64 to ArrayBuffer
        publicKeyOptions.challenge = bufferDecode(publicKeyOptions.challenge);

        // Call WebAuthn API
        const assertion = await navigator.credentials.get({ publicKey: publicKeyOptions });

        // Convert assertion into a format that can be sent to the server
        const assertionForServer = {
            id: assertion.id,
            rawId: bufferEncode(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferEncode(assertion.response.authenticatorData),
                clientDataJSON: bufferEncode(assertion.response.clientDataJSON),
                signature: bufferEncode(assertion.response.signature),
                userHandle: bufferEncode(assertion.response.userHandle),
            }
        };

        // Send the assertion to the server for verification
        await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(assertionForServer)
        });

        alert('Login successful');
    } catch (err) {
        console.error(err);
        alert('Login failed');
    }
}

