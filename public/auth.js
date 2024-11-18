
const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

// define the registration button click event
const registerButton = document.getElementById('registerBtn');
const loginButton = document.getElementById('loginBtn');

const elemSuccess = document.getElementById('success');
const elemError = document.getElementById('error');
const username = document.getElementById('username');
registerButton.addEventListener('click', async () => {

    elemSuccess.innerHTML = '';
    elemError.innerHTML = '';

    // GET registration options from the endpoint that calls
    // @simplewebauthn/server -> generateRegistrationOptions()
    const resp = await fetch(`/generate-registration-options?userName=${username.value}`);
    if (resp.status !== 200) {
        elemError.innerText = 'Error: ' + (await resp.json()).error;
        return;
    }


    const optionsJSON = await resp.json();


    let attResp;
    try {
        // Pass the options to the authenticator and wait for a response
        attResp = await startRegistration({ optionsJSON });

    } catch (error) {
        // Some basic error handling
        if (error.name === 'InvalidStateError') {
            elemError.innerText = 'Error: Authenticator was probably already registered by user';
        } else {
            elemError.innerText = error;
        }

        throw error;
    }

    // POST the response to the endpoint that calls
    // @simplewebauthn/server -> verifyRegistrationResponse()
    const verificationResp = await fetch('/verify-registration', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userName: username.value, ...attResp })
    });

    // Wait for the results of verification
    const verificationJSON = await verificationResp.json();

    // Show UI appropriate for the `verified` status
    if (verificationJSON && verificationJSON.verified) {
        elemSuccess.innerHTML = 'Success!';
    } else {
        elemError.innerHTML = `Oh no, something went wrong! Response: <pre>${JSON.stringify(
            verificationJSON,
        )}</pre>`;
    }
});


loginButton.addEventListener('click', async () => {

    elemSuccess.innerHTML = '';
    elemError.innerHTML = '';

    // GET authentication options from the endpoint that calls
    // @simplewebauthn/server -> generateAuthenticationOptions()
    const resp = await fetch('/generate-authentication-options?userName=' + username.value);
    if (resp.status !== 200) {
        elemError.innerText = 'Error: ' + (await resp.json()).error;
        return;
    }
    const optionsJSON = await resp.json();

    let attResp;
    try {
        // Pass the options to the authenticator and wait for a response
        attResp = await startAuthentication({ optionsJSON });
    } catch (error) {
        // Some basic error handling
        elemError.innerText = error;
        throw error;
    }

    // POST the response to the endpoint that calls
    // @simplewebauthn/server -> verifyAuthenticationResponse()
    const verificationResp = await fetch('/verify-authentication', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userName: username.value, ...attResp })
    });


    // Wait for the results of verification
    const verificationJSON = await verificationResp.json();

    // Show UI appropriate for the `verified` status
    if (verificationJSON && verificationJSON.verified) {
        elemSuccess.innerHTML = 'Success!';
    } else {
        elemError.innerHTML = `Oh no, something went wrong! Response: <pre>${JSON.stringify(
            verificationJSON,
        )}</pre>`;
    }
}
);