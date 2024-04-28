# WebAuthn Implementation Lab Guide

In this lab, you will set up a WebAuthn-enabled server and client. WebAuthn allows for secure passwordless authentication using public key cryptography.

## Prerequisites

- Node.js installed on your machine

## Step 1: Setup Your Project

Start by setting up your Node.js environment and installing necessary packages.

```bash
# Initialize a new Node.js project
npm install
```

this will install: express body-parser @simplewebauthn/server base64url sqlite3

After installation is completed, run this command

```bash
# Initialize a new Node.js project
npm run start
```

Then open [http://localhost:3000 ](http://localhost:3000)

## Step 2 Add the registeration UI:

Add this code to public/index.html inside the body

```html
<div>
    <input type="text" id="username" placeholder="Username" autocomplete ="webauthn">
    <button id="registerBtn">Register</button>
</div>
<script src="./auth.js" type="module"></script>
```

Go check [http://localhost:3000 ](http://localhost:3000) and try to register.

The button is not working, right? that becuase we do not have code inside ``auth.js``

## Step 3 Add the client registeration handler

Add this code to public/auth.js

```js
import {
  startRegistration,
  startAuthentication,
} from 'https://cdn.skypack.dev/@simplewebauthn/browser';

export async function register() {
  const username = document.getElementById('username').value;

  // Begin registration process to get options
  let optionsRes = await fetch('/register/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username }),
  });

  let options = await optionsRes.json();
  if (options.error) {
    return alert(options.error);
  }

  // Use @simplewebauthn/browser to start registration
  let attestation = await startRegistration(options);

  // Send attestation response to server
  let verificationRes = await fetch('/register/finish', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username,
      attestationResponse: attestation,
    }),
  });
  let verificationResult = await verificationRes.json();

  alert(`Registration ${verificationResult ? 'successful' : 'failed'}`);
}
document.getElementById('registerBtn').addEventListener('click', register);

```

### Here's a detailed explanation of each part of this code:

```js
import {
  startRegistration,
  startAuthentication,
} from 'https://cdn.skypack.dev/@simplewebauthn/browser';
```

This line imports two functions from the @simplewebauthn/browser package hosted on Skypack, a CDN for npm packages. startRegistration is used for initiating the registration process, and startAuthentication is for the login process. However, only startRegistration is used in this snippet.

```js
export async function register() {
```

This line defines an asynchronous function named register, which is exported so it can be used index.html

```js
const username = document.getElementById('username').value;
```

This retrieves the value entered in an HTML input element with the ID username.

```js
let optionsRes = await fetch('/register/start', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ username }),
});
```

This asynchronous request is made to the server at the endpoint `/register/start`. It sends the username as a JSON payload using POST. The server is expected to respond with registration options required to begin the WebAuthn registration process.

```js
let options = await optionsRes.json();
if (options.error) {
  return alert(options.error);
}
```

After receiving the response from the server, the code converts the response to JSON. If the response contains an error, it alerts the user with the error message and exits the function.

```js
let attestation = await startRegistration(options);
```

Using the registration options received from the server, this line calls the startRegistration function from the @simplewebauthn/browser library. This function interacts with the user's browser and potentially their authenticator device (like a security key or biometric device) to create a new credential. It returns an attestation object, which includes cryptographic proof of the new credential's creation.

```js
let verificationRes = await fetch('/register/finish', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    username,
    attestationResponse: attestation,
  }),
});
```

This block sends the attestation response back to the server to the /register/finish endpoint. The server will then verify the attestation response to ensure it is valid and register the new credential associated with the user.

```js
let verificationResult = await verificationRes.json();
alert(`Registration ${verificationResult ? 'successful' : 'failed'}`);
```

Finally, this code parses the response from the /register/finish endpoint. It checks if the registration was successful based on the server's response and alerts the user accordingly.
*Note:* in somecase, you may need to redirect the user to other pages instead of showing alert.

## Step 4 Handeling registeration request inside server

First setup the `server.js` file by adding this code:

```js
import express from 'express';
import bodyParser from 'body-parser';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import base64url from 'base64url';
import { signin, signup } from './db/db.mjs';

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

const PORT = 3000;
const rpID = 'localhost'; // Relying Party Identifier
const expectedOrigin = 'http://localhost:' + PORT;

app.listen(PORT, () => {
    console.log('Server listening on port ' + PORT);
});
```

Now handel the registeration request that comes from the client by adding this code:

```js
// Endpoint to start the registration process
app.post('/register/start', async (req, res) => {
  // Extract username from request body
  const { username } = req.body;
  if (!username) {
    return res.status(400).send({ error: 'Username is required' });
  }

  // Check if user already exists
  const user = await signin(username);
  if (user) {
    return res.status(400).send({ error: 'User already exists' });
  }

  // Generate registration options
  const registrationOptions = await generateRegistrationOptions({
    rpName: 'Future Of Authentication',
    rpID,
    userID: base64url(Buffer.from(username)),
    userName: username,
    timeout: 60000, // Timeout for the request in milliseconds
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  // Store the challenge temporarily for verification in the next step
  authenticators[username] = {
    challenge: registrationOptions.challenge,
  };

  // Send registration options to the client
  return res.send(registrationOptions);
});

// Endpoint to finish the registration process
app.post('/register/finish', async (req, res) => {
  const { username, attestationResponse } = req.body;

  // Retrieve the stored challenge from the 'authenticators' object
  const expectedChallenge = authenticators[username].challenge;

  let verification;
  try {
    // Verify the registration response
    verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  // Check if verification was successful
  const { verified } = verification;
  if (verified) {
    // Prepare user data for storage
    const user = {
      devices:[{
        credentialPublicKey: base64url.encode(verification.registrationInfo.credentialPublicKey),
        credentialID: base64url.encode(verification.registrationInfo.credentialID),
        transports: attestationResponse.response.transports,
      }],
      userID: base64url(Buffer.from(username)),
      userName: username,
    };

    // Remove the temporary authenticator
    authenticators[username] = undefined;

    try {
      // Store the user in the database
      await signup(username, user);
    }
    catch (error) {
      return res.status(400).send({ error: error.message });
    }

    // Send verification result to the client
    return res.send({ verified });
  } else {
    return res.status(400).send({ error: 'Unable to verify registration' });
  }
});
```

### Here's a detailed explanation of each part of this code:

Part 1: Start Registration Endpoint

```js
app.post('/register/start', async (req, res) => {
  // Extract username from request body
  const { username } = req.body;
  if (!username) {
    return res.status(400).send({ error: 'Username is required' });
  }

  // Check if user already exists
  const user = await signin(username);
  if (user) {
    return res.status(400).send({ error: 'User already exists' });
  }

  // Generate registration options
  const registrationOptions = await generateRegistrationOptions({
    rpName: 'Future Of Authentication',
    rpID,
    userID: base64url(Buffer.from(username)),
    userName: username,
    timeout: 60000,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  // Store the challenge temporarily for verification in the next step
  authenticators[username] = {
    challenge: registrationOptions.challenge,
  };

  // Send registration options to the client
  return res.send(registrationOptions);
});
```

* **Extract username:** This code checks the incoming request for a username and responds with an error if it's not provided.
* **User existence check:** It checks if a user with the provided username already exists in the system (using a hypothetical signin function), returning an error if the user exists.
* **Generate registration options:** Utilizes the generateRegistrationOptions function from @simplewebauthn/server to prepare the data needed by the client's browser to begin the registration process. These options include the Relying Party (RP) identifier, user details, and cryptographic preferences.
* **Store challenge:** The WebAuthn protocol uses challenges to prevent replay attacks. Here, the challenge generated as part of the registration options is stored temporarily (ideally, this should be in a more secure storage or session).
* **Send registration options:** The server sends these options back to the client to initiate the credential creation process on the user's authenticator (e.g., YubiKey, Windows Hello).

Part 2: Finish Registration Endpoint

```js
app.post('/register/finish', async (req, res) => {
  const { username, attestationResponse } = req.body;

  // Retrieve the stored challenge from the 'authenticators' object
  const expectedChallenge = authenticators[username].challenge;

  let verification;
  try {
    // Verify the registration response
    verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  // Check if verification was successful
  const { verified } = verification;
  if (verified) {
    // Prepare user data for storage
    const user = {
      devices: [{
        credentialPublicKey: base64url.encode(verification.registrationInfo.credentialPublicKey),
        credentialID: base64url.encode(verification.registrationInfo.credentialID),
        transports: attestationResponse.response.transports,
      }],
      userID: base64url(Buffer.from(username)),
      userName: username,
    };

    // Remove the temporary authenticator
    authenticators[username] = undefined;

    try {
      // Store the user in the database
      await signup(username, user);
    }
    catch (error) {
      return res.status(400).send({ error: error.message });
    }

    // Send verification result to the client
    return res.send({ verified });
  } else {
    return res.status(400).send({ error: 'Unable to verify registration' });
  }
});
```

* **Retrieve attestation response and challenge**: This endpoint receives the attestation response from the client (which includes the newly created credential details) and retrieves the expected challenge stored earlier.
* **Verify registration response**: Using verifyRegistrationResponse, it checks the authenticity and integrity of the attestation response against the expected values.
* **Store user credentials**: If the verification is successful, it encodes and stores the credential details. These details are necessary for future authentications.
* **Clean up and respond**: Removes the stored challenge as it is no longer needed and returns the result of the verification to the client.


## Step 5 setting up the database

Add this code inside db/db.mjs

```js
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

// Open the SQLite Database
async function openDb() {
    return open({
        filename: './db/users.db',
        driver: sqlite3.Database
    });
}

// Create table (if not exists)
async function setupDb() {
    const db = await openDb();
    await db.exec(`CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        user_webauthen_data TEXT
    )`);
    await db.close();
}

// Function to get user by username
async function getUser(username) {
    const db = await openDb();
    const user = await db.get(`SELECT user_webauthen_data FROM users WHERE username = ?`, [username]);
    await db.close();
    return user ? JSON.parse(user.user_webauthen_data) : null;
}

// Function to add a new user
async function addUser(username, user) {
    const db = await openDb();
    const existingUser = await getUser(username);
    if (existingUser) {
        throw Error('username already exists');
    }
    await db.run(`INSERT INTO users (username, user_webauthen_data) VALUES (?, ?)`, [username, JSON.stringify(user)]);
    await db.close();
}

export async function signup(username, user) {
    await addUser(username, user);
}

export async function signin(username) {
    return await getUser(username);
}

// Setup database tables on startup
setupDb();
```

## Step 6 Testing user registeration
Now go to [http://localhost:3000 ](http://localhost:3000 ) and register a user. Then check the database to see the data that was saved.

## Step 7 Adding login button
Go back to the public/index.html add a login button

```html
  <div>
    <input type="text" id="username" placeholder="Username" autocomplete ="webauthn">
    <button id="registerBtn">Register</button>
    <!-- Add this button -->
    <button id="loginBtn">Login</button> 
    <!--  -->
  </div>

  <script src="./auth.js" type="module"></script>
```

## Step 8 Adding login handler in the client
Inside the `auth.js` add the login handler 

```js 
export async function login() {
  const username = document.getElementById('username').value;

  // Begin authentication process to get options
  let optionsRes = await fetch('/login/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username }),
  });
  let options = await optionsRes.json();

  if (options.error) {
    return alert(options.error);
  }

  // Use @simplewebauthn/browser to start authentication
  console.log(options);

  let assertion = await startAuthentication(options);

  // Send assertion response to server
  let verificationRes = await fetch('/login/finish', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username,
      assertionResponse: assertion,
    }),
  });
  let verificationResult = await verificationRes.json();

  alert(`Login ${verificationResult ? 'successful' : 'failed'}`);
}

document.getElementById('loginBtn').addEventListener('click', login);
```
This code is very similar to the code inside the register, but we use here `startAuthentication` API instead.


## Step 9 Adding login hanler in the server

Add this code to the server.js
```js
app.post('/login/start', async (req, res) => {
  const { username } = req.body;
  // Verify if the user exists
  const user = await signin(username);
  if (!user) {
    return res.status(400).send({ error: 'User does not exist' });
  }

  // Generate authentication options
  const options = {
    rpID,
    timeout: 60000, // Timeout for the request in milliseconds
    userVerification: 'required',
    allowCredentials: user.devices.map((device) => ({
      id: new Uint8Array(base64url.toBuffer(device.credentialID)),
      type: 'public-key',
      transports: device.transports,
    })),
  };

  const authenticationOptions = await generateAuthenticationOptions(options);

  // Store the challenge for later use during verification
  authenticators[username] = {
    currentChallenge: authenticationOptions.challenge,
  };

  // Send authentication options to the client
  return res.send(authenticationOptions);
});

// Endpoint to finish the login process
app.post('/login/finish', async (req, res) => {
  const { username, assertionResponse } = req.body;
  const expectedChallenge = authenticators[username].currentChallenge;

  const user = await signin(username);
  const device = user.devices[0];

  let verification;
  try {
    // Verify the authentication response
    verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: new Uint8Array(base64url.toBuffer(device.credentialID)),
        credentialPublicKey: new Uint8Array(base64url.toBuffer(device.credentialPublicKey)),
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  // Send the verification result to the client
  const { verified } = verification;
  if (verified) {
    return res.send({ verified });
  } else {
    return res.status(400).send({ error: 'Unable to verify login' });
  }
});
```