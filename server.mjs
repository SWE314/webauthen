import express from 'express';
import bodyParser from 'body-parser';
import base64url from 'base64url';
import { getUserPasskeys, saveNewPasskeyInDB, getUserFromDB, saveUpdatedCounter } from './db/db.mjs';
import {
    generateRegistrationOptions,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,

} from '@simplewebauthn/server';
const authenticators = {};
const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

const PORT = 3000;
const rpID = 'localhost'; // Relying Party Identifier
const rpName = 'SimpleWebAuthn Lab SWE314';
const origin = `http://${rpID}:${PORT}`;


const getCurrentRegistrationOptions = (user) => {
    return authenticators[user.id];
}
const setCurrentRegistrationOptions = (user, options) => {
    authenticators[user.id] = options;
}

app.get('/generate-registration-options', async (req, res) => {
    const userName = req.query.userName;
    const userPasskeys = await getUserPasskeys(userName);
    if (!userName) {
        return res.status(400).send({ error: 'No username provided' });
    }
    try {
        const options = await generateRegistrationOptions({
            rpName,
            rpID,
            userName,
            attestationType: 'direct',
            authenticatorSelection: {
                userVerification: 'required',
            },
            excludeCredentials: userPasskeys?.map(passkey => ({
                id: passkey.cred_id,
                type: 'public-key',
                transports: passkey.transports,
            })),

            authenticatorSelection: {
                // Defaults
                residentKey: 'preferred',
                userVerification: 'preferred',
                // Optional
                authenticatorAttachment: 'platform',
            },
        });
        setCurrentRegistrationOptions(userName, options);
        res.json(options);

    } catch (error) {
        console.error(error);
        return res.status(400).send({ error: "Failed to register user" });
    }

});


app.post('/verify-registration', async (req, res) => {
    const { body } = req;
    const userName = body.userName;
    const currentOptions = getCurrentRegistrationOptions(userName);



    let verification;
    try {
        verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge: currentOptions.challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });
    } catch (error) {
        console.error(error);
        return res.status(400).send({ error: error.message });
    }

    const { verified, registrationInfo } = verification;
    const {
        credential,
        credentialDeviceType,
        credentialBackedUp,
    } = registrationInfo;
    const newPasskey = {
        // `user` here is from Step 2
        user: currentOptions.user,
        // Created by `generateRegistrationOptions()` in Step 1
        webAuthnUserID: currentOptions.user.id,
        // A unique identifier for the credential
        id: credential.id,
        // The public key bytes, used for subsequent authentication signature verification
        publicKey: credential.publicKey,
        // The number of times the authenticator has been used on this site so far
        counter: credential.counter,
        // How the browser can talk with this credential's authenticator
        transports: credential.transports,
        // Whether the passkey is single-device or multi-device
        deviceType: credentialDeviceType,
        // Whether the passkey has been backed up in some way
        backedUp: credentialBackedUp,
    };

    // (Pseudocode) Save the authenticator info so that we can
    // get it by user ID later
    saveNewPasskeyInDB(newPasskey);

    res.json({ verified });

});




app.get('/generate-authentication-options', async (req, res) => {
    const userName = req.query.userName;
    const userPasskeys = await getUserPasskeys(userName);
    if (!userPasskeys) {
        return res.status(400).send({ error: 'user not found' });
    }
    const options = await generateAuthenticationOptions({
        rpID,
        userVerification: 'required',
        allowCredentials: userPasskeys.map(passkey => ({
            id: passkey.cred_id,
            transports: JSON.parse(passkey.transports),
        })),
    });

    setCurrentRegistrationOptions(userName, options);

    res.json(options);
}
);



app.post('/verify-authentication', async (req, res) => {
    const { body } = req;
    const userName = body.userName;
    const user = await getUserFromDB(userName);
    const currentOptions = getCurrentRegistrationOptions(user.username);
    const passkeys = await getUserPasskeys(user.username)
    const passkey = passkeys[0];

    if (!passkey) {
        throw new Error(`Could not find passkey ${body.id} for user ${user.id}`);
    }

    let verification;
    try {
        verification = await verifyAuthenticationResponse({
            response: body,
            expectedChallenge: currentOptions.challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            credential: {
                id: passkey.cred_id,
                publicKey: passkey.cred_public_key,
                counter: passkey.counter,
                transports: JSON.parse(passkey.transports),
            },
        });
    } catch (error) {
        console.error(error);
        return res.status(400).send({ error: error.message });
    }

    const { verified, authenticationInfo } = verification;
    const { newCounter } = authenticationInfo;

    saveUpdatedCounter(passkey, newCounter);
    res.json({ verified });
}

);


app.listen(PORT, () => {
    console.log('Server listening on http://localhost:' + PORT);
});