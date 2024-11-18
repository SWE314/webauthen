import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

// Open the SQLite Database
async function openDb() {
    return open({
        filename: './db/auth.db',
        driver: sqlite3.Database
    });
}

// Create tables (if not exist)
async function setupDb() {
    const db = await openDb();
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);
    await db.exec(`
        CREATE TABLE IF NOT EXISTS passkeys (
            cred_id TEXT PRIMARY KEY,
            cred_public_key BLOB NOT NULL,
            internal_user_id INTEGER NOT NULL,
            webauthn_user_id TEXT NOT NULL,
            counter INTEGER DEFAULT 0,
            backup_eligible BOOLEAN DEFAULT FALSE,
            backup_status BOOLEAN DEFAULT FALSE,
            transports TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            FOREIGN KEY (internal_user_id) REFERENCES users (id)
        );
    `);
    await db.close();
}

// Function to get passkeys for a user by username
async function getUserPasskeys(username) {
    const db = await openDb();
    const user = await getUserFromDB(username);
    if (!user) {
        await db.close();

        return undefined;
    }
    const passkeys = await db.all(`SELECT * FROM passkeys WHERE internal_user_id = ?`, [user.id]);
    await db.close();
    return passkeys;
}

// Function to save a new passkey in the database
async function saveNewPasskeyInDB(passkey) {
    const db = await openDb();
    let user = await getUserFromDB(passkey.user.name);
    if (!user) {
        // save user
        await addUser(passkey.user.name);
        user = await getUserFromDB(passkey.user.name);
    }
    await db.run(`
        INSERT INTO passkeys (
            cred_id,
            cred_public_key,
            internal_user_id,
            webauthn_user_id,
            counter,
            backup_eligible,
            backup_status,
            transports,
            created_at,
            last_used
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        passkey.id,
        passkey.publicKey,
        user.id,
        passkey.webAuthnUserID,
        passkey.counter,
        passkey.backupEligible,
        passkey.backedUp,
        JSON.stringify(passkey.transports),
        new Date().toISOString(),
        new Date().toISOString()
    ]);
    await db.close();
}

// Function to add a new user
async function addUser(username) {
    const db = await openDb();
    try {
        await db.run(`INSERT INTO users (username) VALUES (?)`, [username]);
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT') {
            throw new Error('Username already exists');
        }
        throw error;
    } finally {
        await db.close();
    }
}

// Function to get user from database
async function getUserFromDB(username) {
    const db = await openDb();
    const user = await db.get(`SELECT * FROM users WHERE username = ?`, [username]);
    await db.close();
    if (!user) {
        return undefined;
    }
    return user;
}

// Function to update the counter for a passkey
async function saveUpdatedCounter(passkey, newCounter) {
    const db = await openDb();
    await db.run(`
        UPDATE passkeys
        SET counter = ?, last_used = ?
        WHERE cred_id = ?
    `, [newCounter, new Date().toISOString(), passkey.id]);
    await db.close();
}

export {
    addUser,
    getUserPasskeys,
    saveNewPasskeyInDB,
    getUserFromDB,
    saveUpdatedCounter
};

// Setup database tables on startup
setupDb();