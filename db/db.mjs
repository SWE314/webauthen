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


