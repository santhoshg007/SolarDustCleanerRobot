const https = require('https');
const fs = require('fs');
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const awsIot = require('aws-iot-device-sdk');
const app = express();
const PORT = 8443;
const { randomUUID } = require('crypto');

const SECRET_KEY = 'c90069dbacfedb7a94644184d53550c8dafcdd1785a139ea69c29f00c4680659162ac630cc4b55a06b7a2f802972b4aa801e16f05a77de9d49c6c98299a010f8'; // Use .env in production for security!

// --- AWS IoT Configuration ---
// IMPORTANT: Replace these placeholders with your actual AWS IoT Core details.
const AWS_IOT_ENDPOINT = 'a120abaz514cfc-ats.iot.us-east-1.amazonaws.com';
const AWS_IOT_PRIVATE_KEY_PATH = '../CERT/aws_iot/private.pem.key';
const AWS_IOT_CERTIFICATE_PATH = '../CERT/aws_iot/certificate.pem.crt';
const AWS_IOT_ROOT_CA_PATH = '../CERT/aws_iot/AmazonRootCA1.pem';

// AWS IoT Client Initialization
const mqttClient = awsIot.device({
    keyPath: AWS_IOT_PRIVATE_KEY_PATH,
    certPath: AWS_IOT_CERTIFICATE_PATH,
    caPath: AWS_IOT_ROOT_CA_PATH,
    clientId: `backend-client-${randomUUID().slice(0,8)}`, // Unique client ID
    host: AWS_IOT_ENDPOINT,
    protocol: 'mqtts' // Secure MQTT over TLS
});

mqttClient.on('connect', () => {
    console.log('✅ Connected to AWS IoT broker');
});

mqttClient.on('reconnect', () => {
    console.log('🔄 Reconnecting to AWS IoT broker...');
});

mqttClient.on('offline', () => {
    console.warn('⚠️ AWS IoT client is offline.');
});

mqttClient.on('error', (err) => {
    console.error('❌ AWS IoT connection error:', err);
});

// This general 'message' event is useful for handling other incoming telemetry
// or notifications from IoT devices, separate from specific command acknowledgments.
mqttClient.on('message', (topic, payload) => {
    console.log(`Received message from AWS IoT - Topic: ${topic}, Payload: ${payload.toString()}`);
    // You might want to process other types of incoming messages here (e.g., sensor data).
});

// --- End of AWS IoT Configuration ---

// SSL Certs for HTTPS Server
// Make sure these paths are correct for your HTTPS server certificates.
const privateKey = fs.readFileSync('../CERT/key.pem', 'utf8');
const certificate = fs.readFileSync('../CERT/cert.pem', 'utf8');
const credentials = { key: privateKey, cert: certificate };

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MySQL setup
const DB_NAME = 'robot_om_db';
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'dustcleanrobot#$07', // Consider environment variable for production
    multipleStatements: true
});

// Init DB & tables
db.connect(err => {
    if (err) throw err;
    console.log('Connected to MySQL');

    db.query(
        `CREATE DATABASE IF NOT EXISTS ${DB_NAME};
         USE ${DB_NAME};
         CREATE TABLE IF NOT EXISTS rtbl_accounts_dts (
           id INT AUTO_INCREMENT PRIMARY KEY,
           email VARCHAR(191) UNIQUE NOT NULL,
           password_hash VARCHAR(255) NOT NULL,
           created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
         );
         CREATE TABLE IF NOT EXISTS rtbl_token_blacklist (
           token VARCHAR(512) NOT NULL,
           blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
         );
         CREATE TABLE IF NOT EXISTS rtbl_clients (
           id INT AUTO_INCREMENT PRIMARY KEY,
           name VARCHAR(191) NOT NULL,
           created_by INT NOT NULL,
           created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
           FOREIGN KEY (created_by) REFERENCES rtbl_accounts_dts(id)
         );
         CREATE TABLE IF NOT EXISTS rtbl_locations (
           id VARCHAR(50) PRIMARY KEY,
           name VARCHAR(191) NOT NULL,
           client_id INT NOT NULL,
           address_line1 VARCHAR(255),
           address_line2 VARCHAR(255),
           address_line3 VARCHAR(255),
           city VARCHAR(100),
           state VARCHAR(100),
           zip VARCHAR(20),
           country VARCHAR(10),
           created_by INT NOT NULL,
           created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
           FOREIGN KEY (client_id) REFERENCES rtbl_clients(id)
         );
         CREATE TABLE IF NOT EXISTS rtbl_robots (
           id VARCHAR(24) PRIMARY KEY,
           name VARCHAR(100) NOT NULL,
           macaddress VARCHAR(32) UNIQUE NOT NULL,
           model VARCHAR(50) NOT NULL,
           location VARCHAR(50) NOT NULL,
           comm_port VARCHAR(50),
           status ENUM('OPERATIONAL', 'INACTIVE', 'FAULT') DEFAULT 'OPERATIONAL',
           installation_date DATETIME,
           created_by INT,
           created DATETIME DEFAULT CURRENT_TIMESTAMP,
           updated_by INT,
           updated DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
           last_command JSON,
           btn TINYINT(1) DEFAULT 0,
           FOREIGN KEY (location) REFERENCES rtbl_locations(id) ON DELETE CASCADE,
           FOREIGN KEY (created_by) REFERENCES rtbl_accounts_dts(id) ON DELETE SET NULL,
           FOREIGN KEY (updated_by) REFERENCES rtbl_accounts_dts(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS rtbl_commands (
           id VARCHAR(24) PRIMARY KEY,
           robot_id VARCHAR(24) NOT NULL,
           command_type VARCHAR(50) NOT NULL,
           payload JSON NOT NULL,
           status ENUM('pending', 'success', 'failure') DEFAULT 'pending',
           acknowledged_at DATETIME DEFAULT NULL,
           created_by INT,
           created DATETIME DEFAULT CURRENT_TIMESTAMP,
           FOREIGN KEY (robot_id) REFERENCES rtbl_robots(id) ON DELETE CASCADE,
           FOREIGN KEY (created_by) REFERENCES rtbl_accounts_dts(id) ON DELETE SET NULL
         );`,

        err => {
            if (err) throw err;
            console.log("Database and required tables ready.");
        }
    );
});
// --- Authentication Routes ---

// Signup
app.post('/account/signup', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: 'Email and password are required' });

    db.query(`SELECT * FROM ${DB_NAME}.rtbl_accounts_dts WHERE email = ?`, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (results.length > 0)
            return res.status(400).json({ error: 'Account with that email already registered' });

        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            `INSERT INTO ${DB_NAME}.rtbl_accounts_dts (email, password_hash) VALUES (?, ?)`,
            [email, hashedPassword],
            err => {
                if (err) return res.status(500).json({ error: 'Failed to create account' });

                return res.status(200).json({
                    message: 'New account created successfully',
                    email
                });
            }
        );
    });
});

// Login
app.post('/account/login/local', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: 'Email and password are required' });

    db.query(`SELECT * FROM ${DB_NAME}.rtbl_accounts_dts WHERE email = ?`, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (results.length === 0)
            return res.status(401).json({ error: 'Invalid email or password' });

        const user = results[0];

        if (!user.password_hash)
            return res.status(500).json({ error: 'Stored password missing' });

        try {
            const match = await bcrypt.compare(password, user.password_hash);

            if (!match)
                return res.status(401).json({ error: 'Invalid email or password' });

            const token = jwt.sign({ id: user.id.toString() }, SECRET_KEY, {
                expiresIn: '6h'
            });

            return res.status(200).json({
                message: 'Successfully logged in',
                account: user.id.toString().padStart(24, '0'),
                email: user.email,
                token
            });
        } catch (compareError) {
            return res.status(500).json({ error: 'Password compare failed', details: compareError.message });
        }
    });
});

// Auth middleware with blacklist check
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token required' });

    // Check blacklist first
    db.query(`SELECT * FROM ${DB_NAME}.rtbl_token_blacklist WHERE token = ?`, [token], (err, results) => {
        if (err) return res.status(500).json({ error: 'Token validation error' });

        if (results.length > 0) {
            return res.status(403).json({ error: 'Token has been revoked' });
        }

        // Verify JWT
        jwt.verify(token, SECRET_KEY, (err, user) => {
            if (err) return res.status(403).json({ error: 'Invalid token' });
            req.user = user;
            next();
        });
    });
}

// Protected route example
app.get('/solar-robot/:id', authenticateToken, (req, res) => {
    res.json({
        message: 'Access granted to solar robot data',
        userId: req.user.id,
        robotId: req.params.id
    });
});

// Logout
app.post('/account/logout', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(400).json({ error: 'API key (token) required in x-api-key header' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });

        db.query(
            `INSERT INTO ${DB_NAME}.rtbl_token_blacklist (token) VALUES (?)`,
            [token],
            (err) => {
                if (err) return res.status(500).json({ error: 'Failed to blacklist token' });

                return res.status(200).json({ message: 'Successfully logged out' });
            }
        );
    });
});

// Cleanup expired tokens every hour
setInterval(() => {
    db.query(
        `DELETE FROM ${DB_NAME}.rtbl_token_blacklist WHERE blacklisted_at < (NOW() - INTERVAL 6 HOUR)`,
        (err, result) => {
            if (err) console.error('[CLEANUP] Failed to clean expired tokens:', err);
            else console.log(`[CLEANUP] Removed ${result.affectedRows} expired blacklisted tokens`);
        }
    );
}, 3600000); // every 1 hour

app.get('/account', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });

        const userId = decoded.id;

        db.query(`SELECT id, email FROM ${DB_NAME}.rtbl_accounts_dts WHERE id = ?`, [userId], (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (results.length === 0) return res.status(404).json({ error: 'User not found' });

            const user = results[0];
            return res.status(200).json({
                account: user.id.toString().padStart(24, '0'),
                email: user.email
            });
        });
    });
});

app.patch('/account/change-password', async (req, res) => {
    const token = req.headers['x-api-key'];
    const newPassword = req.body['new-password'];

    if (!token) return res.status(401).json({ error: 'Token required' });
    if (!newPassword) return res.status(400).json({ error: 'New password required' });

    jwt.verify(token, SECRET_KEY, async (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });

        const userId = decoded.id;
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        db.query(
            `UPDATE ${DB_NAME}.rtbl_accounts_dts SET password_hash = ? WHERE id = ?`,
            [hashedPassword, userId],
            (err, result) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                return res.status(200).json({ message: 'Password updated successfully' });
            }
        );
    });
});

// --- Client Management Routes ---

// Create New Client
app.post('/client', (req, res) => {
    const token = req.headers['x-api-key'];
    const { name } = req.body;

    if (!token) return res.status(401).json({ error: 'API key (token) required in x-api-key header' });
    if (!name) return res.status(400).json({ error: 'Client name is required' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });

        const userId = decoded.id;

        db.query(
            `INSERT INTO ${DB_NAME}.rtbl_clients (name, created_by) VALUES (?, ?)`,
            [name, userId],
            (err, result) => {
                if (err) return res.status(500).json({ error: 'Failed to create client' });

                return res.status(200).json({
                    message: 'Client created successfully',
                    clientId: result.insertId,
                    name
                });
            }
        );
    });
});

// Get All Clients
app.get('/allclient', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        const userId = decoded.id;

        db.query(
            `SELECT id, name FROM ${DB_NAME}.rtbl_clients WHERE created_by = ?`,
            [userId],
            (err, results) => {
                if (err) return res.status(500).json({ error: 'Database error' });

                const clients = results.map(c => ({
                    _id: c.id.toString().padStart(24, '0'),
                    name: c.name,
                    __v: 0
                }));

                res.status(200).json({
                    "number-of-clients-found": clients.length,
                    clients
                });
            }
        );
    });
});

// Get Client by ID
app.get('/client/:id', (req, res) => {
    const token = req.headers['x-api-key'];
    const clientId = parseInt(req.params.id);
    if (!token) return res.status(401).json({ error: 'Token required' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });

        db.query(
            `SELECT id, name FROM ${DB_NAME}.rtbl_clients WHERE id = ? AND created_by = ?`,
            [clientId, decoded.id],
            (err, results) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                if (results.length === 0) return res.status(404).json({ error: 'Client not found' });

                const c = results[0];
                res.status(200).json({
                    client: {
                        _id: c.id.toString().padStart(24, '0'),
                        name: c.name,
                        __v: 0
                    }
                });
            }
        );
    });
});

// Update Client
app.patch('/client/:id', (req, res) => {
    const token = req.headers['x-api-key'];
    const newName = req.body.name;
    const clientId = parseInt(req.params.id);

    if (!token) return res.status(401).json({ error: 'Token required' });
    if (!newName) return res.status(400).json({ error: 'Client name required' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });

        db.query(
            `UPDATE ${DB_NAME}.rtbl_clients SET name = ? WHERE id = ? AND created_by = ?`,
            [newName, clientId, decoded.id],
            (err, result) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                if (result.affectedRows === 0) return res.status(404).json({ error: 'Client not found or not owned' });

                res.status(200).json({
                    message: 'Client updated',
                    client: {
                        _id: clientId.toString().padStart(24, '0'),
                        name: newName,
                        __v: 0
                    }
                });
            }
        );
    });
});

// Delete Client
app.delete('/client/:id', (req, res) => {
    const token = req.headers['x-api-key'];
    const clientId = parseInt(req.params.id);

    if (!token) return res.status(401).json({ error: 'Token required' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });

        db.query(
            `DELETE FROM ${DB_NAME}.rtbl_clients WHERE id = ? AND created_by = ?`,
            [clientId, decoded.id],
            (err, result) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                if (result.affectedRows === 0) return res.status(404).json({ error: 'Client not found or not owned' });

                res.status(200).json({ message: 'Client deleted successfully' });
            }
        );
    });
});

// --- Location Management Routes ---

// Create New Location
app.post('/location', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    let decoded;
    try {
        decoded = jwt.verify(token, SECRET_KEY);
    } catch {
        return res.status(403).json({ error: 'Invalid token' });
    }
    const userId = decoded.id;

    const { name, client, address } = req.body;
    const sql = `INSERT INTO ${DB_NAME}.rtbl_locations
        (name, client_id, address_line1, address_line2, address_line3, city, state, zip, country, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    const values = [
        name,
        parseInt(client, 16),
        address['line-1'],
        address['line-2'],
        address['line-3'],
        address.city,
        address.state,
        address.zip,
        address.country,
        userId
    ];

    db.query(sql, values, (err, result) => {
        if (err) return res.status(500).json({ error: 'Database insert error' });

        const locationId = result.insertId.toString(16).padStart(24, '0');
        res.status(200).json({
            message: 'New location registered',
            location: {
                _id: locationId,
                name,
                client,
                address,
                __v: 0
            }
        });
    });
});

// Get All Locations
app.get('/alllocation', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    let decoded;
    try {
        decoded = jwt.verify(token, SECRET_KEY);
    } catch {
        return res.status(403).json({ error: 'Invalid token' });
    }
    const userId = decoded.id;

    db.query(`SELECT * FROM ${DB_NAME}.rtbl_locations WHERE created_by = ?`, [userId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database read error' });

        const locations = results.map(row => ({
            _id: row.id.toString(16).padStart(24, '0'),
            name: row.name,
            client: row.client_id.toString(16).padStart(24, '0'),
            address: {
                'line-1': row.address_line1,
                'line-2': row.address_line2,
                'line-3': row.address_line3,
                city: row.city,
                state: row.state,
                zip: row.zip,
                country: row.country
            },
            __v: 0
        }));

        res.status(200).json({
            "number-of-locations-found": locations.length,
            locations
        });
    });
});

// Get Location by ID
app.get('/location/:id', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    let decoded;
    try {
        decoded = jwt.verify(token, SECRET_KEY);
    } catch {
        return res.status(403).json({ error: 'Invalid token' });
    }

    const locationId = parseInt(req.params.id, 16);

    db.query(`SELECT * FROM ${DB_NAME}.rtbl_locations WHERE id = ?`, [locationId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database read error' });
        if (results.length === 0) return res.status(404).json({ error: 'Location not found' });

        const row = results[0];
        res.status(200).json({
            location: {
                _id: row.id.toString(16).padStart(24, '0'),
                name: row.name,
                client: row.client_id.toString(16).padStart(24, '0'),
                address: {
                    'line-1': row.address_line1,
                    'line-2': row.address_line2,
                    'line-3': row.address_line3,
                    city: row.city,
                    state: row.state,
                    zip: row.zip,
                    country: row.country
                },
                __v: 0
            }
        });
    });
});

// Update Location
app.patch('/location/:id', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    let decoded;
    try {
        decoded = jwt.verify(token, SECRET_KEY);
    } catch {
        return res.status(403).json({ error: 'Invalid token' });
    }

    const locationId = parseInt(req.params.id, 16);
    const {
        name, client_id,
        address_line1, address_line2, address_line3,
        city, state, zip, country
    } = req.body;

    // Build fields dynamically based on non-empty input
    const fields = [];
    const values = [];

    if (name) {
        fields.push("name = ?");
        values.push(name);
    }
    if (client_id) {
        fields.push("client_id = ?");
        values.push(parseInt(client_id, 16));
    }
    if (address_line1) {
        fields.push("address_line1 = ?");
        values.push(address_line1);
    }
    if (address_line2) {
        fields.push("address_line2 = ?");
        values.push(address_line2);
    }
    if (address_line3) {
        fields.push("address_line3 = ?");
        values.push(address_line3);
    }
    if (city) {
        fields.push("city = ?");
        values.push(city);
    }
    if (state) {
        fields.push("state = ?");
        values.push(state);
    }
    if (zip) {
        fields.push("zip = ?");
        values.push(zip);
    }
    if (country) {
        fields.push("country = ?");
        values.push(country);
    }

    // If nothing to update, return early
    if (fields.length === 0) {
        return res.status(400).json({ error: 'No valid fields to update' });
    }

    values.push(locationId); // for WHERE id = ?

    const sql = `
        UPDATE ${DB_NAME}.rtbl_locations
        SET ${fields.join(', ')}
        WHERE id = ?
    `;

    db.query(sql, values, (err) => {
        if (err) return res.status(500).json({ error: 'Database update error', detail: err.message });

        db.query(`SELECT * FROM ${DB_NAME}.rtbl_locations WHERE id = ?`, [locationId], (err2, results) => {
            if (err2) return res.status(500).json({ error: 'Read back error' });
            const row = results[0];

            res.status(200).json({
                message: 'Location updated',
                location: {
                    _id: row.id.toString(16).padStart(24, '0'),
                    name: row.name,
                    client: row.client_id.toString(16).padStart(24, '0'),
                    address: {
                        'line-1': row.address_line1,
                        'line-2': row.address_line2,
                        'line-3': row.address_line3,
                        city: row.city,
                        state: row.state,
                        zip: row.zip,
                        country: row.country
                    },
                    __v: 0
                }
            });
        });
    });
});

// Delete Location
app.delete('/location/:id', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    let decoded;
    try {
        decoded = jwt.verify(token, SECRET_KEY);
    } catch {
        return res.status(403).json({ error: 'Invalid token' });
    }

    const locationId = parseInt(req.params.id, 16);

    db.query(`SELECT * FROM ${DB_NAME}.rtbl_locations WHERE id = ?`, [locationId], (err, results) => {
        if (err || results.length === 0) return res.status(404).json({ error: 'Location not found' });
        const row = results[0];

        db.query(`DELETE FROM ${DB_NAME}.rtbl_locations WHERE id = ?`, [locationId], (err2) => {
            if (err2) return res.status(500).json({ error: 'Delete error' });

            res.status(200).json({
                message: 'Location removed',
                location: {
                    _id: row.id.toString(16).padStart(24, '0'),
                    name: row.name,
                    client: row.client_id.toString(16).padStart(24, '0'),
                    address: {
                        'line-1': row.address_line1,
                        'line-2': row.address_line2,
                        'line-3': row.address_line3,
                        city: row.city,
                        state: row.state,
                        zip: row.zip,
                        country: row.country
                    },
                    __v: 0
                }
            });
        });
    });
});

// --- Robot Management Routes ---

// Create New Robot
app.post('/solar-robot', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    let decoded;
    try {
        decoded = jwt.verify(token, SECRET_KEY);
    } catch {
        return res.status(403).json({ error: 'Invalid token' });
    }

    const data = req.body;
    const id = randomUUID().replace(/-/g, '').slice(0, 24);
    const mac = data['mac-address'];

    // Step 1: Check if mac address exists
    db.query('SELECT id FROM rtbl_robots WHERE macaddress = ?', [mac], (err, results) => {
        if (err) {
            console.error('DB Check Error:', err);
            return res.status(500).json({ error: 'Database error', detail: err.message });
        }

        if (results.length > 0) {
            return res.status(409).json({ error: 'MAC address already exists' });
        }

        // Step 2: Proceed to insert
        const query = `
            INSERT INTO rtbl_robots
            (id, name, macaddress, model, location, comm_port, status, installation_date, created_by, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            id,
            data['name'] || '',
            mac,
            data['model'] || '',
            data['location'] || '',
            data['comm-port'] || '',
            data['status'] || 'OPERATIONAL',
            data['installation-date'] || null,
            decoded.id,
            decoded.id
        ];

        db.query(query, values, (err2, result) => {
            if (err2) {
                console.error('DB Insert Error:', err2);
                return res.status(500).json({ error: 'Failed to create robot', detail: err2.message });
            }

            res.json({
                message: 'New solar robot registered',
                'solar-robot': {
                    _id: id,
                    ...data,
                    'created-by': decoded.id,
                    'updated-by': decoded.id,
                    created: new Date().toISOString(),
                    updated: new Date().toISOString(),
                    __v: 0
                }
            });
        });
    });
});

// Get All Robots
app.get('/allrobot', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    let decoded;
    try {
        decoded = jwt.verify(token, SECRET_KEY);
    } catch {
        return res.status(403).json({ error: 'Invalid token' });
    }

    db.query('SELECT * FROM rtbl_robots', (err, results) => {
        if (err) {
            console.error('DB Select Error:', err);
            return res.status(500).json({ error: 'Database error', detail: err.message });
        }

        res.json({
            'number-of-controllers-found': results.length,
            'solar-robots': results
        });
    });
});

// Get Robot by ID
app.get('/robot/:id', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    let decoded;
    try {
        decoded = jwt.verify(token, SECRET_KEY);
    } catch {
        return res.status(403).json({ error: 'Invalid token' });
    }

    const robotId = req.params.id;

    db.query('SELECT * FROM rtbl_robots WHERE id = ?', [robotId], (err, results) => {
        if (err) {
            console.error('DB Select Error:', err);
            return res.status(500).json({ error: 'Database error', detail: err.message });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Robot not found' });
        }

        res.json({ 'solar-robot': results[0] });
    });
});

// Update Robot
app.patch('/solar-robot/:id', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    let decoded;
    try {
        decoded = jwt.verify(token, SECRET_KEY);
    } catch {
        return res.status(403).json({ error: 'Invalid token' });
    }

    const data = req.body;
    const fields = [];
    const values = [];

    for (const key in data) {
        if (
            data[key] !== null &&
            data[key] !== undefined &&
            data[key] !== ''
        ) {
            const dbKey =
                key === 'comm-port' ? 'comm_port' :
                key === 'installation-date' ? 'installation_date' : key;
            fields.push(`${dbKey} = ?`);
            values.push(data[key]);
        }
    }

    if (fields.length === 0) {
        return res.status(400).json({ error: 'No valid fields provided for update' });
    }

    fields.push('updated_by = ?');
    values.push(decoded.id);
    values.push(req.params.id);

    const updateSql = `UPDATE rtbl_robots SET ${fields.join(', ')} WHERE id = ?`;

    db.query(updateSql, values, (err, result) => {
        if (err) {
            console.error('DB Update Error:', err);
            return res.status(500).json({ error: 'Database update error', detail: err.message });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Robot not found or no change applied' });
        }

        db.query('SELECT * FROM rtbl_robots WHERE id = ?', [req.params.id], (err2, rows) => {
            if (err2) {
                console.error('DB Fetch Error:', err2);
                return res.status(500).json({ error: 'Database fetch error', detail: err2.message });
            }

            res.json({
                message: 'Robot updated successfully',
                updated: rows[0]
            });
        });
    });
});

// Delete Robot
app.delete('/solar-robot/:id', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    let decoded;
    try {
        decoded = jwt.verify(token, SECRET_KEY);
    } catch {
        return res.status(403).json({ error: 'Invalid token' });
    }

    const robotId = req.params.id;

    db.query('SELECT * FROM rtbl_robots WHERE id = ?', [robotId], (err, rows) => {
        if (err) {
            console.error('Select error:', err);
            return res.status(500).json({ error: 'Database error on select' });
        }

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Robot not found' });
        }

        db.query('DELETE FROM rtbl_robots WHERE id = ?', [robotId], (err2, result) => {
            if (err2) {
                console.error('Delete error:', err2);
                return res.status(500).json({ error: 'Database error on delete' });
            }

            res.json({
                message: 'Solar robot removed',
                'solar-robot': rows[0]
            });
        });
    });
});

// Send Command to Robot (via AWS IoT)
app.patch('/solar-robot/command/:id', (req, res) => {
    const token = req.headers['x-api-key'];
    if (!token) return res.status(401).json({ error: 'Token required' });

    let decoded;
    try {
        decoded = jwt.verify(token, SECRET_KEY);
    } catch {
        return res.status(403).json({ error: 'Invalid token' });
    }

    const robotId = req.params.id;
    const { timestamp, params = {}, command } = req.body;

    if (!robotId || !timestamp || !command) {
        return res.status(400).json({ status: "failure", reason: "Missing robot ID, command or timestamp" });
    }

    db.query('SELECT * FROM rtbl_robots WHERE id = ?', [robotId], (err, robotRows) => {
        if (err) return res.status(500).json({ error: 'DB error', detail: err.message });
        if (robotRows.length === 0) {
            return res.status(404).json({ status: "failure", reason: "Invalid robot ID" });
        }

        const robot = robotRows[0]; // Store the robot object here for later use

        let payload = {
            status: "",
            direction: "",
            "main-speed": 0,
            "brush-speed": 0,
            timestamp,
            params: {}
        };

        switch (command) {
            case "startCleaning":
                payload.status = "START";
                payload.direction = params.direction || "FWD";
                payload["main-speed"] = params.mainSpeed || 50;
                payload["brush-speed"] = params.brushSpeed || 50;
                break;
            case "stopCleaning":
                payload.status = "STOP";
                break;
            case "move":
                payload.status = "START";
                payload.direction = params.direction || "FWD";
                payload["main-speed"] = params.speed || 50;
                break;
            case "startDirectionalCleaning":
            case "setMotorSpeed":
                payload.status = "START";
                payload.direction = params.direction || "FWD";
                payload["main-speed"] = params.mainSpeed || 50;
                payload["brush-speed"] = params.brushSpeed || 50;
                break;
            default:
                return res.status(400).json({ status: "failure", reason: "Invalid command" });
        }

        const commandId = randomUUID().replace(/-/g, '').slice(0, 24);
        const insertSql = `INSERT INTO rtbl_commands (id, robot_id, command_type, payload, status, created_by)
                             VALUES (?, ?, ?, ?, ?, ?)`;

        db.query(insertSql, [commandId, robotId, command, JSON.stringify(payload), 'pending', decoded.id], (err2) => {
            if (err2) return res.status(500).json({ error: 'Insert error', detail: err2.message });

            const topic = `robot/${robotId}/commands`;
            mqttClient.publish(topic, JSON.stringify(payload), { qos: 1 }, (publishErr) => {
                if (publishErr) {
                    console.error('Failed to publish to AWS IoT:', publishErr);
                    // It's crucial to handle errors immediately if publish fails
                    updateAfterAck({ status: 'failure', reason: 'Failed to publish to AWS IoT', originalError: publishErr });
                    return; // Prevent further execution if publish fails
                } else {
                    console.log(`Published command to AWS IoT topic: ${topic}`);
                }
            });

            const ackTopic = `robot/${robotId}/ack`;

            // Subscribe to the ACK topic to receive the response from the robot.
            // This needs to be done *before* the command is published, or very quickly after.
            mqttClient.subscribe(ackTopic, (subscribeErr) => {
                if (subscribeErr) {
                    console.error(`Failed to subscribe to ACK topic ${ackTopic}:`, subscribeErr);
                    updateAfterAck({ status: 'failure', reason: 'Failed to subscribe to ACK topic', originalError: subscribeErr });
                    return; // Prevent further execution if subscription fails
                }
                console.log(`Subscribed to ACK topic: ${ackTopic}`);
            });

            const timer = setTimeout(() => {
                // IMPORTANT: Use removeListener as the listener for this specific command is attached directly.
                mqttClient.removeListener('message', handler);
                // Unsubscribe after timeout as well
                mqttClient.unsubscribe(ackTopic, (err) => {
                    if(err) console.error(`Error unsubscribing from ${ackTopic} on timeout:`, err);
                });
                updateAfterAck({ status: 'failure', reason: 'timeout' });
            }, 15000); // 15 seconds timeout

            let ackReceived = false; // Flag to ensure `updateAfterAck` is called only once

            const handler = (recvTopic, message) => {
                // Ensure the received message is for the correct robot ID and is an acknowledgment
                if (recvTopic === ackTopic && !ackReceived) {
                    ackReceived = true;
                    clearTimeout(timer);
                    mqttClient.removeListener('message', handler); // Remove this specific listener
                    // Unsubscribe after receiving the ACK to prevent accumulating listeners
                    mqttClient.unsubscribe(ackTopic, (err) => {
                        if(err) console.error(`Error unsubscribing from ${ackTopic}:`, err);
                    });

                    try {
                        const data = JSON.parse(message.toString());
                        updateAfterAck({ status: 'success', ...data });
                    } catch (parseError) {
                        updateAfterAck({ status: 'failure', reason: 'invalid JSON in ACK', originalError: parseError });
                    }
                }
            };

            // Attach the message handler to listen for the ACK.
            mqttClient.on('message', handler);


            function updateAfterAck(ack) {
                // This function should only be called once. The `ackReceived` flag helps ensure that.
                db.query(
                    `UPDATE rtbl_commands SET status = ?, acknowledged_at = ? WHERE id = ?`,
                    [ack.status, new Date(), commandId],
                    (dbUpdateErr) => {
                        if (dbUpdateErr) {
                            console.error('Error updating command status in DB:', dbUpdateErr);
                        }

                        db.query(
                            `UPDATE rtbl_robots SET last_command = ?, updated = CURRENT_TIMESTAMP WHERE id = ?`,
                            [JSON.stringify(payload), robotId],
                            (dbRobotUpdateErr) => {
                                if (dbRobotUpdateErr) {
                                    console.error('Error updating robot last_command in DB:', dbRobotUpdateErr);
                                }

                                const userSetting = {
                                    status: payload.status,
                                    direction: payload.direction,
                                    "main-speed": payload["main-speed"],
                                    "brush-speed": payload["brush-speed"]
                                };

                                const reportedOperation = {
                                    status: payload.status,
                                    direction: payload.direction,
                                    "main-speed": 30, // Example static values for reported-operation, replace with actual robot reported state if available
                                    "brush-speed": 10
                                };

                                res.json({
                                    message: "Configuration command sent",
                                    "solar-robot": {
                                        "user-setting": userSetting,
                                        "reported-operation": reportedOperation,
                                        "acknowledgment-status": ack.status,
                                        "acknowledgment-reason": ack.reason || 'N/A',
                                        // Include full robot details from the 'robot' object
                                        _id: robot.id,
                                        name: robot.name,
                                        "mac-address": robot.macaddress,
                                        model: robot.model,
                                        location: robot.location,
                                        "comm-port": robot.comm_port,
                                        status: robot.status,
                                        "installation-date": robot.installation_date,
                                        "created-by": robot.created_by,
                                        created: robot.created,
                                        "updated-by": robot.updated_by,
                                        updated: robot.updated,
                                        __v: 0
                                    }
                                });
                            }
                        );
                    }
                );
            }
        });
    });
});

// Start the HTTPS server
https.createServer(credentials, app).listen(PORT, () => {
    console.log(`🚀 HTTPS Server running on https://localhost:${PORT}`);
});
