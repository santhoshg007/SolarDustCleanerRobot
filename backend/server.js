const https = require('https');
const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mqtt = require('mqtt');
const mysql = require('mysql2/promise');

const app = express();
const port = 8443;

// SSL Options
const sslOptions = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MQTT Client
const mqttClient = mqtt.connect('mqtt://localhost:1883', {
  username: 'konguess',
  password: 'konguess#$007'
});

mqttClient.on('connect', () => {
  console.log('✅ Connected to MQTT broker');
});
mqttClient.on('error', (err) => {
  console.error('❌ MQTT connection error:', err);
});

const db = mysql.createPool({
  host: 'localhost',
  user: 'dustcleanrobot',
  password: 'dustcleanrobot#$07',
  database: 'robotdb'
});

// Simulated valid devices (for auth)
const validDevices = new Set([
  "1001",
  "1002"
]);

// Utility: Wait for acknowledgment
function awaitAck(deviceUUID, timeoutMs = 30000) {
  return new Promise((resolve) => {
    const topic = `ack/${deviceUUID}`;
    const timer = setTimeout(() => {
      mqttClient.removeListener('message', handler);
      resolve({ status: 'failure', reason: 'timeout' });
    }, timeoutMs);

    const handler = (recvTopic, message) => {
      if (recvTopic === topic) {
        clearTimeout(timer);
        mqttClient.removeListener('message', handler);
        try {
          const data = JSON.parse(message.toString());
          resolve(data);
        } catch (e) {
          resolve({ status: 'failure', reason: 'invalid JSON' });
        }
      }
    };

    mqttClient.subscribe(topic, () => {
      mqttClient.on('message', handler);
    });
  });
}

// Utility: Update last_command in MySQL
async function updateRobotLastCommand(deviceUUID, commandJson) {
  try {
    const [rows] = await db.query(
      'SELECT deviceid FROM rtbl_robots_sts_details WHERE uuid = ?',
      [deviceUUID]
    );

    if (rows.length === 0) {
      console.warn(`⚠️ No matching device found for UUID: ${deviceUUID}`);
      return;
    }

    const deviceId = rows[0].deviceid;
    await db.query(
      'UPDATE rtbl_robots_sts_details SET last_command = ? WHERE deviceid = ?',
      [JSON.stringify(commandJson), deviceId]
    );

    console.log(`✅ Updated last_command for UUID: ${deviceUUID}`);
  } catch (err) {
    console.error('❌ MySQL update error:', err);
  }
}

// Publish and wait for ack
async function publishAndWaitAck(deviceUUID, payload) {
  const topic = `robot/${deviceUUID}`;
  try {
    mqttClient.publish(topic, JSON.stringify(payload), { qos: 1 });
  } catch (err) {
    console.error(`❌ MQTT publish error for ${deviceUUID}:`, err);
    return { status: 'failure', reason: 'MQTT publish error' };
  }

  try {
    const ack = await awaitAck(deviceUUID);
    if (ack.status === 'success') {
      await updateRobotLastCommand(deviceUUID, payload);
    }
    return ack;
  } catch (err) {
    console.error(`❌ Error waiting for ack:`, err);
    return { status: 'failure', reason: 'Ack error' };
  }
}


// AUTH Endpoint
app.post('/auth', async (req, res) => {
  const { deviceUUID, firmwareVersion, imei, timestamp } = req.body;

  if (!deviceUUID) {
    return res.status(400).json({ authStatus: "failure", reason: "Missing deviceUUID" });
  }

  const isValid = validDevices.has(deviceUUID);
  const payload = {
    type: 'auth',
    deviceUUID,
    firmwareVersion,
    imei,
    timestamp,
    authStatus: isValid ? 'success' : 'failure',
    ...(isValid && { sessionToken: "xyz-session-token-12345" })
  };

  const ack = await publishAndWaitAck(deviceUUID, payload);
  return res.json({ ...payload, ack });
});

// Generic command handler
function commandHandler(commandName) {
  return async (req, res) => {
    const { deviceUUID, timestamp, params } = req.body;

    if (!deviceUUID || !timestamp) {
      return res.status(400).json({ status: "failure", reason: "Missing fields" });
    }

    let payload = {
      "status": "",
      "direction": "",
      "main-speed": 0,
      "brush-speed": 0,
      "timestamp": timestamp,
      "params": {}
    };

    switch (commandName) {
      case "startCleaning":
        payload["status"] = "START";
        payload["direction"] = params.direction || "FWD";
        payload["main-speed"] = params.mainSpeed || 50;
        payload["brush-speed"] = params.brushSpeed || 50;
        break;
      case "stopCleaning":
        payload["status"] = "STOP";
        break;
      case "move":
        payload["status"] = "START";
	payload["direction"] = params.direction || "FWD";
        payload["direction"] = params.direction || "";
        payload["main-speed"] = params.speed || 50;
        break;
      case "startDirectionalCleaning":
        payload["status"] = "START";
        payload["direction"] = params.direction || "FWD";
        payload["direction"] = params.direction || "";
        payload["main-speed"] = params.mainSpeed || 50;
        payload["brush-speed"] = params.brushSpeed || 50;
        break;
      case "setMotorSpeed":
        payload["status"] = "START";
        payload["direction"] = params.direction || "FWD";
        payload["main-speed"] = params.mainSpeed || 50;
        payload["brush-speed"] = params.brushSpeed || 50;
        break;
      default:
        return res.status(400).json({ status: "failure", reason: "Invalid command" });
    }

    console.log(`Payload before publishing:`, JSON.stringify(payload, null, 2));

    const ack = await publishAndWaitAck(deviceUUID, payload);
    return res.json({ requestStatus: ack.status, ack });
  };
}
// GET /device-details?uuid=1001
app.post('/device-details', async (req, res) => {
  //const uuid = parseInt(req.query.uuid, 10);

  try {
    const [rows] = await db.execute(
      'SELECT RD.uuid, RD.name, RD.updated_at,RSD.status,RSD.battery,RSD.btn FROM rtbl_robots_details RD inner join rtbl_robots_sts_details RSD ON RD.uuid=RSD.uuid'
    );

    if (rows.length === 0) {
      return res.status(404).json({ status: "failure", reason: "Device not found" });
    }

    return res.json({
      status: "success",
      data: rows
    });

  } catch (error) {
    console.error("❌ DB Error:", error);
    return res.status(500).json({ status: "failure", reason: "Internal Server Error" });
  }
});

app.post('/device-details', async (req, res) => {
  try {
    const [rows] = await db.execute(
      'SELECT RD.uuid, RD.name, RD.updated_at, RSD.status, RSD.battery, RSD.btn FROM rtbl_robots_details RD INNER JOIN rtbl_robots_sts_details RSD ON RD.uuid = RSD.uuid'
    );

    if (rows.length === 0) {
      return res.status(404).json({ status: "failure", reason: "No devices found" });
    }

    return res.json({ status: "success", data: rows });
  } catch (error) {
    console.error("❌ DB Error in /device-details:", error);
    return res.status(500).json({ status: "failure", reason: "Database error" });
  }
});

// Command Routes
app.post('/startCleaning', commandHandler('startCleaning'));
app.post('/stopCleaning', commandHandler('stopCleaning'));
app.post('/move', commandHandler('move'));
app.post('/startDirectionalCleaning', commandHandler('startDirectionalCleaning'));
app.post('/setMotorSpeed', commandHandler('setMotorSpeed'));
app.post('/scheduleCleaning', commandHandler('scheduleCleaning'));

// Start HTTPS Server
https.createServer(sslOptions, app).listen(port, '0.0.0.0', () => {
  console.log(`🔐 HTTPS server running at https://0.0.0.0:${port}`);
});

