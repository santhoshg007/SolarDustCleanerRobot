const awsIot = require('aws-iot-device-sdk');
const { randomUUID } = require('crypto');

// Configuration - replace with your actual AWS IoT details
const config = {
  keyPath: '../CERT/aws_iot/private.pem.key',
  certPath: '../CERT/aws_iot/certificate.pem.crt',
  caPath: '../CERT/aws_iot/AmazonRootCA1.pem',
  clientId: `robot-simulator-${randomUUID().slice(0, 8)}`,
  host: 'a120abaz514cfc-ats.iot.us-east-1.amazonaws.com' // Your AWS IoT endpoint
};

// Create device instance
const device = awsIot.device(config);

// Robot ID - this would typically come from configuration or environment
const ROBOT_ID = 'RB2025AX4397'; // Replace with your robot's ID

device.on('connect', () => {
  console.log('✅ Connected to AWS IoT');
  
  // Subscribe to the robot's command topic
  const commandTopic = `robot/${ROBOT_ID}/command`;
  device.subscribe(commandTopic, { qos: 1 }, (err) => {
    if (err) {
      console.error('❌ Subscription error:', err);
    } else {
      console.log(`🔔 Subscribed to ${commandTopic}`);
    }
  });
});

device.on('message', (topic, payload) => {
  console.log(`📨 Message received on ${topic}`);
  
  try {
    const message = JSON.parse(payload.toString());
    console.log('Command received:', message);
    
    // Prepare acknowledgment response
    const responseTopic = `robot/${ROBOT_ID}/response`;
    const response = {
      Response: "success",
      status: message.status || "START",
      direction: message.direction || "FWD",
      "main-speed": message["main-speed"] || 50,
      "brush-speed": message["brush-speed"] || 50
    };
    
    // Publish the response
    device.publish(responseTopic, JSON.stringify(response), { qos: 1 }, (err) => {
      if (err) {
        console.error('❌ Failed to publish response:', err);
      } else {
        console.log(`📤 Sent response to ${responseTopic}:`, response);
      }
    });
    
  } catch (err) {
    console.error('❌ Error processing message:', err);
  }
});

device.on('error', (err) => {
  console.error('❌ AWS IoT error:', err);
});

device.on('reconnect', () => {
  console.log('🔄 Reconnecting to AWS IoT...');
});

device.on('offline', () => {
  console.log('⚠️ Device is offline');
});

process.on('SIGINT', () => {
  console.log('\nDisconnecting...');
  device.end();
  process.exit();
});

console.log('🤖 Robot simulator started. Waiting for commands...');
