const mqtt = require('mqtt');
const deviceUUID = '1001';

// MQTT Client
const client = mqtt.connect('mqtt://localhost:1883', {
  username: 'konguess',
  password: 'konguess#$007'
});

client.on('connect', () => {
  client.subscribe(`robot/${deviceUUID}`, () => {
    console.log(`✅ Subscribed to robot/${deviceUUID}`);
  });
});

client.on('message', (topic, message) => {
  const data = JSON.parse(message.toString());
  console.log('📥 Received:', data);

  // Simulate processing success
  const ack = {
    status: 'success',
    receivedCommand: data.command || data.type
  };

  client.publish(`ack/${deviceUUID}`, JSON.stringify(ack), { qos: 1 });
});
