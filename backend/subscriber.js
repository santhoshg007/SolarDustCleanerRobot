const mqtt = require('mqtt');
const mysql = require('mysql2');
const deviceUUID = '54769dfca8d4417bb9ab6f78';

//const client = mqtt.connect('mqtt://localhost:1883');

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
  console.log('📥 Received response data:', data);

  // Simulate processing success
  const ack = {
    status: 'success',
    receivedCommand: data.command || data.type
  };

  client.publish(`ack/${deviceUUID}`, JSON.stringify(ack), { qos: 1 });
});
