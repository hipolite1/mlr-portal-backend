// backend/pickups.js

const express = require('express');
const db = require('./database');
const router = express.Router();
const twilio = require('twilio');
const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Function to send SMS reminder
const sendPickupReminder = (phoneNumber, message) => {
  client.messages.create({
    body: message,
    from: process.env.TWILIO_PHONE_NUMBER, // Your Twilio phone number
    to: phoneNumber
  })
  .then(message => console.log(`Reminder sent: ${message.sid}`))
  .catch(err => console.error('Error sending reminder:', err));
};

// Update pickup status and send reminder if status is 'ready'
router.post('/update/:id', (req, res) => {
  const { status } = req.body;
  const pickupId = req.params.id;

  // Fetch the pickup details from the database
  db.get('SELECT * FROM pickups WHERE id = ?', [pickupId], (err, row) => {
    if (err || !row) {
      return res.status(500).send('Pickup not found.');
    }

    // Update the pickup status
    db.run('UPDATE pickups SET status = ? WHERE id = ?', [status, pickupId], (err) => {
      if (err) {
        return res.status(500).send('Error updating pickup.');
      }

      // If status is 'ready', send a reminder SMS
      if (status === 'ready') {
        const message = `Your laundry is ready for pickup! Pickup ID: ${pickupId}`;
        sendPickupReminder(row.phone_number, message); // Send SMS reminder
      }

      res.status(200).send('Pickup status updated and reminder sent.');
    });
  });
});

module.exports = router;
