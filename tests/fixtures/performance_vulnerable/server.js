const fs = require('fs');
const express = require('express');
const app = express();

app.get('/report', (req, res) => {
  res.send(fs.readFileSync('./report.csv', 'utf8'));
});

module.exports = app;
