const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const INDEX = path.join(__dirname, 'index.html');

app.get('/', (req, res) => res.sendFile(INDEX));
app.get('/index.html', (req, res) => res.sendFile(INDEX));

app.get('*', (req, res) => {
  res.sendFile(INDEX);
});

app.listen(PORT, () => {
  console.log(`RAID WIKI запущен на порту ${PORT}`);
});
