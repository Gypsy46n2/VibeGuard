const axios = require('axios');

async function load(url) {
  const a = await axios.get(url);
  const b = await fetch(url);
  return [a, b];
}

module.exports = { load };
