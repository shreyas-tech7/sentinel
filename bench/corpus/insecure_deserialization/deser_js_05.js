// Practice sample: node-serialize on a parsed body value.
const serialize = require('node-serialize');

app.post('/import-state', (req, res) => {
  const state = serialize.unserialize(req.body.state);
  res.json({ restored: state.mode });
});
