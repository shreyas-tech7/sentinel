// Practice sample: child_process.exec with concatenated input.
const { exec } = require('child_process');

app.post('/tools/archive', (req, res) => {
  exec('tar -czf backup.tgz ' + req.body.path, (err, stdout) => {
    res.send(stdout);
  });
});
