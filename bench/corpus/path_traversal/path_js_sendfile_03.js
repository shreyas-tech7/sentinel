// Practice sample: express sendFile on a joined request path.
app.get('/files/:file', (req, res) => {
  res.sendFile(path.join('public/docs/', req.params.file));
});
