// Practice sample: React sink bypassing the escaper.
app.post('/products/preview', (req, res) => {
  const html = req.body.description;
  res.send(<div dangerouslySetInnerHTML={{ __html: html }} />);
});
