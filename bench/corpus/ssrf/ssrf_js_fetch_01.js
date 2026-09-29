// Practice sample (Juice Shop-style): server fetches an attacker-supplied URL.
app.post('/profile/image-url', async (req, res) => {
  const url = req.body.imageUrl;
  const response = await fetch(url);
  res.json({ status: response.status });
});
