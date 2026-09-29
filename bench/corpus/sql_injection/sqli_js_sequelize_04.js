// Practice sample (Juice Shop-style): template literal into sequelize.query.
app.get('/api/search', async (req, res) => {
  const criteria = req.query.q;
  const results = await sequelize.query(
    `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
  );
  res.json(results);
});
