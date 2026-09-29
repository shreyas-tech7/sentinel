// Practice sample: NoSQL operator injection — request data used as a filter value.
app.post('/api/users/search', (req, res) => {
  db.collection('users').findOne({ email: req.body.email }, (err, user) => {
    res.json(user);
  });
});
