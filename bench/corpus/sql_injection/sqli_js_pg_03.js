// Practice sample: pg client with a concatenated query.
const { rows } = await pool.query(
  "SELECT * FROM orders WHERE customer = '" + req.query.customer + "'"
);
