// Clean sample: parameterized pg, DOMPurify, textContent, execFile, literal URL.
const { rows } = await pool.query('SELECT * FROM orders WHERE customer = $1', [req.query.customer]);

function renderComment(comment) {
  document.getElementById('comment-box').textContent = comment.body;
}

const clean = DOMPurify.sanitize(comment.body);
el.innerHTML = clean;

execFile('tar', ['-czf', 'backup.tgz', req.body.path], (err, stdout) => res.send(stdout));

const GAS_PRICE_URL = 'https://api.example.com/gas';
const response = await fetch(GAS_PRICE_URL);

const stripeKey = process.env.STRIPE_SECRET_KEY;
