// Clean sample: basename + explicit root sendFile, allowlisted redirect targets.
const BASENAME = require('path').basename;

app.get('/files/:file', (req, res) => {
  const safe = BASENAME(req.params.file);
  res.sendFile(safe, { root: 'public/docs/' });
});

const ALLOWED_REDIRECTS = ['/account', '/home'];
if (ALLOWED_REDIRECTS.includes(req.query.next)) {
  res.redirect(req.query.next);
}
