// Practice sample: DOM XSS — unsanitized request value assigned to innerHTML.
app.post('/preview', (req, res) => {
  const el = document.getElementById('comment-box');
  el.innerHTML = '<div class="comment">' + req.body.body + '</div>';
  res.json({ ok: true });
});
