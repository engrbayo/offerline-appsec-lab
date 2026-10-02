const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const claims = jwt.decode(token);
  if (!claims) return res.status(401).end();
  req.user = claims;
  next();
}

app.get('/redirect', (req, res) => {
  res.redirect(req.query.next);
});

app.get('/api/search', (req, res) => {
  res.send(`<h1>Results for ${req.query.q}</h1>`);
});

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});
