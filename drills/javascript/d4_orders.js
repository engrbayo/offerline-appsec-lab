const express = require('express');
const router = express.Router();

router.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).end();
  res.json(order);
});

router.patch('/api/users/me', requireAuth, async (req, res) => {
  const user = await User.findByIdAndUpdate(req.user.id, req.body, { new: true });
  res.json(user);
});

router.post('/api/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email, password: req.body.password });
  if (!user) return res.status(401).json({ error: 'bad credentials' });
  res.json({ token: issueToken(user) });
});
