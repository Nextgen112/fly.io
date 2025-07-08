import express from 'express';
import session from 'express-session';

const app = express();
app.use(express.json());
app.use(session({
  secret: 'your_secret_key_here',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // set true if using HTTPS
}));

// In-memory stores (replace with real DB in production)
const allowedIPs = new Set();
const users = {
  admin: { password: 'adminpass' },
  user1: { password: 'userpass' }
};

// Helper to get real IP behind proxies
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
}

// Admin login endpoint
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === users.admin.password) {
    req.session.admin = true;
    return res.json({ message: 'Admin logged in' });
  }
  res.status(401).json({ error: 'Unauthorized' });
});

// Admin add IP to whitelist
app.post('/admin/add-ip', (req, res) => {
  if (!req.session.admin) return res.status(401).json({ error: 'Unauthorized' });
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  allowedIPs.add(ip);
  res.json({ message: `IP ${ip} added to whitelist` });
});

// User login and add current IP to whitelist
app.post('/user/login', (req, res) => {
  const { username, password } = req.body;
  if (users[username]?.password === password) {
    const ip = getClientIP(req);
    allowedIPs.add(ip);
    req.session.user = username;
    return res.json({ message: 'User logged in and IP added', ip });
  }
  res.status(401).json({ error: 'Unauthorized' });
});

// Middleware to protect /vip.js route by IP
app.use('/vip.js', (req, res, next) => {
  const ip = getClientIP(req);
  if (allowedIPs.has(ip)) next();
  else res.status(403).send('Access denied: Your IP is not allowed');
});

// The /vip.js file (served only if IP allowed)
app.get('/vip.js', (req, res) => {
  res.type('application/javascript');
  res.send(`console.log('VIP JS loaded for allowed IP');`);
});

app.listen(process.env.PORT || 3000, () => {
  console.log('Server running on port', process.env.PORT || 3000);
});
