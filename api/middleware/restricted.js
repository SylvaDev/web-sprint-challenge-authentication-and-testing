const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  const token = req.headers.authorization;
  const secret = process.env.JWT_SECRET || 'shh';

  if (!token) {
    return res.status(401).json({ message: 'token required' });
  }

  jwt.verify(token, secret, (err, decodedToken) => {
    if (err) {
      return res.status(401).json({ message: 'token invalid' });
    }
    req.decodedToken = decodedToken;
    next();
  });
};
