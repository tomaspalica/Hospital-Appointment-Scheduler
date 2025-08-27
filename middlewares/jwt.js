const { verify } = require("../helpers/jwtHelpers");
require("dotenv").config();

function auth(req, res, next) {
  const token = req.headers.authorization.split(" ")[1];
  console.log(token);
  if (!token) return res.status(401).json({ message: "invalid token" });
  try {
    const verified = verify(token, process.env.JWT_SECRET);
    next();
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
}

module.exports = { auth };
