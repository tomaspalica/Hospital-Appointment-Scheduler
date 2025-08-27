const crypto = require("crypto");
require("dotenv").config();

const JWT_TO_NODE_HASH = {
  HS256: "sha256",
  HS384: "sha384",
  HS512: "sha512",
};
const signCrypto = (input, secret, algorithm = "sha256") => {
  return crypto.createHmac(algorithm, secret).update(input).digest("base64url");
};
const base64Url = (input) => {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
};
function parseTimespan(input) {
  if (typeof input === "number" && Number.isFinite(input)) {
    if (input < 0) throw new RangeError("expiresIn can't be a negative number");
    return Math.floor(input);
  }
  if (typeof input !== "string") {
    throw new TypeError(
      'expiresIn shoud be a number (seconds) or a string, for example "15m"'
    );
  }
  const m = input.trim().match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d)?$/i);
  if (!m) throw new TypeError(`Incorect time format: ${input}`);
  const value = parseFloat(m[1]);
  const unit = (m[2] || "s").toLowerCase();

  const unitToSec = {
    ms: 1 / 1000,
    s: 1,
    m: 60,
    h: 60 * 60,
    d: 60 * 60 * 24,
  };
  const seconds = value * unitToSec[unit];
  return Math.floor(seconds);
}
function sign(payload, secret, options = {}) {
  const header = {
    alg: options.algorithm || "HS256",
    typ: "JWT",
  };

  const now = Math.floor(Date.now() / 1000);
  const registeredClaims = {
    iat: now,
    ...(options.exp && { exp: now + parseTimespan(options.exp) }),
    iss: process.env.ISSUER,
  };

  if (!payload || !secret) return null;

  const cryptHeader = base64Url(JSON.stringify(header));
  const cryptPayload = base64Url(
    JSON.stringify({ ...payload, ...registeredClaims })
  );
  const toSign = cryptHeader + "." + cryptPayload;
  const cryptSignature = signCrypto(
    toSign,
    secret,
    JWT_TO_NODE_HASH[header.alg]
  );

  const token = toSign + "." + cryptSignature;
  return token;
  // payload object ?
  // check if there is a secret
  // check for expire date if not then token is forever
  // generate a token
  // return the token
}

function verify(token, secret) {
  const algs = ["HS256", "HS384", "HS512"];
  const parts = token.split(".");
  // if array dosn't have 3 values after spliting the string by dots it means token has a invalid format
  if (parts.length !== 3) throw new Error("Invalid token format ");
  // decoding header and payload also we create a key that we can use to validate signature
  const header = JSON.parse(Buffer.from(parts[0], "base64").toString());
  const payload = JSON.parse(Buffer.from(parts[1], "base64").toString());

  const key =
    base64Url(JSON.stringify(header)) +
    "." +
    base64Url(JSON.stringify(payload));
  // if statment checks if white list includes the algorithm that header provieds if it dosn't then token is invalid
  if (!algs.includes(header.alg)) throw new Error("Invalid token");

  // function only expects type jwt in header
  if (!header.typ && !header.typ === "JWT") throw new Error("invalid token");

  // checking if signature is valid
  const signature = signCrypto(key, secret, JWT_TO_NODE_HASH[header.alg]);

  if (signature !== parts[2]) throw new Error("invalid token");
  // claims
  if (payload.iss !== process.env.ISSUER) throw new Error("invalid issuer");
  if (payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("token expired");
  }

  return payload;
}
module.exports = { sign, verify };
