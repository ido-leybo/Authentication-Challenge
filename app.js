/* write your server code here */
const express = require("express");
const jwt = require("jsonwebtoken");
const { hashSync, genSaltSync, compareSync } = require("bcrypt");
const app = express();
app.use(express.json());

const USERS = [
  {
    email: "admin@email.com",
    name: "admin",
    password: "$2b$10$.D81s5Ninuv6ul3QpcOzXuvzUNZWt1JSLo2288a2Sg.kd5MDGGIga",
    isAdmin: true,
  },
];
const INFORMATION = [
  {
    email: "admin@email.com",
    info: "admin info",
  },
];
const REFRESHTOKENS = [];

app.post("/users/register", (req, res) => {
  const userData = req.body;

  userData.password = hashSync(userData.password, genSaltSync());
  const currentUser = USERS.find(
    (user) => user.name === userData.name || user.email === userData.email
  );
  if (currentUser) {
    return res.status(409).send("user already exists");
  }
  USERS.push(userData);
  INFORMATION.push({ email: userData.email, info: `${userData.name} info` });
  res.status(201).send("Register Success");
});

app.post("/users/login", (req, res) => {
  const userData = req.body;
  const currentUser = USERS.find(
    (user) => user.name === userData.name || user.email === userData.email
  );
  if (!currentUser) {
    return res.status(404).send("cannot find user");
  } else {
    const correct = compareSync(userData.password, currentUser.password);
    if (!correct) {
      return res.status(403).send("User or Password incorrect");
    }
  }
  const accessToken = jwt.sign({ userData }, "secretKey", { expiresIn: "10s" });
  const refreshToken = jwt.sign({ userData }, "secretRefreshKey", {
    expiresIn: "1d",
  });
  REFRESHTOKENS.push(refreshToken);
  res.status(200).json({
    accessToken: accessToken,
    refreshToken: refreshToken,
    name: userData.name,
    email: userData.email,
    isAdmin: currentUser.isAdmin,
  });
});

app.get("/api/v1/information", (req, res) => {
  const bearerToken = req.get("authorization");
  if (!bearerToken) {
    return res.status(401).send("Access Token Required");
  }
  const token = bearerToken.slice(7);
  const user = jwt.verify(token, "secretKey");

  if (!user.userData) {
    return res.status(403).send("Invalid Access Token");
  }
  const userInfo = INFORMATION.filter(
    (item) => item.email === user.userData.email
  );
  res.status(200).json(userInfo);
});

app.get("/api/v1/users", (req, res) => {
  const bearerToken = req.get("authorization");

  if (!bearerToken) {
    return res.status(401).send("Access Token Required");
  }
  const token = bearerToken.slice(7);
  //   console.log(token);
  const user = jwt.verify(token, "secretKey");

  if (!user.userData) {
    return res.status(403).send("Invalid Access Token");
  }

  res.status(200).json(USERS);
});

app.post("/users/logout", (req, res) => {
  const token = req.body.token;
  if (!token) {
    return res.status(400).send("Refresh Token Required");
  }
  const currentToken = REFRESHTOKENS.find(
    (refreshToken) => refreshToken === token
  );
  if (!currentToken) {
    return res.status(400).send("Invalid Refresh Token");
  }
  res.status(200).send("User Logged Out Successfully");
});

// function verifyToken(req, res, next) {
//   const bearerHeader = req.headers["authorization"];
//   if (typeof bearerHeader !== "undefined") {
//     const bearer = bearerHeader.split(" ");
//     const bearerToken = bearer[1];
//     req.token = bearerToken;
//     next();
//   } else {
//     res.sendStatus(403);
//   }
// }
module.exports = app;
