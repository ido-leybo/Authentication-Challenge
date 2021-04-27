/* write your server code here */
const express = require("express");
const jwt = require("jsonwebtoken");
const { hashSync, genSaltSync, compareSync } = require("bcrypt");
const e = require("express");
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
  const accessToken = jwt.sign({ userData }, "secretKey", { expiresIn: 10 });
  const refreshToken = jwt.sign({ userData }, "secretRefreshKey");
  REFRESHTOKENS.push(refreshToken);
  res.status(200).json({
    accessToken: accessToken,
    refreshToken: refreshToken,
    name: userData.name,
    email: userData.email,
    isAdmin: currentUser.isAdmin,
  });
});

app.get("/api/v1/information", verifyToken, (req, res) => {
  const user = req.user;
  console.log(user);
  console.log(INFORMATION);

  const userInfo = INFORMATION.filter((item) => {
    console.log(item);
    console.log(user);
    return item.email === user.email;
  });
  console.log(userInfo);
  res.status(200).send(userInfo);
});

app.get("/api/v1/users", verifyToken, (req, res) => {
  const user = req.user;
  const adminValid = USERS.find((i) => i.email === user.email);
  if (!adminValid.isAdmin) return res.status(403).send("Not Required");
  res.status(200).send(USERS);
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

app.post("/users/token", async (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.status(401).send("Refresh Token Required");
  const currentToken = REFRESHTOKENS.find((token) => token === refreshToken);
  if (!currentToken) return res.status(403).send("Invalid Refresh Token");
  jwt.verify(currentToken, "secretRefreshKey", (err, authData) => {
    if (err) {
      return res.status(403).send("Not Required");
    } else {
      const accessToken = jwt.sign(authData.userData, "secretKey", {
        expiresIn: 10,
      });
      return res.status(200).json({ accessToken });
    }
  });
});

app.options("/", (req, res) => {
  const bearerHeader = req.headers["authorization"];
  if (!bearerHeader) {
    return res.status(200).send([
      {
        method: "post",
        path: "/users/register",
        description: "Register, Required: email, name, password",
        example: {
          body: { email: "user@email.com", name: "user", password: "password" },
        },
      },
      {
        method: "post",
        path: "/users/login",
        description: "Login, Required: valid email and password",
        example: { body: { email: "user@email.com", password: "password" } },
      },
    ]);
  } else {
    const token = bearerHeader.split(" ")[1];
    jwt.verify(token, "secretKey", (err, authData) => {
      if (err) {
        return res.status(200).send([
          {
            method: "post",
            path: "/users/register",
            description: "Register, Required: email, name, password",
            example: {
              body: {
                email: "user@email.com",
                name: "user",
                password: "password",
              },
            },
          },
          {
            method: "post",
            path: "/users/login",
            description: "Login, Required: valid email and password",
            example: {
              body: { email: "user@email.com", password: "password" },
            },
          },
          {
            method: "post",
            path: "/users/token",
            description: "Renew access token, Required: valid refresh token",
            example: { headers: { token: "*Refresh Token*" } },
          },
        ]);
      }
      const adminValid = USERS.find((i) => i.email === authData.userData.email);
      if (!adminValid.isAdmin) {
        return res.status(200).send([
          {
            method: "post",
            path: "/users/register",
            description: "Register, Required: email, name, password",
          },
          {
            method: "post",
            path: "/users/login",
            description: "Login, Required: valid email and password",
          },
          {
            method: "post",
            path: "/users/token",
            description: "Renew access token, Required: valid refresh token",
          },
          {
            method: "get",
            path: "/api/v1/information",
            description:
              "Access user's information, Required: valid access token",
          },
          {
            method: "post",
            path: "/users/logout",
            description: "Logout, Required: access token",
          },
          {
            method: "post",
            path: "/users/tokenValidate",
            description:
              "Access Token Validation, Required: valid access token",
          },
        ]);
      } else {
        return res.status(200).send([
          {
            method: "post",
            path: "/users/register",
            description: "Register, Required: email, name, password",
          },
          {
            method: "post",
            path: "/users/login",
            description: "Login, Required: valid email and password",
          },
          {
            method: "post",
            path: "/users/token",
            description: "Renew access token, Required: valid refresh token",
          },
          {
            method: "post",
            path: "/users/tokenValidate",
            description:
              "Access Token Validation, Required: valid access token",
          },
          {
            method: "get",
            path: "/api/v1/information",
            description:
              "Access user's information, Required: valid access token",
          },
          {
            method: "post",
            path: "/users/logout",
            description: "Logout, Required: access token",
          },
          {
            method: "get",
            path: "api/v1/users",
            description:
              "Get users DB, Required: Valid access token of admin user",
          },
        ]);
      }
    });
  }
});

function verifyToken(req, res, next) {
  const bearerHeader = req.headers["authorization"];
  if (typeof bearerHeader !== "undefined") {
    const token = bearerHeader.split(" ")[1];
    jwt.verify(token, "secretKey", (err, authData) => {
      if (err) {
        return res.status(403).send("Invalid Access Token");
      } else {
        req.user = authData.userData ? authData.userData : authData;
        next();
      }
    });
  } else {
    return res.status(401).send("Access Token Required");
  }
}

module.exports = app;
