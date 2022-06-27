const express = require("express");
const cors = require("cors");
const app = express();
const bcrypt = require("bcrypt"); //encode
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const secret = "my-login"; //token

const bodyParser = require("body-parser");
const jsonParser = bodyParser.json();

app.use(cors());

const mysql = require("mysql2");
const connection = mysql.createConnection({
  host: "localhost",
  user: "root@",
  port: 3303,
  database: "mytest",
});

app.post("/registers", jsonParser, function (req, res, next) {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    connection.execute(
      "INSERT INTO user (email, password,fname,lname) VALUE (?, ?, ?,?)",
      [req.body.email, hash, req.body.fname, req.body.lname],
      function (err, results, fields) {
        if (err) {
          res.json({ status: "err", message: err });
          return;
        }
        res.json({ status: "ok" });
      }
    );
  });
});

app.post("/login", jsonParser, function (req, res, next) {
  connection.execute(
    "SELECT * FROM user WHERE email=? ",
    [req.body.email],
    function (err, user, fields) {
      if (err) {
        res.json({ status: "err", message: err });
        return;
      }
      if (user.length == 0) {
        res.json({ status: "err", message: "no user found" });
        return;
      }
      bcrypt.compare(
        req.body.password,
        user[0].password,
        function (err, loginresult) {
          if (loginresult) {
            const token = jwt.sign({ email: user[0].email }, secret, { expiresIn: '1h' });
            res.json({ status: "ok", message: "login successful",token });
          } else {
            res.json({ status: "error", message: "login failed" });
          }
        }
      );
    }
  );
});

app.post("/authen", jsonParser, function (req, res, next) {
    try {
        const token=req.headers.authorization.split(' ')[1]
    const decoded = jwt.verify(token, secret);
    res.json({status: 'ok',decoded});
    } catch (error) {
        res.json({status: 'error',message: error.message});
    }

  });

app.listen(3333, function () {
  console.log("CORS-enabled web server listening on port 3333");
});
