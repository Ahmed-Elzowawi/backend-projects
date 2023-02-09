const express = require("express");
const mysql = require("mysql");
const argon2 = require("argon2");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;

const db = mysql.createConnection({
	host: process.env.DATABASE_HOST,
	user: process.env.DATABASE_USER,
	password: process.env.DATABASE_PASSWORD,
	database: process.env.DATABASE,
});
db.connect();

app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
	res.sendFile(__dirname + "/index.html");
});

app.get("/sign-up", (req, res) => {
	res.sendFile(__dirname + "/sign-up.html");
});

app.get("/login", (req, res) => {
	res.sendFile(__dirname + "/login.html");
});

app.get("/success", (req, res) => {
	res.sendFile(__dirname + "/success.html");
});

app.post("/api/sign-up", (req, res) => {
	const { username, password } = req.body;
	db.query(
		"SELECT name FROM users WHERE name = ?",
		[username],
		async function (error, results) {
			if (error) throw error;
			if (results.length) {
				console.log("User already exists");
				res.redirect("/sign-up");
			} else {
				try {
					const hashedPassword = await argon2.hash(password);
					db.query(
						"INSERT INTO users VALUES ?",
						[[[username, hashedPassword]]],
						function (error, results) {
							if (error) throw error;
							console.log("User has been registered");
							res.redirect("/success");
						},
					);
				} catch (err) {
					console.log(err);
					res.redirect("/sign-up");
				}
			}
		},
	);
});

app.post("/api/login", (req, res) => {
	const { username, password } = req.body;
	db.query(
		"SELECT * FROM users WHERE name = ?",
		[username],
		async function (error, results) {
			if (error) throw error;
			try {
				if (
					!results.length ||
					(!await argon2.verify(results[0].password, password))
				) {
					console.log("Wrong username or password");
					res.redirect("/login");
				} else res.redirect("/success");
			} catch (err) {
				console.log(err);
				res.redirect("/login");
			}
		},
	);
});

app.listen(port, () => {
	console.log(`Listening on port ${port}`);
});
