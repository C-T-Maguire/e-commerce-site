const router = require("express").Router();
const pool = require("../db");
const bcrypt = require("bcrypt");
const jwtGen = require("../utils/jwtGen");
const validInfo = require("../middleware/validInfo");
const authorisation = require("../middleware/authorisation");

//register

router.post("/register", validInfo, async(req, res) => {
  try {

    //1. destructure the req.body (username, email, first_name, last_name, password, password2)

    const { username, email, first_name, last_name, password, password2 } = req.body

    //2. check is user exists (if exists throw Err)

    const userEmailCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if(userEmailCheck.rows.length > 0) {
      return res.status(401).json("Email already in use");
    }

    const usernameCheck = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if(usernameCheck.rows.length > 0) {
      return res.status(401).json("Username already in use");
    }

    //3. Bcyrpt user password
    if(password !== password2) {
      return res.status(401).json("Passwords do not match!");
    }

    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const bcrpytPasssword = await bcrypt.hash(password, salt);

    //4. Enter the user into Database Table

    const newUser = await pool.query(
      "INSERT INTO users (username, email, first_name, last_name, password) VALUES ($1, $2, $3, $4, $5) RETURNING *", [username, email, first_name, last_name, bcrpytPasssword]
    );

    //5. Generating our JWT token

    const token = jwtGen(newUser.rows[0].user_id);
    return res.json({token});

  } catch (err) {
    console.error(err.message)
    res.status(500).json("Server Error");
  }
});

router.post("/login", validInfo, async (req, res) => {
  try {

    //destructure req.body
    const {email, password} = req.body;

    //check if user exists if not throw err
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if(user.rows.length === 0) {
      return res.status(401).json("Password or Email is incorrect");
    }

    //check if incoming pw is the same as the DB pw

    const validPassword = await bcrypt.
    compare(
      password, 
      user.rows[0].password
    );

    if(!validPassword) {
      return res.status(401).json("Password or Email is incorrect")
    }

    //give them the jwt token
    const token = jwtGen(user.rows[0].id);
    res.json({token});
    
  } catch(err) {
    console.error(err)
    res.status(500).json("Server Error");
  }
});

router.post("/verify", authorisation, (req, res) => {
  try {
    
    res.json(true);

  } catch (err) {
    console.error(err.message)
    res.status(500).json("Server Error");
  }
})
module.exports = router;