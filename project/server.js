var express = require('express');
var app = express();
const admin = require("firebase-admin");
const { getFirestore } = require('firebase-admin/firestore');
var serviceAccount = require("./key.json");
const bcrypt = require("bcrypt"); // Import bcrypt library

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = getFirestore();
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

// Function to send a file
function sendFile(res, filePath) {
  res.sendFile(__dirname + "/public" + filePath);
}

// Function to hash a password
async function hashPassword(plainPassword) {
  return await bcrypt.hash(plainPassword, 10); // 10 is the number of salt rounds
}

app.get('/signup', function (req, res) {
  sendFile(res, "/signup.html");
});

app.post('/signupSubmit', async (req, res) => {
  const { Fullname, Email, Password } = req.body;
  if (!Fullname || !Email || !Password) {
    return res.status(400).send("Please provide all required fields.");
  }

  try {
    // Check if the email already exists in the database
    const emailExists = await checkEmailExists(Email);

    if (emailExists) {
      return res.send("<script>alert('Email already exists.'); window.history.back();</script>");
    }

    const hashedPassword = await hashPassword(Password);

    // Store the hashed password in Firestore
    db.collection('Users').add({
      Fullname,
      Email,
      Password: hashedPassword // Store the hashed password
    }).then(() => {
      sendFile(res, "/login.html");
    });
  } catch (error) {
    console.error("Error hashing or adding document to Firestore: ", error);
    res.status(500).send("An error occurred while signing up.");
  }
});

// Function to check if an email already exists in the database
async function checkEmailExists(email) {
  const querySnapshot = await db.collection('Users')
    .where("Email", "==", email)
    .get();

  return !querySnapshot.empty;
}

app.get('/login', function (req, res) {
  sendFile(res, "/login.html");
});

app.post('/loginSubmit', async function (req, res) {
  const { Email, Password } = req.body;
  if (!Email || !Password) {
    return res.status(400).send("Please provide both Email and Password.");
  }

  try {
    const querySnapshot = await db.collection('Users')
      .where("Email", "==", Email)
      .get();

    if (querySnapshot.empty) {
      res.send("Login Failed");
      return;
    }

    const user = querySnapshot.docs[0].data();
    const hashedPassword = user.Password;

    const passwordMatch = await bcrypt.compare(Password, hashedPassword);

    if (passwordMatch) {
      res.redirect('/index.html');
    } else {
      res.send("Login Failed");
    }
  } catch (error) {
    console.error("Error querying Firestore or comparing passwords: ", error);
    res.status(500).send("An error occurred while attempting to log in.");
  }
});

app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});
