const functions = require('firebase-functions');
const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");

const {google} = require("googleapis");
const admin = require("firebase-admin");
const firebase = require("firebase/app");
require("firebase/auth");

const serviceAcountKey = require("./serviceAccountKey");
admin.initializeApp({
  credential:admin.credential.cert(serviceAcountKey),
  databaseURL:"https://flashchat-2020.firebaseio.com"
});

const firebaseKey = require("./firebaseKey");
firebase.initializeApp(firebaseKey.firebaseConfig);
firebase.auth().setPersistence(firebase.auth.Auth.Persistence.NONE);

const googleApiKey = require("./googleApiKey");
const CLIENT_ID = googleApiKey.web.client_id;
const CLIENT_SECRET = googleApiKey.web.client_secret;
const REDIRECT_URL = googleApiKey.web.redirect_uris[0];
const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URL);

const app = express();
app.set("view engine", "ejs");
app.use(cookieParser());
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));

function checkIfSignedIn(url) {
  return (req, res, next)=>{
    if (req.url === url){
      const sessionCookie = req.cookies.__session || "";
      admin.auth().verifySessionCookie(sessionCookie, true)
      .then(()=> res.redirect("/profile"))
      .catch(()=>next());
    }else {
      next();
    }
  }
}
app.use(checkIfSignedIn("/"));

app.get("/", (req,res)=>{
  res.render("index");
})

app.get("/signin", (req, res)=>{
  res.render("signin");
})

app.get("/register", (req, res)=>{
  res.render("register");
})



exports.app = functions.https.onRequest(app);

