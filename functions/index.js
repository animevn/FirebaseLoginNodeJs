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
});

app.get("/signin", (req, res)=>{
  res.render("signin");
});

app.post("/signin", (req, res)=>{
  const email = req.body.email;
  const password = req.body.password;
  firebase.auth().signInWithEmailAndPassword(email, password).then(()=>setCookies(res))
  .catch(err=>{
    console.log(err);
    res.redirect("/");
  });
});

app.get("/register", (req, res)=>{
  res.render("register");
});

app.post("/register", (req, res)=>{
  const email = req.body.email;
  const password = req.body.password;
  firebase.auth().createUserWithEmailAndPassword(email, password).then(()=>setCookies(res))
  .catch(err=>{
    console.log(err);
    res.redirect("/");
  })
});

app.get("/google-auth", (req, res)=>{
  const url = oAuth2Client.generateAuthUrl({
    access_type: "offline",
    //userinfo.email and userinfo.profile are minimum needed to access user profile
    scope: ["https://www.googleapis.com/auth/userinfo.email",
      "https://www.googleapis.com/auth/userinfo.profile"]
  });
  //redirect to auth url
  res.redirect(url);
});

//setCookies for current firebase user
function setCookies(res){
  firebase.auth().currentUser.getIdToken().then(idToken=>{
    //cookie expires in one day
    const timeOut = 60 * 60 * 24 * 1000;
    admin.auth().verifyIdToken(idToken).then(decodedClaims=>{
      //force user to re-signin after 60 minutes
      if (new Date().getTime()/1000 - decodedClaims.auth_time < 60 * 60) {
        return admin.auth().createSessionCookie(idToken, {expiresIn: timeOut});
      }
      throw new Error("PLEASE SIGN IN AGAIN");
    }).then(sessionCookie=>{
      const options = {maxAge:timeOut, httpOnly:true, secure:false};
      res.cookie("__session", sessionCookie, options);
      res.redirect("/profile");
      res.end();
    }).catch(()=>res.status(401).send("UNAUTHORISED REQUEST"));
  })
}

//process redirects from google, /auth/google/callback is defined in google api credential, and
//can be changed to other name
app.get("/auth/google/callback", (req, res)=>{
  const code = req.query;
  if (code){
    oAuth2Client.getToken(code, (err, token)=>{
      if (err){
        console.log(err);
        res.redirect("/");
      }else {
        let credential = firebase.auth.GoogleAuthProvider.credential(token.id_token);
        firebase.auth().signInWithCredential(credential).then(()=> setCookies(res))
        .catch(err=>{console.log(err); res.redirect("/");})
      }
    });
  }
});

app.get("/profile", (req, res)=>{
  const sessionCookie = req.cookies.__session || "";
  admin.auth().verifySessionCookie(sessionCookie, true).then(decodedClaims=>{
    const uid = decodedClaims.uid;
    res.render("profile", {userUID:uid});
  }).catch(err=>{
    console.log(err);
    res.redirect("/");
  })
});

app.get("/logout", (req, res)=>{
  const sessionCookie = req.cookies.__session || "";
  res.clearCookie("__session");
  if (sessionCookie){
    admin.auth().verifySessionCookie(sessionCookie, true).then(decodedClaims=>{
      return admin.auth().revokeRefreshTokens(decodedClaims.sub);
    }).then(()=> res.redirect("/")).catch(()=>res.redirect("/"));
  }else {res.redirect("/")}
});

app.get("/delete", (req, res)=>{
  const sessionCookie = req.cookies.__session || "";
  res.clearCookie("__session");
  if (sessionCookie){
    admin.auth().verifySessionCookie(sessionCookie, true).then(decodedClaims=>{
      return admin.auth().revokeRefreshTokens(decodedClaims.sub).then(()=>
        admin.auth().deleteUser(decodedClaims.sub)).then(()=>res.redirect("/"));
    }).catch(()=>res.redirect("/"));
  }else {res.redirect("/")}
});

//redirect wrong routes to index
app.get("**", (req, res) => {
  res.status(404).redirect("/");
});

exports.app = functions.https.onRequest(app);

