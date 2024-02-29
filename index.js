import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import express from "express";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import name from "./features.js";
import path from "path";

mongoose
  .connect("mongodb://localhost:27017", {
    dbname: "backend",
  })
  .then(() => {
    console.log("Database Connected");
  })
  .catch((e) => console.log(e));

const userschema = new mongoose.Schema({
  name: String,
  email: String,
  password:String,
});
const User = mongoose.model("User", userschema);

const app = express();

app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(cookieParser());

const isauthenticated = async (req, res, next) => {
  const { token } = req.cookies;

  if (token) {
    const decoder = jwt.verify(token, "uigfiuhweoihiug");
    req.user = await User.findById(decoder._id);
    console.log(decoder);

    next();
  } else {
   res.redirect("/login");
  }
};


app.get("/", isauthenticated, (req, res) => {
  res.render("logout", { name: req.user.name });
});

app.get("/login",(req,res)=>{
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});


app.post("/login",async(req,res)=>{
  const {email,password}=req.body;
 let user=await User.findOne({email})
 if(!user){
 return res.redirect("/register")
 }
 const ismatch=await bcrypt.compare(password,user.password);
 if(!ismatch) return res.render("login",{email,message:"Incorrect Password"});
 
 const token = jwt.sign({ _id: user._id }, "uigfiuhweoihiug");

 res.cookie("token", token, {
   httpOnly: true,
   expires: new Date(Date.now() + 60 * 1000),
 });
 res.redirect("/");
})

app.post("/register", async (req, res) => {
  const { name, email,password } = req.body;

  let user = await User.findOne({ email });
  if (user) {
    return res.redirect("/login");
  }
  const hashedpassword=await bcrypt.hash(password,10)
  user = await User.create({
    name,
    email,
    password:hashedpassword,
  });

  const token = jwt.sign({ _id: user._id }, "uigfiuhweoihiug");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });
  res.redirect("/");
 
});

app.get("/logout", (req, res) => {
  res.cookie("token", null, {
    expires: new Date(Date.now()),
  });
  res.redirect("/");
});

app.listen(5000, () => {
  console.log("server is working");
});
