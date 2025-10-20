// backend/server.js
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from 'dotenv';
dotenv.config();
import fs from "fs";
import csvParser from "csv-parser";
import multer from "multer";
import { GoogleGenAI } from "@google/genai";
import bcrypt from "bcrypt";
import jwt from 'jsonwebtoken';


const ai = new GoogleGenAI({});
async function portfolioAnalysis(portfolio) {
  
  try {
    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash-lite",
      contents: 
`Give me up to 5 clear, actionable suggestions to improve this portfolio: ${JSON.stringify(portfolio)}. Focus on risk diversification, sector balance, and growth potential. Return the response as a JSON array. Each item should have:
- "title": a short, plain-language summary of the suggestion
- "description": a simple explanation of why this change helps, written for newer investors

Avoid introductions, conclusions, or formatting like bold text. Keep the tone helpful and easy to understand.
Return only the JSON array.`,

    });
    return response.text;
  } catch (err) {
    console.error("Google GenAI error:", err.message);
  }
}


mongoose.connect(`mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@cluster0.aamrcye.mongodb.net/InvestiSmart`, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(async () => {
    console.log("MongoDB Atlas connected");
}).catch(err => console.error(err));

const userSchema = new mongoose.Schema({
    username: String,
    password: String,    
}, { versionKey: false });
const User = mongoose.model("logindatas", userSchema);


const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));




//Article fetch route for dashboard
const articleSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: String,
  topics: [String]
}, { timestamps: true });
const Article = mongoose.model("articles", articleSchema);

app.get("/articles", async (req, res) => {
  try {
    const auth = await AuthenticateToken(req,res);

    if (auth.status != 200) {

      return res.status(auth.status).json({ message: auth.message });
    }
    const articles = await Article.find().sort({ createdAt: -1 });
    res.json(articles);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch articles" });
  }
});



// Get single article
app.get("/articles/:id", async (req, res) => {
  try {
    const auth = await AuthenticateToken(req,res);
    if (auth.status !== 200) {
      return res.status(auth.status).json({ message: "Invalid token" });
    }
    const article = await Article.findById(req.params.id);
    if (!article) return res.status(404).json({ message: "Article not found" });
    res.json(article);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch article" });
  }
});

// Logout route
app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });

  res.json({ message: "Logout successful" });
});

// Token verification API endpoint
app.post("/verifyToken", async (req, res) => {
  const auth = await AuthenticateToken(req);
  if (auth.status !== 200) {
    return res.status(auth.status).json({ message: auth.message });
  }
  res.json({ message: "Token is valid" });
});



// signup route
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    const token = jwt.sign({ userId: username }, process.env.JWT_SECRET, {
    expiresIn: "1h",
    });

    res.cookie("token", token, {
      httpOnly: true, 
      secure: true,   
      sameSite: "strict", 
      maxAge: 60 * 60 * 1000 
    });
    res.json({ message: "Login successful" });
  } 
  catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


//LOGIN SECTION
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  
  if (!user) return res.status(401).json({ message: "Invalid username or password" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ message: "Invalid username or password" });

  const token = jwt.sign({ userId: username }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });

  res.cookie("token", token, {
    httpOnly: true, 
    secure: true,   
    sameSite: "strict", 
    maxAge: 60 * 60 * 1000 
  });

  res.json({ message: "Login successful" });
});


app.listen(5000, () => console.log("Backend running at http://localhost:5000"));


//TOKEN AUTHENTICATION FUNCTION
async function AuthenticateToken(req) {
  const token = req.cookies.token;
  if (!token) return { status: 401, message: "No token provided" };

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ username: decoded.userId });
    if (!user) return { status: 403, message: "Invalid token" };

    req.user = user;
    return { status: 200, message: "VALIDATED" };
  } catch (err) {
    return { status: 403, message: "Invalid token" };
  }
}



//UPLOAD SECTION
const upload = multer({ dest: "uploads/" });

const portfolioSchema = new mongoose.Schema({
  username: { type: String, required: true },
  holdings: [
    {
      code: String,
      stock: String,
      units: Number,
      pricePence: Number,
      value: Number,
      cost: Number,
      gainLoss: Number,
      gainLossPercent: Number,
    },
  ],
  analysis: String,
  lastAnalysis: { type: Date, default: null }
}, { timestamps: true });

const Portfolio = mongoose.model("Portfolio", portfolioSchema);

const headers = [
  "Code",
  "Stock",
  "Units held",
  "Price (pence)",
  "Value (£)",
  "Cost (£)",
  "Gain/loss (£)",
  "Gain/loss (%)"
];

//UPLOADING THE CSV
app.post("/upload-csv", upload.single("file"), async (req, res) => {
  try {
    const auth = await AuthenticateToken(req,res);
    
    if (auth.status !== 200) {
      return res.status(auth.status).json({ message: "Invalid token" });
    }

    const username = req.user.username;
    const allRows = [];
    fs.createReadStream(req.file.path)
      .pipe(csvParser({ headers, skipEmptyLines: true }))
      .on("data", (row) => {
        allRows.push(row);
      })
      .on("end", async () => {
        fs.unlinkSync(req.file.path);

        let holdingsRows;

        if (
          allRows[allRows.length - 1]['Code'] ===
          "Shares are valued at the bid-price, delayed by 15 minutes. Funds are valued at the most recent bid-price."
        ) {
          holdingsRows = allRows.slice(11, allRows.length - 2);
        } else {
          holdingsRows = allRows.slice(11, allRows.length - 4);
        }

        const cleanNumber = (str) => {
          if (typeof str !== "string") return 0;
          const cleaned = str.replace(/,/g, "").trim();
          return isNaN(cleaned) ? 0 : Number(cleaned);
        };

        const holdings = holdingsRows.map(row => ({
          code: row["Code"]?.trim() || "",
          stock: row["Stock"]?.trim() || "",
          units: cleanNumber(row["Units held"]),
          pricePence: cleanNumber(row["Price (pence)"]),
          value: cleanNumber(row["Value (£)"]),
          cost: cleanNumber(row["Cost (£)"]),
          gainLoss: cleanNumber(row["Gain/loss (£)"]),
          gainLossPercent: cleanNumber(row["Gain/loss (%)"]),
        }));

        const analysis = await portfolioAnalysis(holdings);
        const lastAnalysisDate = new Date();

        // Save to MongoDB
        await Portfolio.findOneAndUpdate(
          { username },
          { holdings, analysis: analysis, lastAnalysis: lastAnalysisDate },
          { upsert: true }
        );

        res.json({ message: "CSV uploaded and processed", holdings, analysis });
      });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to process CSV" });
  }
});


//PORTFOLIO DOWNLOAD
app.get("/portfolio", async (req,res) => {
  try {    

    const auth = await AuthenticateToken(req,res);
    if (auth.status !== 200){
      return res.status(auth.status).json({ message: "Invalid token" });
    }
    
    const username = req.user.username;

    const portfolio = await Portfolio.findOne({ username });
    if (!portfolio) {
      return res.status(404).json({ message: "Portfolio not found" });
    }
    res.json(portfolio);
    /*

    Removed to avoid accessive GenAI calls. Make user upload new, updated CSV if they want fresh analysis.

    if (!portfolio.lastAnalysis || (new Date(portfolio.lastAnalysis) < new Date(Date.now() - 24*60*60*1000))) {
      const analysis = await portfolioAnalysis(portfolio.holdings);
      portfolio.analysis = analysis;
      portfolio.lastAnalysis = new Date();
      await portfolio.save();
    }
  
    */
  } 
  catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to retrieve portfolio" });
  }
});