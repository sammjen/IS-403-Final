// william gifford, waylan abbott, luke hooper, sam jenson
// good-news app (bare-bones)
// section: Node + Express + EJS with Knex + PostgreSQL (pgcrypto)
// Notes:
// - No async/await: uses .then()/.catch() style
// - Password hashing uses PostgreSQL crypt() (pgcrypto). See REGISTER route.
// - Sessions used for auth. req.session.isLoggedIn, req.session.user
// - Minimal validation for brevity — add as needed.

// setting up the necessary libraries and paths to make our website work
require('dotenv').config();

const express = require("express");
const session = require("express-session");
const path = require("path");
// this is the library used to filter out bad news
const Sentiment = require("sentiment");
const sentiment = new Sentiment();
// setting up our database
const knex = require("knex")({
    client: "pg",
    connection: {
        host: process.env.RDS_HOSTNAME || "localhost",
        user: process.env.RDS_USERNAME || "postgres",
        password: process.env.RDS_PASSWORD || "admin",
        database: process.env.RDS_DB_NAME || "goodnewsnetwork",
        port: process.env.RDS_PORT || 5432,
        ssl: process.env.DB_SSL ? {rejectUnauthorized: false} : false
    }
});

const app = express();

// ---------------------------
// SESSION CONFIG
// ---------------------------
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'fallback-secret-key',
        resave: false,
        saveUninitialized: false
    })
);

// ---------------------------
// BODY PARSER
// ---------------------------
app.use(express.urlencoded({ extended: true }));

// ---------------------------
// STATIC FILES
// ---------------------------
app.use(express.static(path.join(__dirname, "public")));

// ---------------------------
// EJS
// ---------------------------
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// ---------------------------
// LOGIN MIDDLEWARE (public feed allowed)
// ---------------------------
// Allow paths: '/', '/feed', '/login', '/register', '/post/:id' for unauthenticated users.
// Others require login (adding posts, reacting, replying, deleting).
app.use((req, res, next) => {
    const publicPaths = [
        '/', '/feed', '/login', '/register', '/logout'
    ];
    // allow static assets
    if (req.path.startsWith('/public')) return next();

    // Allow GET /post/:id without login
    if (req.path.startsWith('/post/')) return next();

    // Allow if path in publicPaths
    if (publicPaths.includes(req.path)) return next();

    // If logged in continue
    if (req.session.isLoggedIn) return next();

    // Otherwise show login page
    return res.render("login", { error_message: "Please log in to access that page" });
});

// ---------------------------
// ROUTES
// ---------------------------

// Landing -> redirect to feed
app.get("/", (req, res) => {
    res.redirect("/feed");
});

// FEED (public) - newest first
app.get("/feed", (req, res) => {
    // We want: submissions (newest first), author info (if available),
    // reaction totals, per-reaction breakdown, and current user's reaction.
    knex
        .select(
            "submissions.subid",
            "submissions.subtext",
            "submissions.subnegativestatus",
            "submissions.subdate",
            "submissions.userid as authorid",
            "users.userfirstname",
            "users.userlastname"
        )
        .from("submissions")
        .leftJoin("users", "submissions.userid", "users.userid")
        .orderBy("submissions.subdate", "desc")
        .then(subs => {
            const subIds = subs.map(s => s.subid);

            if (subIds.length === 0) {
                return Promise.resolve({
                    subs: subs,
                    totals: {},
                    breakdown: {},
                    myReactions: {}
                });
            }

            // Per-reaction counts: one row per (subid, reactionid)
            const breakdownQ = knex("subreactions")
                .select("subid", "reactionid")
                .count("* as cnt")
                .whereIn("subid", subIds)
                .groupBy("subid", "reactionid");

            // Current user's reactions per post
            const myReactionsQ = req.session.isLoggedIn ?
                knex("subreactions")
                    .select("subid", "reactionid")
                    .whereIn("subid", subIds)
                    .andWhere("userid", req.session.user.userid)
                : Promise.resolve([]);

            return Promise.all([breakdownQ, myReactionsQ]).then(([breakdownRows, myReRows]) => {
                const totals = {};          // subid -> total reaction count
                const breakdown = {};       // subid -> { reactionid -> count }

                breakdownRows.forEach(r => {
                    const sid = r.subid;
                    const rid = r.reactionid;
                    const cnt = parseInt(r.cnt, 10);

                    if (!breakdown[sid]) breakdown[sid] = {};
                    breakdown[sid][rid] = cnt;

                    totals[sid] = (totals[sid] || 0) + cnt;
                });

                const myReactions = {};
                myReRows.forEach(r => { myReactions[r.subid] = r.reactionid; });

                return { subs, totals, breakdown, myReactions };
            });
        })
        .then(result => {
            // Render feed
            res.render("feed", {
                submissions: result.subs,
                reactionCounts: result.totals,
                reactionBreakdown: result.breakdown,
                myReactions: result.myReactions,
                currentUser: req.session.user || null,
                error_message: ""
            });
        })
        .catch(err => {
            console.error("Error loading feed:", err.message);
            res.render("feed", {
                submissions: [],
                reactionCounts: {},
                reactionBreakdown: {},
                myReactions: {},
                currentUser: req.session.user || null,
                error_message: "Database error: " + err.message
            });
        });
});

// REGISTER (GET)
app.get("/register", (req, res) => {
    res.render("register", { error_message: "" });
});

// REGISTER (POST) - fixed to avoid double render bug
app.post("/register", (req, res) => {
    const { firstname, lastname, email, password } = req.body;

    if (!firstname || !lastname || !email || !password) {
        return res.render("register", { error_message: "All fields required" });
    }

    // Check if email already exists
    knex("users")
        .where("useremail", email)
        .first()
        .then(user => {
            if (user) {
                // Email already registered → render once and stop the chain
                res.render("register", {
                    error_message: "Email already registered"
                });
                return null; // important: prevents the next .then() from running
            }

            // Insert hashed password and return all user info
            return knex.raw(
                `INSERT INTO users (userfirstname, userlastname, useremail, userpassword)
                 VALUES (?, ?, ?, crypt(?, gen_salt('bf')))
                 RETURNING userid, userfirstname, userlastname, useremail, manager`,
                [firstname, lastname, email, password]
            );
        })
        .then(result => {
            // If result is null, we already handled response (duplicate email)
            if (!result) return;

            if (!result.rows || result.rows.length === 0) {
                return res.render("register", { error_message: "Registration error" });
            }

            const newUser = result.rows[0];

            // Auto login
            req.session.isLoggedIn = true;
            req.session.user = {
                userid: newUser.userid,
                userfirstname: newUser.userfirstname,
                userlastname: newUser.userlastname,
                useremail: newUser.useremail,
                manager: newUser.manager
            };

            // Redirect to feed
            res.redirect("/feed");
        })
        .catch(err => {
            console.error("Register error:", err.message);
            // Only render if headers not already sent
            if (!res.headersSent) {
                res.render("register", { error_message: "Registration error" });
            }
        });
});

// LOGIN (GET) - show login form
app.get("/login", (req, res) => {
    res.render("login", { error_message: "" });
});

// LOGIN (POST)
app.post("/login", (req, res) => {
    const sEmail = req.body.email;
    const sPassword = req.body.password;

    if (!sEmail || !sPassword) {
        return res.render("login", { error_message: "Email and password required" });
    }

    knex.raw(
        `SELECT userid, userfirstname, userlastname, useremail, manager
         FROM users
         WHERE useremail = ?
         AND userpassword::text = crypt(?, userpassword::text)`,
        [sEmail, sPassword]
    )
        .then(result => {
            const users = result.rows;
            if (users.length > 0) {
                req.session.isLoggedIn = true;
                req.session.user = users[0];
                res.redirect("/feed");
            } else {
                res.render("login", { error_message: "Invalid login" });
            }
        })
        .catch(err => {
            console.error("Login error:", err.message);
            res.render("login", { error_message: "Invalid login" });
        });
});

// LOGOUT
app.get("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) console.error("Session destroy error:", err);
        res.redirect("/feed");
    });
});

// NEW POST (GET)
app.get("/newpost", (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    res.render("newPost", { error_message: "", currentUser: req.session.user });
});

// NEW POST (POST)
// NEW POST (POST)
app.post("/newpost", (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    const { subtext } = req.body;
    if (!subtext || subtext.trim().length === 0) {
        return res.render("newPost", { 
            error_message: "Post content cannot be empty.", 
            currentUser: req.session.user 
        });
    }

    // --- START FILTER LOGIC ---
    const analysis = sentiment.analyze(subtext);
    
    // If the score is negative (e.g., less than 0), block the post
    if (analysis.score < 0) {
        return res.render("newPost", { 
            // Send them back to the form with an error
            error_message: "Oops! We only allow Good News here. Your post was detected as negative.", 
            currentUser: req.session.user 
        });
    }
    // --- END FILTER LOGIC ---

    knex("submissions")
      .insert({
          userid: req.session.user.userid,
          subtext: subtext,
          subnegativestatus: false, // It passed the filter, so this is false
          subdate: knex.fn.now()
      })
      .then(() => {
          res.redirect("/feed");
      })
      .catch(err => {
          console.error("Add post error:", err.message);
          res.render("newPost", { 
              error_message: "Error adding post: " + err.message, 
              currentUser: req.session.user 
          });
      });
});

// VIEW SINGLE POST (public)
// VIEW SINGLE POST (public)
app.get("/post/:id", (req, res) => {
    const postId = req.params.id;

    // Get post and author (if any)
    knex
        .select(
            "submissions.subid",
            "submissions.subtext",
            "submissions.subnegativestatus",
            "submissions.subdate",
            "submissions.userid as authorid",
            "users.userfirstname",
            "users.userlastname"
        )
        .from("submissions")
        .leftJoin("users", "submissions.userid", "users.userid")
        .where("submissions.subid", postId)
        .first()
        .then(post => {
            if (!post) {
                return res.render("post", {
                    post: null,
                    replies: [],
                    reactionCounts: 0,
                    reactionBreakdown: {},
                    myReaction: null,
                    currentUser: req.session.user,
                    error_message: "Post not found"
                });
            }

            // Per-reaction breakdown for this single post
            const breakdownQ = knex("subreactions")
                .select("reactionid")
                .count("* as cnt")
                .where("subid", postId)
                .groupBy("reactionid");

            // Get replies with author info
            const repliesQ = knex("replies")
                .select(
                    "replies.replyid",
                    "replies.replytext",
                    "replies.replydate",
                    "replies.userid as authorid",
                    "users.userfirstname",
                    "users.userlastname"
                )
                .leftJoin("users", "replies.userid", "users.userid")
                .where("replies.subid", postId)
                .orderBy("replies.replydate", "asc");

            // Current user's reaction
            const myReactionQ = req.session.isLoggedIn
                ? knex("subreactions")
                    .select("reactionid")
                    .where({ subid: postId, userid: req.session.user.userid })
                    .first()
                : Promise.resolve(null);

            return Promise.all([breakdownQ, repliesQ, myReactionQ]).then(([breakdownRows, replies, myRe]) => {
                let total = 0;
                const breakdownMap = {};
                breakdownMap[postId] = {};

                breakdownRows.forEach(r => {
                    const rid = r.reactionid;
                    const cnt = parseInt(r.cnt, 10);
                    breakdownMap[postId][rid] = cnt;
                    total += cnt;
                });

                const myReaction = myRe ? myRe.reactionid : null;

                // Check if the URL has ?error=negative
                let errorMsg = "";
                if (req.query.error === 'negative') {
                    errorMsg = "Oops! We only allow Good News here. Your reply was detected as negative.";
                }

                res.render("post", {
                    post: post,
                    replies: replies,
                    reactionCounts: total,
                    reactionBreakdown: breakdownMap,
                    myReaction: myReaction,
                    currentUser: req.session.user || null,
                    error_message: errorMsg
                });
            });
        })
        .catch(err => {
            console.error("Error loading post:", err.message);
            res.render("post", {
                post: null,
                replies: [],
                reactionCounts: 0,
                reactionBreakdown: {},
                myReaction: null,
                currentUser: req.session.user || null,
                error_message: "Database error: " + err.message
            });
        });
});

// REPLY (POST)
app.post("/reply/:id", (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    const subId = req.params.id;
    const { replytext } = req.body;

    if (!replytext || replytext.trim().length === 0) {
        return res.redirect(`/post/${subId}`);
    }

    // --- START FILTER LOGIC ---
    const analysis = sentiment.analyze(replytext);

    if (analysis.score < 0) {
        // Redirect back to the post, but add ?error=negative to the URL
        return res.redirect(`/post/${subId}?error=negative`);
    }
    // --- END FILTER LOGIC ---

    knex("replies")
      .insert({
          userid: req.session.user.userid,
          subid: subId,
          replytext: replytext,
          replynegativestatus: false,
          replydate: knex.fn.now()
      })
      .then(() => {
          res.redirect(`/post/${subId}`);
      })
      .catch(err => {
          console.error("Reply error:", err.message);
          res.redirect(`/post/${subId}`);
      });
});
app.post("/react", (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.status(401).json({ error: "Login required" });
    }

    const subId = req.body.subid;
    const reactionId = req.body.reactionid;
    const userId = req.session.user.userid;

    if (!subId || !reactionId) {
        return res.status(400).json({ error: "subid and reactionid required" });
    }

    const sql = `
        INSERT INTO subreactions (subid, userid, reactionid, reactiondate)
        VALUES (?, ?, ?, NOW())
        ON CONFLICT (subid, userid)
        DO UPDATE SET reactionid = EXCLUDED.reactionid, reactiondate = NOW()
        RETURNING subid
    `;

    knex.raw(sql, [subId, userId, reactionId])
        .then(() => {
            res.redirect(req.get("Referrer") || "/feed");
        })
        .catch(err => {
            console.error("React error:", err);
            res.redirect(req.get("Referrer") || "/feed");
        });
});

//unreact
app.post("/unreact", (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    const subId = req.body.subid;
    const userId = req.session.user.userid;

    knex("subreactions")
        .where({ subid: subId, userid: userId })
        .del()
        .then(() => {
            res.redirect(req.get("Referrer") || "/feed");
        })
        .catch(err => {
            console.error("Unreact error:", err.message);
            res.redirect(req.get("Referrer") || "/feed");
        });
});

// DELETE POST (POST) - only manager OR post owner can delete
app.post("/deletePost/:id", (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    const postId = req.params.id;

    // Load post owner
    knex("submissions").select("userid").where("subid", postId).first()
        .then(post => {
            if (!post) {
                return res.redirect("/feed");
            }

            const isOwner = post.userid === req.session.user.userid;
            const isManager = !!req.session.user.manager;

            if (!isOwner && !isManager) {
                return res.status(403).send("Not authorized to delete this post");
            }

            // Delete the submission (this will cascade delete subreactions and replies per schema)
            return knex("submissions").where("subid", postId).del()
                .then(() => {
                    res.redirect("/feed");
                });
        })
        .catch(err => {
            console.error("Delete post error:", err.message);
            res.redirect("/feed");
        });
});

// ---------------------------
// START SERVER
// ---------------------------
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Good News Server running on port ${port}`);
});
