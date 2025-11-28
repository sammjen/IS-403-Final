// william gifford
// good-news app (bare-bones)
// section: Node + Express + EJS with Knex + PostgreSQL (pgcrypto)
// Notes:
// - No async/await: uses .then()/.catch() style
// - Password hashing uses PostgreSQL crypt() (pgcrypto). See REGISTER route.
// - Sessions used for auth. req.session.isLoggedIn, req.session.user
// - Minimal validation for brevity — add as needed.

require('dotenv').config();

const express = require("express");
const session = require("express-session");
const path = require("path");
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
    // We want: submissions (newest first), author info (if available), reaction counts,
    // and the current user's reaction for each post (if logged in).
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
          // Reaction counts
          if (subIds.length === 0) {
              return Promise.resolve({subs: subs, counts: {}, myReactions: {}});
          }

          const countsQ = knex("subreactions")
            .select("subid")
            .count("reactionid as cnt")
            .whereIn("subid", subIds)
            .groupBy("subid");

          const myReactionsQ = req.session.isLoggedIn ?
            knex("subreactions").select("subid", "reactionid").whereIn("subid", subIds).andWhere("userid", req.session.user.userid)
            : Promise.resolve([]);

          return Promise.all([countsQ, myReactionsQ]).then(([countsRows, myReRows]) => {
              const counts = {};
              countsRows.forEach(r => { counts[r.subid] = parseInt(r.cnt, 10); });

              const myReactions = {};
              myReRows.forEach(r => { myReactions[r.subid] = r.reactionid; });

              return {subs, counts, myReactions};
          });
      })
      .then(result => {
          // Render feed
          res.render("feed", {
              submissions: result.subs,
              reactionCounts: result.counts,
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

// REGISTER (POST)
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
                return res.render("register", {
                    error_message: "Email already registered"
                });
            }

            // Insert hashed password and return all user info
            return knex.raw(
                `INSERT INTO users (userfirstname, userlastname, useremail, userpassword)
                 VALUES (?, ?, ?, crypt(?, gen_salt('bf')))
                 RETURNING userid, userfirstname, userlastname, useremail`,
                [firstname, lastname, email, password]
            );
        })
        .then(result => {
            if (!result || !result.rows || result.rows.length === 0) {
                return res.render("register", { error_message: "Registration error" });
            }

            const newUser = result.rows[0];

            // Auto login
            req.session.isLoggedIn = true;
            req.session.user = {
                userid: newUser.userid,
                userfirstname: newUser.userfirstname,
                userlastname: newUser.userlastname,
                useremail: newUser.useremail
            };

            // Redirect to feed
            res.redirect("/feed");
        })
        .catch(err => {
            console.error("Register error:", err.message);
            res.render("register", { error_message: "Registration error" });
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
app.post("/newpost", (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    const { subtext } = req.body;
    if (!subtext || subtext.trim().length === 0) {
        return res.render("newPost", { error_message: "Post content cannot be empty.", currentUser: req.session.user });
    }

    knex("submissions")
      .insert({
          userid: req.session.user.userid,
          subtext: subtext,
          subnegativestatus: false, // placeholder; AI filter not implemented
          subdate: knex.fn.now()
      })
      .then(() => {
          res.redirect("/feed");
      })
      .catch(err => {
          console.error("Add post error:", err.message);
          res.render("newPost", { error_message: "Error adding post: " + err.message, currentUser: req.session.user });
      });
});

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
              return res.render("post", { post: null, replies: [], reactionCounts: 0, myReaction: null, currentUser: req.session.user, error_message: "Post not found" });
          }

          // Count reactions
          const countQ = knex("subreactions").where("subid", postId).count("reactionid as cnt");
          // Get replies with author info
          const repliesQ = knex("replies")
            .select("replies.replyid", "replies.replytext", "replies.replydate", "replies.userid as authorid", "users.userfirstname", "users.userlastname")
            .leftJoin("users", "replies.userid", "users.userid")
            .where("replies.subid", postId)
            .orderBy("replies.replydate", "asc");

          // Current user's reaction
          const myReactionQ = req.session.isLoggedIn ? knex("subreactions").select("reactionid").where({subid: postId, userid: req.session.user.userid}).first() : Promise.resolve(null);

          return Promise.all([countQ, repliesQ, myReactionQ]).then(([countRows, replies, myRe]) => {
              const cnt = (countRows && countRows[0]) ? parseInt(countRows[0].cnt, 10) : 0;
              const myReaction = myRe ? myRe.reactionid : null;

              res.render("post", {
                  post: post,
                  replies: replies,
                  reactionCounts: cnt,
                  myReaction: myReaction,
                  currentUser: req.session.user || null,
                  error_message: ""
              });
          });
      })
      .catch(err => {
          console.error("Error loading post:", err.message);
          res.render("post", { post: null, replies: [], reactionCounts: 0, myReaction: null, currentUser: req.session.user, error_message: "Database error: " + err.message });
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
