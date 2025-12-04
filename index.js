// william gifford sam jenson luke hooper waylan abbott
// Good News Network - Full App
// Node + Express + EJS + PostgreSQL (Knex)

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const Sentiment = require("sentiment");
const sentiment = new Sentiment();

const knex = require("knex")({
    client: "pg",
    connection: {
        host: process.env.RDS_HOSTNAME || "localhost",
        user: process.env.RDS_USERNAME || "postgres",
        password: process.env.RDS_PASSWORD || "admin",
        database: process.env.RDS_DB_NAME || "goodnewsnetwork",
        port: process.env.RDS_PORT || 5432,
        ssl: process.env.DB_SSL ? { rejectUnauthorized: false } : false
    }
});

const app = express();

// ---------------------------
// SESSION CONFIG
// ---------------------------
app.use(
    session({
        secret: process.env.SESSION_SECRET || "fallback-secret-key",
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
// AUTH MIDDLEWARE
// ---------------------------
app.use((req, res, next) => {
    const publicPaths = ["/", "/feed", "/login", "/register", "/logout"];
    if (req.path.startsWith("/public")) return next();
    if (req.path.startsWith("/post/")) return next();
    if (publicPaths.includes(req.path)) return next();
    if (req.session.isLoggedIn) return next();

    return res.render("login", {
        error_message: "Please log in to access that page"
    });
});

// ---------------------------
// LANDING
// ---------------------------
app.get("/", (req, res) => {
    res.redirect("/feed");
});

// ---------------------------
// FEED (supports search filters)
// ---------------------------
app.get("/feed", async (req, res) => {
    try {
        let { type, q, reaction } = req.query;
        type = type || "content";
        q = q ? q.trim() : "";
        reaction = reaction ? parseInt(reaction) : null;

        let feedQuery = knex
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
            .leftJoin("users", "submissions.userid", "users.userid");

        if (type === "content" && q) {
            feedQuery.whereILike("submissions.subtext", `%${q}%`);
        }

        if (type === "user" && q) {
            feedQuery.where(builder =>
                builder.whereILike("users.userfirstname", `%${q}%`)
                       .orWhereILike("users.userlastname", `%${q}%`)
            );
        }

        if (type === "reaction" && reaction) {
            feedQuery.whereIn("submissions.subid", function () {
                this.select("subid")
                    .from("subreactions")
                    .where("reactionid", reaction);
            });
        }

        feedQuery.orderBy("submissions.subdate", "desc");

        const subs = await feedQuery;

        const subIds = subs.map(s => s.subid);

        let breakdownRows = [];
        if (subIds.length > 0) {
            breakdownRows = await knex("subreactions")
                .select("subid", "reactionid")
                .count("* as cnt")
                .whereIn("subid", subIds)
                .groupBy("subid", "reactionid");
        }

        const breakdownMap = {};
        const totals = {};

        breakdownRows.forEach(r => {
            const sid = r.subid;
            const rid = r.reactionid;
            const cnt = parseInt(r.cnt, 10);

            if (!breakdownMap[sid]) breakdownMap[sid] = {};
            breakdownMap[sid][rid] = cnt;

            totals[sid] = (totals[sid] || 0) + cnt;
        });

        let myReactionsMap = {};
        if (req.session.isLoggedIn && subIds.length > 0) {
            const rows = await knex("subreactions")
                .select("subid", "reactionid")
                .whereIn("subid", subIds)
                .andWhere("userid", req.session.user.userid);

            rows.forEach(r => (myReactionsMap[r.subid] = r.reactionid));
        }

        res.render("feed", {
            submissions: subs,
            reactionCounts: totals,
            reactionBreakdown: breakdownMap,
            myReactions: myReactionsMap,
            currentUser: req.session.user || null,
            error_message: "",
            type,
            q,
            reaction
        });

    } catch (err) {
        console.error("Feed error:", err);
        res.render("feed", {
            submissions: [],
            reactionCounts: {},
            reactionBreakdown: {},
            myReactions: {},
            currentUser: req.session.user || null,
            error_message: "Database error: " + err.message,
            type: "",
            q: "",
            reaction: ""
        });
    }
});

// ---------------------------
// REGISTER
// ---------------------------
app.get("/register", (req, res) => {
    res.render("register", { error_message: "" });
});

app.post("/register", (req, res) => {
    const { firstname, lastname, email, password } = req.body;

    if (!firstname || !lastname || !email || !password) {
        return res.render("register", { error_message: "All fields required" });
    }

    knex("users")
        .where("useremail", email)
        .first()
        .then(user => {
            if (user) {
                res.render("register", { error_message: "Email already registered" });
                return null;
            }

            return knex.raw(
                `INSERT INTO users (userfirstname, userlastname, useremail, userpassword)
                 VALUES (?, ?, ?, crypt(?, gen_salt('bf')))
                 RETURNING userid, userfirstname, userlastname, useremail, manager`,
                [firstname, lastname, email, password]
            );
        })
        .then(result => {
            if (!result) return;

            const newUser = result.rows[0];
            req.session.isLoggedIn = true;
            req.session.user = newUser;

            res.redirect("/feed");
        })
        .catch(err => {
            console.error("Register error:", err);
            res.render("register", { error_message: "Registration error" });
        });
});

// ---------------------------
// LOGIN
// ---------------------------
app.get("/login", (req, res) => {
    res.render("login", { error_message: "" });
});

app.post("/login", (req, res) => {
    const { email, password } = req.body;

    knex.raw(
        `SELECT userid, userfirstname, userlastname, useremail, manager
         FROM users
         WHERE useremail = ?
         AND userpassword::text = crypt(?, userpassword::text)`,
        [email, password]
    )
        .then(result => {
            const rows = result.rows;
            if (rows.length === 1) {
                req.session.isLoggedIn = true;
                req.session.user = rows[0];
                res.redirect("/feed");
            } else {
                res.render("login", { error_message: "Invalid login" });
            }
        })
        .catch(err => {
            console.error("Login error:", err);
            res.render("login", { error_message: "Invalid login" });
        });
});

// ---------------------------
// LOGOUT
// ---------------------------
app.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/feed"));
});

// ---------------------------
// NEW POST
// ---------------------------
app.get("/newpost", (req, res) => {
    res.render("newPost", { error_message: "", currentUser: req.session.user });
});

app.post("/newpost", (req, res) => {
    const { subtext } = req.body;

    if (!subtext || !subtext.trim()) {
        return res.render("newPost", {
            error_message: "Post content cannot be empty.",
            currentUser: req.session.user
        });
    }

    const analysis = sentiment.analyze(subtext);
    if (analysis.score < 0) {
        return res.render("newPost", {
            error_message: "Oops! Only good news allowed.",
            currentUser: req.session.user
        });
    }

    knex("submissions")
        .insert({
            userid: req.session.user.userid,
            subtext,
            subnegativestatus: false,
            subdate: knex.fn.now()
        })
        .then(() => res.redirect("/feed"))
        .catch(err => {
            console.error("Post error:", err);
            res.render("newPost", {
                error_message: "Error submitting post.",
                currentUser: req.session.user
            });
        });
});

// ---------------------------
// VIEW SINGLE POST
// ---------------------------
app.get("/post/:id", async (req, res) => {
    const postId = req.params.id;

    try {
        const post = await knex
            .select(
                "submissions.subid",
                "submissions.subtext",
                "submissions.subdate",
                "submissions.userid as authorid",
                "users.userfirstname",
                "users.userlastname"
            )
            .from("submissions")
            .leftJoin("users", "submissions.userid", "users.userid")
            .where("submissions.subid", postId)
            .first();

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

        const breakdownRows = await knex("subreactions")
            .select("reactionid")
            .count("* as cnt")
            .where("subid", postId)
            .groupBy("reactionid");

        const breakdown = {};
        let total = 0;

        breakdownRows.forEach(r => {
            breakdown[r.reactionid] = parseInt(r.cnt);
            total += parseInt(r.cnt);
        });

        const replies = await knex("replies")
            .select(
                "replyid",
                "replytext",
                "replydate",
                "replies.userid as authorid",
                "users.userfirstname",
                "users.userlastname"
            )
            .leftJoin("users", "replies.userid", "users.userid")
            .where("subid", postId)
            .orderBy("replydate", "asc");

        const myReactionRow = req.session.isLoggedIn
            ? await knex("subreactions")
                  .select("reactionid")
                  .where({ subid: postId, userid: req.session.user.userid })
                  .first()
            : null;

        const myReaction = myReactionRow ? myReactionRow.reactionid : null;

        res.render("post", {
            post,
            replies,
            reactionCounts: total,
            reactionBreakdown: { [postId]: breakdown },
            myReaction,
            currentUser: req.session.user,
            error_message: ""
        });

    } catch (err) {
        console.error("Post view error:", err);
        res.render("post", {
            post: null,
            replies: [],
            reactionCounts: 0,
            reactionBreakdown: {},
            myReaction: null,
            currentUser: req.session.user,
            error_message: "Database error"
        });
    }
});

// ---------------------------
// REPLY (with restored sentiment filter)
// ---------------------------
app.post("/reply/:id", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    const subId = req.params.id;
    const { replytext } = req.body;

    if (!replytext || !replytext.trim()) return res.redirect(`/post/${subId}`);

    // *** Sentiment Filter ***
    const analysis = sentiment.analyze(replytext);
    if (analysis.score < 0) {
        try {
            // Reload post data to re-render the page with the error
            const post = await knex
                .select(
                    "submissions.subid",
                    "submissions.subtext",
                    "submissions.subdate",
                    "submissions.userid as authorid",
                    "users.userfirstname",
                    "users.userlastname"
                )
                .from("submissions")
                .leftJoin("users", "submissions.userid", "users.userid")
                .where("submissions.subid", subId)
                .first();

            const breakdownRows = await knex("subreactions")
                .select("reactionid")
                .count("* as cnt")
                .where("subid", subId)
                .groupBy("reactionid");

            const breakdown = {};
            let total = 0;

            breakdownRows.forEach(r => {
                breakdown[r.reactionid] = parseInt(r.cnt);
                total += parseInt(r.cnt);
            });

            const replies = await knex("replies")
                .select(
                    "replyid",
                    "replytext",
                    "replydate",
                    "replies.userid as authorid",
                    "users.userfirstname",
                    "users.userlastname"
                )
                .leftJoin("users", "replies.userid", "users.userid")
                .where("subid", subId)
                .orderBy("replydate", "asc");

            const myReactionRow = req.session.isLoggedIn
                ? await knex("subreactions")
                      .select("reactionid")
                      .where({ subid: subId, userid: req.session.user.userid })
                      .first()
                : null;

            const myReaction = myReactionRow ? myReactionRow.reactionid : null;

            return res.render("post", {
                post,
                replies,
                reactionCounts: total,
                reactionBreakdown: { [subId]: breakdown },
                myReaction,
                currentUser: req.session.user,
                error_message: "Oops! Your reply is too negative! Please keep it positive (:"
            });

        } catch (err) {
            console.error("Sentiment reply render error:", err);
            return res.redirect(`/post/${subId}`);
        }
    }

    // Insert valid reply
    knex("replies")
        .insert({
            userid: req.session.user.userid,
            subid: subId,
            replytext,
            replydate: knex.fn.now()
        })
        .then(() => res.redirect(`/post/${subId}`))
        .catch(err => {
            console.error("Reply error:", err);
            res.redirect(`/post/${subId}`);
        });
});

// ---------------------------
// REACTIONS
// ---------------------------
app.post("/react", (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    const { subid, reactionid } = req.body;

    knex.raw(
        `
        INSERT INTO subreactions (subid, userid, reactionid, reactiondate)
        VALUES (?, ?, ?, NOW())
        ON CONFLICT (subid, userid)
        DO UPDATE SET reactionid = EXCLUDED.reactionid, reactiondate = NOW()
        `,
        [subid, req.session.user.userid, reactionid]
    )
        .then(() => res.redirect(req.get("Referrer") || "/feed"))
        .catch(err => {
            console.error("React error:", err);
            res.redirect(req.get("Referrer") || "/feed");
        });
});

app.post("/unreact", (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    knex("subreactions")
        .where({
            subid: req.body.subid,
            userid: req.session.user.userid
        })
        .del()
        .then(() => res.redirect(req.get("Referrer") || "/feed"))
        .catch(err => {
            console.error("Unreact error:", err);
            res.redirect(req.get("Referrer") || "/feed");
        });
});

// ---------------------------
// DELETE POST
// ---------------------------
app.post("/deletePost/:id", (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    const postId = req.params.id;

    knex("submissions")
        .select("userid")
        .where("subid", postId)
        .first()
        .then(post => {
            if (!post) return res.redirect("/feed");

            const isOwner = post.userid === req.session.user.userid;
            const isManager = req.session.user.manager;

            if (!isOwner && !isManager) {
                return res.status(403).send("Not authorized");
            }

            return knex("submissions").where("subid", postId).del();
        })
        .then(() => res.redirect("/feed"))
        .catch(err => {
            console.error("Delete error:", err);
            res.redirect("/feed");
        });
});

// ---------------------------
// DELETE REPLY
// ---------------------------
app.post("/deleteReply/:id", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    const replyId = req.params.id;

    try {
        const reply = await knex("replies")
            .select("userid", "subid")
            .where("replyid", replyId)
            .first();

        if (!reply) return res.redirect("/feed");

        const isOwner = reply.userid === req.session.user.userid;
        const isManager = req.session.user.manager;

        if (!isOwner && !isManager) {
            return res.status(403).send("Not authorized");
        }

        await knex("replies")
            .where("replyid", replyId)
            .del();

        res.redirect(`/post/${reply.subid}`);

    } catch (err) {
        console.error("Delete reply error:", err);
        res.redirect("/feed");
    }
});

// ---------------------------
// START SERVER
// ---------------------------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Good News Server running on port ${port}`));

