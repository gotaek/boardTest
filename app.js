require("dotenv").config();

const express = require("express");
const mysql = require("mysql");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const session = require("express-session"); //세션관리 미들웨어
const passport = require("passport"); //Passport 라이브러리
const LocalStrategy = require("passport-local").Strategy; //Passport의 Local Strategy 전략
const bcrypt = require("bcrypt"); //비밀번호 해시 및 비교를 위한 라이브러리
const flash = require("connect-flash");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// EJS 템플릿 설정
app.set("view engine", "ejs");

// DB연결
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: "board",
});

db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log("MySQL connected...");
});

// 사용자 정보 직렬화
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// 사용자 정보 역직렬화
passport.deserializeUser((id, done) => {
  const sql = "SELECT * FROM users WHERE id = ?";
  db.query(sql, [id], (err, results) => {
    if (err) {
      return done(err);
    }
    const user = results[0];
    done(null, user);
  });
});
// localStrategy 전략 사용
// Passport Local Strategy 설정
passport.use(
  new LocalStrategy((username, password, done) => {
    // 데이터베이스에서 username에 해당하는 사용자 조회
    const sql = "SELECT * FROM users WHERE username = ?";
    db.query(sql, [username], (err, results) => {
      if (err) {
        return done(err);
      }
      if (!results.length) {
        return done(null, false, { message: "존재하지 않는 사용자입니다." });
      }

      const user = results[0];

      // 비밀번호 검증
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) {
          return done(err);
        }
        if (!isMatch) {
          return done(null, false, {
            message: "비밀번호가 일치하지 않습니다.",
          });
        }
        return done(null, user);
      });
    });
  })
);
// 로그인 페이지 라우트
app.get("/login", (req, res) => {
  res.render("login", { message: req.flash("error") });
});

// 로그인 처리 라우트
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true, // 실패 시 플래시 메시지 사용
  })
);

// 로그아웃 처리 라우트
app.get("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
// 회원가입 페이지 라우트
app.get("/register", (req, res) => {
  res.render("register", { message: req.flash("message") });
});

// 회원가입 처리 라우트
app.post("/register", (req, res) => {
  const { username, password, email } = req.body;

  // 사용자 이름 중복 체크 쿼리
  const checkDuplicateQuery = "SELECT * FROM users WHERE username = ?";
  db.query(checkDuplicateQuery, [username], (err, results) => {
    if (err) {
      console.error("Error checking duplicate username:", err);
      req.flash("message", "회원가입에 실패했습니다.");
      res.redirect("/register");
      return;
    }

    // 이미 같은 username이 존재하는 경우
    if (results.length > 0) {
      req.flash("message", "이미 사용 중인 사용자 이름입니다.");
      res.redirect("/register");
      return;
    }

    // 비밀번호 해시화
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error("Error hashing password:", err);
        req.flash("message", "회원가입에 실패했습니다.");
        res.redirect("/register");
        return;
      }

      // 데이터베이스에 회원 정보 저장
      const sql =
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";
      db.query(sql, [username, hashedPassword, email], (err, result) => {
        if (err) {
          console.error("Error adding user:", err);
          req.flash("message", "회원가입에 실패했습니다.");
          res.redirect("/register");
          return;
        }
        console.log("User added:", result);
        req.flash("message", "회원가입이 완료되었습니다.");
        res.redirect("/login");
      });
    });
  });
});

// 네비게이션 바 렌더링을 위한 미들웨어
app.use((req, res, next) => {
  res.locals.user = req.user;
  res.locals.currentPage = req.path.split("/")[1] || "home"; // 현재 페이지 설정
  next();
});

// 홈 페이지 라우트
app.get("/", (req, res) => {
  // 모든 글 조회
  db.query("SELECT * FROM posts ORDER BY created_at DESC", (err, results) => {
    if (err) {
      console.error("Error retrieving posts: ", err);
      res.status(500).send("Error retrieving posts");
      return;
    }

    if (req.isAuthenticated()) {
      // Passport에서 제공하는 isAuthenticated 메서드를 사용하여 로그인 상태인지 확인
      // 인증된 사용자가 있을 경우, index.ejs를 렌더링하면서 사용자 정보를 전달
      res.render("index", { user: req.user, posts: results });
    } else {
      // 로그인 상태가 아니면, 단순히 index.ejs를 렌더링하면서 글 목록만 전달
      res.render("index", { user: undefined, posts: results });
    }
  });
});

// 포스트 작성 폼 페이지 라우트
app.get("/post/new", (req, res) => {
  res.render("new");
});

// 포스트 작성 처리 라우트
app.post("/post/new", (req, res) => {
  const { title, content } = req.body;
  const userId = req.user.id; // 세션에서 로그인한 사용자의 id 가져오기

  const sql = "INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)";
  db.query(sql, [title, content, userId], (err, result) => {
    if (err) {
      console.error("Error adding post: ", err);
      res.status(500).send("Error adding post");
      return;
    }
    console.log("Post added:", result);
    res.redirect("/");
  });
});

// 포스트 디테일 페이지 라우트 설정
app.get("/post/:postId", (req, res) => {
  const postId = req.params.postId;

  // postId를 사용하여 데이터베이스에서 해당 포스트를 조회하는 쿼리를 작성
  const sql = "SELECT * FROM posts WHERE id = ?";
  db.query(sql, [postId], (err, result) => {
    if (err) {
      console.error("Error retrieving post:", err);
      res.status(500).send("Error retrieving post");
      return;
    }
    if (result.length === 0) {
      res.status(404).send("Post not found");
      return;
    }
    if (req.isAuthenticated() && req.user.id === result[0].user_id) {
      // post_detail.ejs를 렌더링하고 포스트 데이터를 전달
      res.render("post_detail", { post: result[0], authorization: true });
    } else {
      res.render("post_detail", { post: result[0], authorization: false });
    }
  });
});
// 포스트 삭제 처리 라우트 설정
app.delete("/post/delete/:id", ensureAuthenticated, (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id; // 현재 로그인한 사용자의 ID

  const sql = "DELETE FROM posts WHERE id = ? AND user_id = ?";
  db.query(sql, [postId, userId], (err, result) => {
    if (err) {
      console.error("Error deleting post:", err);
      res.status(500).send("Error deleting post");
      return;
    }
    if (result.affectedRows === 0) {
      res
        .status(403)
        .send("Forbidden: You do not have permission to delete this post");
      return;
    }
    console.log("Post deleted:", result);
    res.sendStatus(200);
  });
});

// 인증된 사용자인지 확인하는 미들웨어 함수
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

// 포스트 수정 페이지 라우트 설정
app.get("/post/update/:id", ensureAuthenticated, (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id; // 현재 로그인한 사용자의 ID

  const sql = "SELECT * FROM posts WHERE id = ?";
  db.query(sql, [postId], (err, result) => {
    if (err) {
      console.error("Error retrieving post: ", err);
      res.status(500).send("Error retrieving post");
      return;
    }
    if (result.length === 0) {
      res.status(404).send("Post not found");
      return;
    }

    // 글의 작성자와 현재 로그인한 사용자가 같은지 확인
    if (result[0].user_id !== userId) {
      res
        .status(403)
        .send("Forbidden: You do not have permission to access this page");
      return;
    }
    // 사용자가 권한이 있는 경우, 수정 페이지 렌더링
    res.render("update", { post: result[0] });
  });
});

// 포스트 수정 처리 라우트 설정
app.post("/post/update/:id", ensureAuthenticated, (req, res) => {
  const postId = req.params.id;
  const { title, content } = req.body;
  const userId = req.user.id; // 현재 로그인한 사용자의 ID

  // 해당 포스트가 있는지 확인
  const checkPostQuery = "SELECT * FROM posts WHERE id = ?";
  db.query(checkPostQuery, [postId], (err, results) => {
    if (err) {
      console.error("Error checking post:", err);
      res.status(500).send("Error checking post");
      return;
    }
    if (results.length === 0) {
      res.status(404).send("Post not found");
      return;
    }

    const post = results[0];

    // 작성자와 현재 로그인한 사용자가 같은지 확인
    if (post.user_id !== userId) {
      res
        .status(403)
        .send("Forbidden: You do not have permission to access this page");
      return;
    }

    // 포스트 업데이트 쿼리
    const updatePostQuery =
      "UPDATE posts SET title = ?, content = ? WHERE id = ?";
    db.query(updatePostQuery, [title, content, postId], (err, result) => {
      if (err) {
        console.error("Error updating post:", err);
        res.status(500).send("Error updating post");
        return;
      }
      console.log("Post updated:", result);
      res.redirect(`/post/${postId}`);
    });
  });
});

// 서버 실행
app.listen(3000, () => {
  console.log("Server started on port 3000");
});
