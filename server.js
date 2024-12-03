const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();

// CORS 설정: 모든 도메인 허용 및 추가 헤더 설정
app.use(cors({
  origin: '*', // 모든 도메인 허용
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // 허용할 HTTP 메서드
  allowedHeaders: ['Content-Type', 'Authorization'], // 허용할 헤더
  credentials: true // 쿠키를 포함한 요청 허용
}));

// JSON 요청 파싱
app.use(bodyParser.json());

// MySQL 연결 설정
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// 데이터베이스 연결
db.connect((err) => {
  if (err) {
    console.error('MySQL 연결 오류:', err);
  } else {
    console.log('MySQL 연결 성공');
  }
});

// 회원가입 API
app.post('/signup', async (req, res) => {
  const { id, password, name, age, phone } = req.body;

  if (!id || !password || !name || !age || !phone) {
    return res.status(400).json({ message: '모든 필드를 입력하세요.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `INSERT INTO users (id, password, name, age, phone) VALUES (?, ?, ?, ?, ?)`;
    db.query(query, [id, hashedPassword, name, age, phone], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: '이미 존재하는 ID입니다.' });
        }
        console.error('회원가입 오류:', err);
        return res.status(500).json({ message: '서버 오류.' });
      }
      res.status(200).json({ message: '회원가입 성공!' });
    });
  } catch (error) {
    console.error('비밀번호 암호화 오류:', error);
    res.status(500).json({ message: '서버 오류.' });
  }
});

// 로그인 API
app.post('/login', (req, res) => {
  const { id, password } = req.body;

  if (!id || !password) {
    return res.status(400).json({ message: '아이디와 비밀번호를 입력하세요.' });
  }

  const query = 'SELECT * FROM users WHERE id = ?';
  db.query(query, [id], async (err, results) => {
    if (err) {
      console.error('MySQL 오류:', err);
      return res.status(500).json({ message: '서버 오류.' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: '아이디 또는 비밀번호가 잘못되었습니다.' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: '아이디 또는 비밀번호가 잘못되었습니다.' });
    }

    res.status(200).json({ message: '로그인 성공!', user: { id: user.id, name: user.name } });
  });
});

// 서버 실행
const PORT = process.env.PORT || 5000; // 클라우드타입에서 PORT 제공
app.listen(PORT, () => {
  console.log(`서버가 포트 ${PORT}에서 실행 중입니다.`);
});
