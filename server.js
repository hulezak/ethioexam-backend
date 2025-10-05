require('dotenv').config();
const express = require('express');
const fs = require('fs')
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const cookieParser= require('cookie-parser');
const SECRET_KEY = process.env.JWT_SECRET || 'haile';

// ✅ TiDB Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'gateway01.us-west-2.prod.aws.tidbcloud.com',
  port: process.env.DB_PORT || 4000,
  user: process.env.DB_USER || 'vGSYJhVS37umFwK.root',
  password: process.env.DB_PASSWORD || 'HyQLLhLBFT2Q4ojr',
  database: process.env.DB_NAME || 'Ethio_Exam',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    ca: fs.readFileSync('./isrgrootx1.pem') // path to your downloaded cert
  }
});

// ✅ Check DB connection before starting the server
async function checkDBConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Database connection successful!');
    connection.release();
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    process.exit(1); // Stop the app if DB connection fails
  }
}

// App Setup

const app = express();
const allowedOrigins = [
  'http://localhost:5173',          // local dev
  'https://ethioexam.netlify.app',  // production frontend 1
  'https://ethioexam2.netlify.app'  // production frontend 2
];

// ✅ CORS middleware
const corsOptions = {
  origin: function(origin, callback) {
    // Allow requests with no origin (Postman, server-to-server)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  allowedHeaders: ['Content-Type'], // still only allow these headers
  credentials: true, // allow cookies/auth
  methods: '*'        // allow all HTTP methods
};

// Apply CORS globally
app.use(cors(corsOptions));

// ✅ Handle preflight OPTIONS requests for all routes
app.options('*', cors(corsOptions));

app.use(bodyParser.json());
app.use(cookieParser());
// 🔐 Authentication Middleware


// 📌 AUTH ENDPOINTS
app.post('/auth/register', async (req, res) => {
  const { email, password, role, first_name, last_name, phone, date_of_birth, gender, address } = req.body;

  console.log('registering user', req.body);

  if (!email || !password || !role) {
    return res.status(400).send('Email, password, and role are required');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      `INSERT INTO users 
      (email, password_hash, role, first_name, last_name, phone, date_of_birth, gender, address) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [email, hashedPassword, role, first_name || null, last_name || null, phone || null, date_of_birth || null, gender || null, address || null]
    );

    const token = jwt.sign({ userId: result.insertId, role }, SECRET_KEY);
    res.status(201).send({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(400).send('Email already exists');
  }
});



// ==================== LOGIN ====================
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('All fields are required');

  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (!users.length) return res.status(401).send('Invalid credentials');

    const isMatch = await bcrypt.compare(password, users[0].password_hash);
    if (!isMatch) return res.status(401).send('Invalid credentials');

    // Include role in JWT payload
    const payload = { 
      userId: users[0].user_id, 
      role: users[0].role 
    };

    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });

    // Save role in cookie for easy frontend access (optional)
    res.cookie('role', users[0].role, { httpOnly: false, secure: false, sameSite: 'Strict' });

    res.send({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Login failed');
  }
});

// ==================== AUTH MIDDLEWARE ====================
const authenticate = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '') || req.cookies.token;
  if (!token) return res.status(401).send('Access denied');
console.log('we are authetticating')
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const [users] = await pool.query('SELECT * FROM users WHERE user_id = ?', [decoded.userId]);
    if (!users.length) return res.status(401).send('Invalid token');

    req.user = { ...users[0], role: decoded.role };
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).send('Token expired');
    }
    res.status(401).send('Invalid token');
  }
};

// ==================== ROLE AUTHORIZATION ====================
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).send('Forbidden: insufficient permissions');
    }
    next();
  };
};

// ==================== EXAMPLE PROTECTED ROUTE ====================
app.get('/admin', authenticate, authorizeRole(['admin']), (req, res) => {
  res.send('Welcome Admin!');
});


// 👤 USER PROFILE
app.get('/users/me', authenticate, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM users WHERE user_id = ?`,
      [req.user.user_id]
    );

    if (rows.length === 0) {
      return res.status(404).send({ message: 'User not found' });
    }

    res.send(rows[0]);
  } catch (err) {
    console.error('❌ Failed to fetch profile:', err);
    res.status(500).send({ message: 'Failed to fetch profile' });
  }
});



// user management

// GET all users
app.get('/users', authenticate, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT * FROM users');
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to fetch users');
  }
});

// PUT update user by id
app.put('/users/:id', authenticate, async (req, res) => {
  const userId = req.params.id;
  const {
    email,
    role,
    first_name,
    last_name,
    phone,
    date_of_birth,
    gender,
    address,
    avatar_url

  } = req.body;
console.log('updating userinfo', req.body)

  try {
    const [result] = await pool.query(
      `UPDATE users SET 
        email = ?, 
        role = ?, 
        first_name = ?, 
        last_name = ?, 
        phone = ?, 
        date_of_birth = ?, 
        gender = ?, 
        address = ?,
        avatar_url=?
 
      WHERE user_id = ?`,
      [email, role, first_name, last_name, phone, date_of_birth, gender, address, avatar_url
, userId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).send('User not found');
    }
    res.send({ success: true, message: 'User updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to update user');
  }
});

// Create Exam

app.post('/create-exams', async (req, res) => {
  try {
    const { title, exam_type, exam_subject, exam_year, stream, description, created_by } = req.body;
    console.log('creating exam', req.body)
    if (!title || !exam_type || !exam_subject || !exam_year || !stream) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const [result] = await pool.execute(
      `INSERT INTO exams (title, exam_type, exam_subject, exam_year, stream, description, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [title, exam_type, exam_subject, exam_year, stream, description || null, created_by || null]
    );

    res.status(201).json({ success: true, exam_id: result.insertId });
  } catch (error) {
    console.error('Error creating exam:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});
app.get('/exams', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM exams ORDER BY created_at DESC');
    res.json(rows);
  } catch (error) {
    console.error('Error fetching exams:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});
// Update exam details
app.put('/exams/:exam_id', async (req, res) => {
  const { exam_id } = req.params;
  const { title, exam_type, exam_subject, exam_year, stream, description } = req.body;

  if (!title || !exam_type || !exam_subject || !exam_year || !stream) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }

  try {
    await pool.query(
      `UPDATE exams 
       SET title = ?, exam_type = ?, exam_subject = ?, exam_year = ?, stream = ?, description = ?
       WHERE exam_id = ?`,
      [title, exam_type, exam_subject, exam_year, stream, description || '', exam_id]
    );

    res.json({ success: true, message: 'Exam updated successfully' });
  } catch (err) {
    console.error('Error updating exam:', err);
    res.status(500).json({ error: 'Failed to update exam' });
  }
});


app.get('/users/role', async (req, res) => {
  const role = req.query.role;
  if (!role) return res.status(400).json({ error: 'Role query param required' });

  try {
    const [rows] = await pool.query('SELECT user_id, first_name, last_name, email FROM users WHERE role = ?', [role]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// 3) Get list of users who have access to an exam
app.get('/exam-access/:exam_id', async (req, res) => {
  const { exam_id } = req.params;

  try {
    const [rows] = await pool.query(`
      SELECT u.user_id, u.first_name, u.last_name, u.email
      FROM exam_access ea
      JOIN users u ON ea.user_id = u.user_id
      WHERE ea.exam_id = ?
    `, [exam_id]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching exam access:', err);
    res.status(500).json({ error: 'Failed to fetch exam access list' });
  }
});

// 4) POST to grant access to user for an exam
app.post('/exam-access', async (req, res) => {
  const { exam_id, user_id } = req.body;
  if (!exam_id || !user_id) {
    return res.status(400).json({ error: 'exam_id and user_id are required' });
  }

  try {
    // Insert only if not exists (unique key prevents duplicates)
    await pool.query(`
      INSERT INTO exam_access (exam_id, user_id) VALUES (?, ?)
      ON DUPLICATE KEY UPDATE access_id = access_id
    `, [exam_id, user_id]);

    res.json({ success: true });
  } catch (err) {
    console.error('Error granting access:', err);
    res.status(500).json({ error: 'Failed to grant access' });
  }
});

// Revoke a user's access to a specific exam
app.delete('/exam-access/:exam_id/:user_id', async (req, res) => {
  const { exam_id, user_id } = req.params;

  if (!exam_id || !user_id) {
    return res.status(400).json({ error: 'exam_id and user_id are required' });
  }

  try {
    const [result] = await pool.query(
      'DELETE FROM exam_access WHERE exam_id = ? AND user_id = ?',
      [exam_id, user_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Access not found' });
    }

    res.json({ success: true, message: 'Access revoked successfully' });
  } catch (err) {
    console.error('Error revoking access:', err);
    res.status(500).json({ error: 'Failed to revoke access' });
  }
});

// we check user acces sofr exam
app.get('/get_myexams', authenticate, async (req, res) => {
  try {
    const userId = req.user.user_id;
    const userRole = req.user.role; // assuming role is in the JWT/session
console.log(userRole,userId)
    let query = '';
    let params = [];

    if (userRole === 'admin') {
      // Admin sees all exams
      query = `
        SELECT exam_id, title, exam_type, exam_subject, 
               exam_year, stream, description, created_at
        FROM exams
        ORDER BY created_at DESC
      `;
    } else {
      // Regular user sees only exams they have access to
      query = `
        SELECT e.exam_id, e.title, e.exam_type, e.exam_subject, 
               e.exam_year, e.stream, e.description, e.created_at
        FROM exam_access ea
        INNER JOIN exams e ON ea.exam_id = e.exam_id
        WHERE ea.user_id = ?
        ORDER BY e.created_at DESC
      `;
      params = [userId];
    }

    const [rows] = await pool.execute(query, params);
    res.json(rows);

  } catch (err) {
    console.error('Error fetching exams:', err);
    res.status(500).json({ message: 'Server error fetching exams' });
  }
});



// 📚 SUBJECTS
app.get('/subjects', async (req, res) => {
  try {
    const [subjects] = await pool.query('SELECT * FROM subjects');
    res.send(subjects);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to fetch subjects');
  }
});

// 📊 EXAMS
app.get('/exams/:id', async (req, res) => {
  try {
    const [exams] = await pool.query(`
      SELECT e.*, et.name as exam_type_name, s.name as subject_name
      FROM exams e
      LEFT JOIN exam_types et ON e.exam_type_id = et.exam_type_id
      LEFT JOIN subjects s ON e.subject_id = s.subject_id
      WHERE e.exam_id = ?`,
      [req.params.id]
    );
    exams[0] ? res.send(exams[0]) : res.status(404).send('Exam not found');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to fetch exam');
  }
});


//  submit the question broo


app.post('/submit_question', async (req, res) => {
  console.log('Request body:', req.body);
  console.log('Submitting a question');
  const {
    exam_id,
    question_number,
    question_text,
    options,
    explanation,
    difficulty,
    tags,
    user_id,
  } = req.body;

  // Basic validation
  if (
    !exam_id ||
    !user_id ||
    !question_number ||
    !question_text ||
    !Array.isArray(options) ||
    options.length < 2 ||
    !options.some(o => o.is_correct)
  ) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  // Convert tags to string or null
  const tagsString = Array.isArray(tags) ? tags.join(',') : (tags || null);

  const connection = await pool.getConnection(); 
  try {
    await connection.beginTransaction();

    // Insert into questions (with explanation, difficulty, tags)
    const insertQuestionSql = `
      INSERT INTO questions (exam_id, submitted_by, question_text, verified, explanation, difficulty, tags)
      VALUES (?, ?, ?, 0, ?, ?, ?)
    `;
    const [questionResult] = await connection.execute(insertQuestionSql, [
      exam_id,
      user_id,
      question_text,
      explanation || null,
      difficulty || 'None',
      tagsString
    ]);

    const questionId = questionResult.insertId;

    // Insert choices
    const insertChoiceSql = `
      INSERT INTO choices (question_id, choice_label, choice_text, is_correct)
      VALUES (?, ?, ?, ?)
    `;

    for (const opt of options) {
      await connection.execute(insertChoiceSql, [
        questionId,
        opt.label,
        opt.text,
        opt.is_correct ? 1 : 0
      ]);
    }

    await connection.commit();

    res.status(201).json({ message: 'Question submitted successfully', question_id: questionId });

  } catch (error) {
    await connection.rollback();
    console.error('Error inserting question:', error);
    res.status(500).json({ error: 'Failed to submit question' });
  } finally {
    connection.release();
  }
});


// bulk quetsion upload
app.post('/submit_bulk_questions', async (req, res) => {
  console.log('Bulk upload request body:', req.body);

  const {  examId,  userId, questions } = req.body;

  // Basic validation
  if (!examId || !userId || !Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ error: 'Invalid input: examId, userId, and questions are required.' });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const insertQuestionSql = `
      INSERT INTO questions (exam_id, submitted_by, question_text, verified, explanation, difficulty, tags)
      VALUES (?, ?, ?, 0, ?, ?, ?)
    `;

    const insertChoiceSql = `
      INSERT INTO choices (question_id, choice_label, choice_text, is_correct)
      VALUES (?, ?, ?, ?)
    `;

    const insertedIds = [];

    for (const q of questions) {
      const {
        question_number,
        question_text,
        options,
        explanation,
        difficulty,
        tags
      } = q;

      // Validate question
      if (
        !question_number ||
        !question_text ||
        !Array.isArray(options) ||
        options.length < 2 ||
        !options.some(o => o.is_correct)
      ) {
        throw new Error(`Invalid question at number ${question_number}`);
      }

      const tagsString = Array.isArray(tags) ? tags.join(',') : (tags || null);

      // Insert question
      const [questionResult] = await connection.execute(insertQuestionSql, [
        examId,
        userId,
        question_text,
        explanation || null,
        difficulty || 'None',
        tagsString
      ]);

      const questionId = questionResult.insertId;
      insertedIds.push(questionId);

      // Insert choices
      for (const opt of options) {
        await connection.execute(insertChoiceSql, [
          questionId,
          opt.label,
          opt.text,
          opt.is_correct ? 1 : 0
        ]);
      }
    }

    await connection.commit();
    res.status(201).json({
      message: 'Bulk questions submitted successfully',
      inserted_question_ids: insertedIds
    });

  } catch (error) {
    await connection.rollback();
    console.error('Error in bulk insert:', error);
    res.status(500).json({ error: 'Failed to submit bulk questions' });
  } finally {
    connection.release();
  }
});






app.get('/api/submitted-questions', async (req, res) => {
  const { userId, examId } = req.query;

  if (!userId || !examId) {
    return res.status(400).json({ error: 'Missing userId or examId' });
  }

  const connection = await pool.getConnection();
  try {
    const sql = `
      SELECT 
        q.question_id AS id,
        q.question_text AS text,
        q.exam_id,
        q.submitted_by,
        q.verified,
        q.explanation,
        q.difficulty,
        q.tags,
        q.created_at,
        JSON_ARRAYAGG(
          JSON_OBJECT(
            'id', c.choice_id,
            'label', c.choice_label,
            'text', c.choice_text,
            'is_correct', c.is_correct
          )
        ) AS choices
      FROM questions q
      LEFT JOIN choices c ON q.question_id = c.question_id
      WHERE q.exam_id = ? AND q.submitted_by = ?
      GROUP BY q.question_id
      ORDER BY q.created_at ASC
    `;

    const [rows] = await connection.execute(sql, [examId, userId]);

    const formatted = rows.map(r => ({
      id: r.id,
      text: r.text,
      choices: Array.isArray(r.choices) ? r.choices : [],
      verified: r.verified,
      explanation: r.explanation,
      difficulty: r.difficulty,
      tags: r.tags ? r.tags.split(',').map(t => t.trim()) : [],
      created_at: r.created_at
    }));

    res.json(formatted);
  } catch (err) {
    console.error('Error fetching submitted questions:', err);
    res.status(500).json({ error: 'Failed to fetch submitted questions' });
  } finally {
    connection.release();
  }
});

app.get('/user-submitted-stats', async (req, res) => {

  const { userId, examId } = req.query;
console.log('fetchging user stat', userId)
  if (!userId) return res.status(400).json({ error: 'User ID is required' });

  try {
    let query = `SELECT COUNT(*) as totalQuestions
                 FROM questions
                 WHERE submitted_by = ?`;
    const params = [userId];

    if (examId) {
      query += ` AND exam_id = ?`;
      params.push(examId);
    }

    const [rows] = await pool.execute(query, params);

    const totalQuestions = rows[0].totalQuestions || 0;

    const stats = {
      totalQuestions,
      points: totalQuestions * 5,  // points = questions submitted × 5
    };

    return res.json(stats);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/user-submitted-stats', async (req, res) => {
  const { userId, examId } = req.query;

  if (!userId) return res.status(400).json({ error: 'User ID is required' });

  try {
    let query = `SELECT COUNT(*) as totalQuestions, 
                        SUM(CASE WHEN is_correct IS NOT NULL THEN 5 ELSE 0 END) as points 
                 FROM questions
                 WHERE submitted_by = ?`;
    const params = [userId];

    if (examId) {
      query += ` AND exam_id = ?`;
      params.push(examId);
    }

    const [rows] = await pool.execute(query, params);

    const stats = {
      totalQuestions: rows[0].totalQuestions || 0,
      points: rows[0].points || 0,
    };

    return res.json(stats);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.put('/delete_qustion', async(req,res) =>{

//  accept the quetion id and user id
// make sure the user sibmitted tat quetsion
// delet the question
// delete the related choices and solution and otehr stuffss


})

// Backend: server.js
app.put('/api/update_question', async (req, res) => {
  const {
    id,
    question_text,
    options,
    difficulty,
    explanation,
    tags,
    user_id,
    exam_id
  } = req.body;

  console.log('--- PUT /api/update_question called ---');
  console.log('Raw payload:', req.body);

  // Convert to numbers if needed
  const questionId = Number(id);
  const userIdNum = Number(user_id);
  const examIdNum = Number(exam_id);

  console.log({ questionId, userIdNum, examIdNum });

  // Validation
  if (
    !questionId || !question_text || !Array.isArray(options) || options.length < 2 ||
    !options.some(c => c.is_correct) || !userIdNum || !examIdNum
  ) {
    console.error('Validation failed:', {
      questionId, question_text, options, userIdNum, examIdNum
    });
    return res.status(400).json({
      error: 'Invalid input. Make sure question, options, correct answer, user_id, and exam_id exist.'
    });
  }

  const tagsString = Array.isArray(tags) ? tags.join(',') : (tags || null);

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    console.log('Updating question in DB...');

    // 1️⃣ Update main question
    const updateQuestionSql = `
      UPDATE questions
      SET question_text = ?, explanation = ?, difficulty = ?, tags = ?
      WHERE question_id = ? AND submitted_by = ? AND exam_id = ?
    `;
    const [result] = await connection.execute(updateQuestionSql, [
      question_text,
      explanation || null,
      difficulty || 'none',
      tagsString,
      questionId,
      userIdNum,
      examIdNum
    ]);

    console.log('Update result:', result);

    if (result.affectedRows === 0) {
      await connection.rollback();
      console.warn('No rows affected. Question not found or no permission.');
      return res.status(404).json({ error: 'Question not found or you do not have permission.' });
    }

    // 2️⃣ Delete old choices
    console.log('Deleting old choices...');
    await connection.execute(`DELETE FROM choices WHERE question_id = ?`, [questionId]);

    // 3️⃣ Insert new choices
    console.log('Inserting new choices...');
    const insertChoiceSql = `
      INSERT INTO choices (question_id, choice_label, choice_text, is_correct)
      VALUES (?, ?, ?, ?)
    `;
    for (const c of options) {
      console.log('Inserting choice:', c);
      await connection.execute(insertChoiceSql, [
        questionId,
        c.label,
        c.text || '',
        c.is_correct ? 1 : 0
      ]);
    }

    await connection.commit();
    console.log('Transaction committed successfully.');

    // 4️⃣ Fetch updated question with choices
    const [updatedQuestions] = await connection.execute(
      `SELECT * FROM questions WHERE question_id = ?`, [questionId]
    );

    const [updatedChoices] = await connection.execute(
      `SELECT * FROM choices WHERE question_id = ?`, [questionId]
    );

    console.log('Updated question fetched:', updatedQuestions[0]);
    console.log('Updated choices fetched:', updatedChoices);

    res.json({
      message: 'Question updated successfully',
      question: updatedQuestions[0],
      choices: updatedChoices
    });

  } catch (err) {
    if (connection) await connection.rollback();
    console.error('Error updating question:', err);
    res.status(500).json({ error: 'Failed to update question', details: err.message });
  } finally {
    if (connection) connection.release();
    console.log('Connection released.');
  }
});





// 🏁 Start Server after DB check
const PORT = process.env.PORT || 3000;
(async () => {
  await checkDBConnection();
  app.listen(PORT, () => {
    console.log(`🚀 TiDB-backed API running on port ${PORT}`);
  });
})();
   



















