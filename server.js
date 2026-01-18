require('dotenv').config();
const express = require('express');
const fs = require('fs')
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const cookieParser= require('cookie-parser');
const crypto = require('crypto')
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const SECRET_KEY = process.env.JWT_SECRET || 'haile';
const nodemailer = require('nodemailer');
const FRONTEND_URL ='https://ethioexam.pro.et';

// Continue with the rest of your code...
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
  'http://localhost:5173',      // for local React dev
  'https://ethioexam.et',
  'https://ethioexam2.netlify.app' ,// production React app
  'https://ethioexam.pro.et' // production React app
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
app.use(bodyParser.json());
app.use(cookieParser());
// 🔐 Authentication Middleware


// ========== BREVO API SETUP ==========
const { Resend } = require('resend');
const resend = new Resend('re_VncZDWzZ_2NLioTnJpGucF63GB3cFWQeE');


async function sendResetEmail(email, resetLink) {
  console.log('📤 Sending email via Resend to:', email);
  
  try {
    const data = await resend.emails.send({
      from: 'Ethioexam <onboarding@resend.dev>',
      to: email,
      subject: 'Reset Your Ethioexam Password',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: #4361ee; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1 style="margin: 0; font-size: 28px;">Password Reset</h1>
          </div>
          
          <div style="padding: 30px; background: #f8f9fa; border-radius: 0 0 10px 10px;">
            <p>Hello,</p>
            <p>Click the button below to reset your password:</p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetLink}" 
                 style="background: #4361ee; color: white; padding: 14px 32px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: bold;">
                Reset Password
              </a>
            </div>
            
            <p>Or copy this link:</p>
            <div style="background: #e9ecef; padding: 15px; border-radius: 5px; word-break: break-all;">
              ${resetLink}
            </div>
            
            <p style="color: #e63946; font-weight: bold; margin-top: 20px;">
              ⚠️ This link expires in 1 hour.
            </p>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px;">
              <p>If you didn't request this, please ignore this email.</p>
              <p>© ${new Date().getFullYear()} Ethioexam</p>
            </div>
          </div>
        </div>
      `
    });

    console.log('✅ Email sent successfully via Resend');
    return { success: true, messageId: data.id };
    
  } catch (error) {
    console.error('❌ Resend error:', error.message);
    
    // Fallback: log the link
    console.log('🔗 RESET LINK FOR MANUAL SENDING:');
    console.log('   Email:', email);
    console.log('   Link:', resetLink);
    
    return { 
      success: false, 
      error: error.message,
      resetLink: resetLink
    };
  }
}



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


// ========== FORGOT PASSWORD ==========
app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  if (!email || !email.includes('@')) {
    return res.status(400).json({ message: 'Valid email is required' });
  }
  
  console.log('🔐 Forgot password request for:', email);
  
  try {
    const [rows] = await pool.query('SELECT user_id FROM users WHERE email = ?', [email.toLowerCase().trim()]);
    
    // Security: Always return success message
    if (!rows.length) {
      console.log('⚠️ Email not found (security response)');
      return res.json({ 
        message: 'If your email is registered, you will receive a reset link shortly.',
        success: true 
      });
    }

    const userId = rows[0].user_id;
    
    // Check for existing valid tokens first (prevent spam)
    const [existingTokens] = await pool.query(
      'SELECT id, token FROM password_resets WHERE user_id = ? AND used = 0 AND expires > UTC_TIMESTAMP()',
      [userId]
    );
    
    let token;
    
    if (existingTokens.length > 0) {
      // Reuse existing valid token
      token = existingTokens[0].token;
      console.log('↪️ Using existing token for user:', userId);
    } else {
      // Generate new token
      token = crypto.randomBytes(32).toString('hex');
      const expires = new Date(Date.now() + 3600 * 1000); // 1 hour
      const expiresUTC = expires.toISOString().slice(0, 19).replace('T', ' ');
      
      console.log('🆕 New token generated:', token.substring(0, 20) + '...');
      console.log('Expires (UTC):', expiresUTC);
      
      await pool.query(
        'INSERT INTO password_resets (user_id, token, expires) VALUES (?, ?, ?)',
        [userId, token, expiresUTC]
      );
    }

    // Create reset link
    const resetLink = `${FRONTEND_URL}/reset-password?token=${token}`;
    
    console.log('📧 Sending reset email via Brevo API...');
    
    // 🔥 CHANGED: Send email via Brevo API instead of SMTP
   const emailResult = await sendResetEmail(email, resetLink);
    
    if (!emailResult.success) {
      console.log('⚠️ Email sending failed:', emailResult.error);
      // Log the link for manual sending
      console.log('🔗 Reset link for manual sending:', resetLink);
    } else {
      console.log('✅ Brevo email sent successfully, Message ID:', emailResult.messageId);
    }
    
    res.json({ 
      message: 'If your email is registered, you will receive a password reset link shortly.',
      success: true
    });
    
  } catch (err) {
    console.error('🔥 Forgot password error:', err);
    res.status(500).json({ 
      message: 'Something went wrong. Please try again later.',
      success: false
    });
  }
});
// ========== RESET PASSWORD ==========
app.post('/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  
  console.log('=== RESET PASSWORD REQUEST ===');
  console.log('Token (first 20 chars):', token ? token.substring(0, 20) + '...' : 'none');
  console.log('Password length:', newPassword?.length || 0);
  
  if (!token || !newPassword) {
    console.log('❌ Missing token or password');
    return res.status(400).json({ 
      message: 'Token and new password are required' 
    });
  }

  if (newPassword.length < 8) {
    console.log('❌ Password too short');
    return res.status(400).json({ 
      message: 'Password must be at least 8 characters' 
    });
  }

  try {
    // Find valid token using UTC time
    const [rows] = await pool.query(
      `SELECT pr.*, u.email 
       FROM password_resets pr
       LEFT JOIN users u ON pr.user_id = u.user_id
       WHERE pr.token = ? 
         AND pr.used = 0 
         AND pr.expires > UTC_TIMESTAMP()`,
      [token]
    );
    
    console.log(`🔍 Found ${rows.length} valid token(s)`);
    
    if (rows.length === 0) {
      // Debug why token is invalid
      const [debugRows] = await pool.query(
        `SELECT 
          pr.token,
          pr.used,
          pr.expires,
          u.email,
          UTC_TIMESTAMP() as current_utc,
          pr.expires > UTC_TIMESTAMP() as is_valid,
          TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), pr.expires) as seconds_left
         FROM password_resets pr
         LEFT JOIN users u ON pr.user_id = u.user_id
         WHERE pr.token = ?`,
        [token]
      );
      
      console.log('📊 Token debug info:', debugRows);
      
      if (debugRows.length === 0) {
        return res.status(400).json({ 
          message: 'Invalid reset token' 
        });
      }
      
      const debug = debugRows[0];
      if (debug.used) {
        return res.status(400).json({ 
          message: 'This reset link has already been used' 
        });
      }
      
      if (!debug.is_valid) {
        return res.status(400).json({ 
          message: 'Reset link has expired. Please request a new one.' 
        });
      }
      
      return res.status(400).json({ 
        message: 'Invalid reset token' 
      });
    }

    const reset = rows[0];
    console.log('✅ Valid token found');
    console.log('   User ID:', reset.user_id);
    console.log('   User email:', reset.email);
    console.log('   Token expires:', reset.expires);
    
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    console.log('🔐 Password hashed');
    
    // Update user's password
    const [updateResult] = await pool.query(
      'UPDATE users SET password_hash = ? WHERE user_id = ?', 
      [hashedPassword, reset.user_id]
    );
    
    console.log('📝 Password updated. Affected rows:', updateResult.affectedRows);
    
    if (updateResult.affectedRows === 0) {
      console.log('⚠️ No user found with ID:', reset.user_id);
      return res.status(400).json({ 
        message: 'User account not found' 
      });
    }
    
    // Mark token as used
    await pool.query(
      'UPDATE password_resets SET used = 1 WHERE id = ?', 
      [reset.id]
    );
    
    console.log('🏷️ Token marked as used');
    console.log('🎉 PASSWORD RESET SUCCESSFUL!');
    
    res.json({ 
      message: 'Password has been reset successfully!',
      success: true
    });
    
  } catch (err) {
    console.error('🔥 Reset password error:', err);
    console.error('Error stack:', err.stack);
    res.status(500).json({ 
      message: 'Server error. Please try again later.' 
    });
  }
});


// ========== TEST EMAIL ENDPOINT ==========
app.get('/test-email', async (req, res) => {
  const { email = 'haileadane3723@gmail.com' } = req.query;
  
  console.log(`📤 Sending test email to: ${email}`);
  
  try {
    // Send the email
    const info = await transporter.sendMail({
      from: '"Ethioexam" <info.ethioexam@gmail.com>',
      to: email,
      subject: '✅ TEST: Ethioexam Email Service Working',
      text: `Test email sent at ${new Date().toLocaleString()}\n\nYour email service is working!`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #4361ee, #3a0ca3); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1 style="margin: 0;">✅ TEST SUCCESSFUL!</h1>
            <p style="margin: 10px 0 0 0;">Ethioexam Email Service is Working</p>
          </div>
          
          <div style="padding: 30px; background: #f8f9fa; border-radius: 0 0 10px 10px;">
            <p>Hello,</p>
            <p>This is a <strong>test email</strong> to confirm your Ethioexam email service is configured correctly.</p>
            
            <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <h3 style="margin-top: 0;">📋 Test Details:</h3>
              <p><strong>To:</strong> ${email}</p>
              <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
              <p><strong>Status:</strong> <span style="color: #28a745;">Active ✓</span></p>
            </div>
            
            <p>If you can read this, your SMTP setup with Brevo is working perfectly! 🎉</p>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px;">
              <p>This is an automated test message from Ethioexam server.</p>
            </div>
          </div>
        </div>
      `
    });

    console.log('✅ Email sent successfully!');
    console.log('   Message ID:', info.messageId);
    console.log('   Response:', info.response);

    // Send success response
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Test Email Sent</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f8f9fa; }
          .card { background: white; max-width: 500px; margin: 0 auto; padding: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
          .success { color: #28a745; font-size: 24px; margin-bottom: 20px; }
          .info { text-align: left; background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
          .email { color: #4361ee; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1 class="success">✅ Test Email Sent!</h1>
          <p>Check your inbox: <span class="email">${email}</span></p>
          
          <div class="info">
            <p><strong>Message ID:</strong> ${info.messageId}</p>
            <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
            <p><strong>Status:</strong> Sent via Brevo SMTP</p>
          </div>
          
          <p>
            <a href="/test-email?email=${email}" style="background: #4361ee; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px;">
              🔄 Send Another
            </a>
          </p>
          
          <p style="color: #666; margin-top: 30px;">
            Server: ${req.headers.host}<br>
            Time: ${new Date().toISOString()}
          </p>
        </div>
      </body>
      </html>
    `);

  } catch (error) {
    console.error('❌ Email failed:', error.message);
    
    res.status(500).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Email Failed</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
          .error { color: #dc3545; font-size: 24px; }
          .debug { background: #ffe5e5; padding: 20px; border-radius: 10px; max-width: 600px; margin: 20px auto; text-align: left; }
        </style>
      </head>
      <body>
        <h1 class="error">❌ Email Failed to Send</h1>
        
        <div class="debug">
          <h3>Error Details:</h3>
          <p><strong>Error:</strong> ${error.message}</p>
          <p><strong>To:</strong> ${email}</p>
          <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
          
          <h4>Possible Issues:</h4>
          <ol>
            <li>Check your Brevo SMTP password</li>
            <li>Verify your Brevo account is active</li>
            <li>Check internet connection</li>
            <li>Try port 465 with secure: true</li>
          </ol>
        </div>
        
        <p>
          <a href="/test-email" style="color: #007bff;">🔄 Try Again</a>
        </p>
      </body>
      </html>
    `);
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

// PUT /exams/:id/status
// Toggle exam status
app.put('/exams/:exam_id/status', async (req, res) => {
  const { exam_id } = req.params;

  console.log('toggling exam status', exam_id);
  try {
    const [result] = await pool.execute(
      `UPDATE exams
       SET status = CASE
           WHEN status = 'public' THEN 'private'
           ELSE 'public'
       END
       WHERE exam_id = ?`,
      [exam_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Exam not found' });
    }

    res.json({ message: 'Exam status toggled successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update exam status', error: err });
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
// Bulk question upload with refs (paragraph, image, instruction)
app.post('/submit_bulk_questions', async (req, res) => {
  console.log('Bulk upload request body:', req.body);

  const { examId, userId, questions } = req.body;

  if (!examId || !userId || !Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ error: 'Invalid input: examId, userId, and questions are required.' });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const insertQuestionSql = `
      INSERT INTO questions (exam_id, submitted_by, question_text, q_number, verified, explanation, difficulty, tags)
      VALUES (?, ?, ?, ?, 0, ?, ?, ?)
    `;

    const insertChoiceSql = `
      INSERT INTO choices (question_id, choice_label, choice_text, is_correct)
      VALUES (?, ?, ?, ?)
    `;

    const insertRefSql = `
      INSERT INTO ref_tables (question_id, paragraph, image_url, instruction, created_at)
      VALUES (?, ?, ?, ?, NOW())
    `;

    const insertedIds = [];

    for (const q of questions) {
      const { question_text, options, explanation, difficulty, tags, paragraph, image_url, instruction, question_number } = q;

      if (!question_text || !Array.isArray(options) || options.length < 2 || !options.some(o => o.is_correct)) {
        throw new Error(`Invalid question: missing text or correct option.`);
      }

      const tagsString = Array.isArray(tags) ? tags.join(',') : (tags || null);

      // Insert question
      const [questionResult] = await connection.execute(insertQuestionSql, [
        examId,
        userId,
        question_text,
        question_number,
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
          opt.text || null,
          opt.is_correct ? 1 : 0
        ]);
      }

      // FIX: Check if paragraph, image_url, or instruction exist directly in the question object
      // instead of looking for a nested "ref" object
      if (paragraph || image_url || instruction) {
        await connection.execute(insertRefSql, [
          questionId,
          paragraph || null,
          image_url || null,
          instruction || null
        ]);
        console.log(`✅ Added ref data for question ${questionId}:`, { paragraph: !!paragraph, image_url: !!image_url, instruction: !!instruction });
      }
    }

    await connection.commit();

    res.status(201).json({
      message: 'Bulk questions submitted successfully',
      inserted_question_ids: insertedIds,
      inserted_count: insertedIds.length
    });

  } catch (error) {
    await connection.rollback();
    console.error('Error in bulk insert:', error);
    res.status(500).json({ error: 'Failed to submit bulk questions', details: error.message });
  } finally {
    connection.release();
  }
});



app.get('/api/submitted-questions',authenticate, async (req, res) => {
  const { userId, examId } = req.query;
  console.log('userId, examId', userId, examId)
  const userRole = req.user.role; // get role from authenticated user
  console.log('fetching submitted questions', req.query, userRole);
  if (!userId || !examId) {
    return res.status(400).json({ error: 'Missing userId or examId' });
  }

  const connection = await pool.getConnection();
  try {
    let sql = `
      SELECT 
        q.question_id AS id,
        q.question_text AS text,
        q.q_number,
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
      WHERE q.exam_id = ?
    `;

    const params = [examId];

    // Only filter by submitted_by if user is not admin
    if (userRole !== 'admin') {
      sql += ' AND q.submitted_by = ?';
      params.push(userId);
    }

    sql += `
      GROUP BY q.question_id
      ORDER BY q.q_number ASC, q.created_at ASC
    `;

    const [rows] = await connection.execute(sql, params);

    const formatted = rows.map(r => ({
      id: r.id,
      q_number: r.q_number,
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

app.put('/delete_question', authenticate, async (req, res) => {
  console.log('Delete question request body:', req.body);
    const { question_id } = req.body;

    if (!question_id) {
        return res.status(400).json({ error: "question_id is required" });
    }

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();

        // 1. Check if the question exists and ownership/admin
        const [questionRows] = await connection.query(
            "SELECT submitted_by FROM questions WHERE question_id = ?",
            [question_id]
        );

        if (!questionRows.length) {
            await connection.rollback();
            return res.status(404).json({ error: "Question not found" });
        }

        const questionOwnerId = questionRows[0].submitted_by;

        if (req.user.role !== 'admin' && req.user.user_id !== questionOwnerId) {
            await connection.rollback();
            return res.status(403).json({ error: "Not authorized to delete this question" });
        }

        // 2. Delete the question itself
        // All related choices, solutions, and ref_tables will be deleted automatically
        await connection.query("DELETE FROM questions WHERE question_id = ?", [question_id]);

        await connection.commit();
        res.json({ message: "Question and all related data deleted successfully" });

    } catch (err) {
        await connection.rollback();
        console.error(err);
        res.status(500).json({ error: "Internal server error" });
    } finally {
        connection.release();
    }
});


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





// students

// get public exam from exam tabel fetch exam whcih are public and send tehm to frotend broo
app.get('/students/public-exams', authenticate, async (req, res) => {
  console.log('Fetching public exams');

  try {
    let query = '';
    let params = [];
    console.log('User role:', req.user.role);   
    
    if (req.user.role === 'admin') {
      // Admin sees all public exams
      query = `
        SELECT 
          exam_id, title, exam_type, exam_subject, status, exam_year, stream,
          description, created_by, created_at
        FROM exams
        WHERE status = 'public'
        ORDER BY created_at DESC
      `;
    } else {
      // Student → fetch stream from students table
      console.log('Fetching student stream for user_id:', req.user.user_id);
      
      const [studentRows] = await pool.query(
        'SELECT stream FROM students WHERE user_id = ?',
        [req.user.user_id]
      );

      if (!studentRows.length) {
        return res.status(404).json({ success: false, message: 'Student not found' });
      }
      
      console.log('Student record:', studentRows);
      const studentStream = studentRows[0].stream;
     


      // If student has no stream (null or empty), show all public exams like admin
      if (!studentStream || studentStream === '' || studentStream === 'null') {
        query = `
          SELECT 
            exam_id, title, exam_type, exam_subject, status, exam_year, stream,
            description, created_by, created_at
          FROM exams
          WHERE status = 'public'
          ORDER BY created_at DESC
        `;
        console.log('Student has no stream - showing all public exams');
      } else {
        // Student has a stream - show only exams matching their stream

        query = `
          SELECT 
            exam_id, title, exam_type, exam_subject, status, exam_year, stream,
            description, created_by, created_at
          FROM exams
          WHERE status = 'public' AND stream = ?
          ORDER BY created_at DESC
        `;
        params = [studentStream];
        console.log('Student stream found:', studentStream, '- filtering exams by stream');
      }
    }

    const [rows] = await pool.query(query, params);

    res.status(200).json({
      success: true,
      message: 'Public exams fetched successfully',
      data: rows,
      count: rows.length  
    });

  } catch (error) {
    console.error('Error fetching public exams:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});


app.get('/students/exam-questions/:examId', async (req, res) => {
  try {
    const { examId } = req.params;
console.log('Fetching public questions for examId:', examId);
    // 1. Quick exam access check
    const [examRows] = await pool.execute(
      'SELECT exam_id, title FROM exams WHERE exam_id = ? AND status = "public"',
      [examId]
    );
    
    if (examRows.length === 0) {
      return res.status(404).json({ success: false, message: 'Exam not found or not public' });
    }

    const exam = examRows[0];

    // 2. Fetch questions, choices, and ref data in single query
    const questionsQuery = `
      SELECT 
        q.question_id,
        q.question_text,
        q.explanation,
        c.choice_label,
        c.choice_text,
        c.is_correct,
        r.paragraph,
        r.image_url,
        r.instruction
      FROM questions q
      INNER JOIN choices c ON q.question_id = c.question_id
      LEFT JOIN ref_tables r ON q.question_id = r.question_id
      WHERE q.exam_id = ?
      ORDER BY q.q_number, c.choice_label
    `;

    const [rows] = await pool.execute(questionsQuery, [examId]);

    if (rows.length === 0) {
      // check student grade and if it 9 or 10th excute the admin pool request which both social and natural exam
      return res.status(404).json({ success: false, message: 'No questions found' });
    }

    // 3. Process data efficiently
    const questionsMap = new Map();

    rows.forEach(row => {
      if (!questionsMap.has(row.question_id)) {
        questionsMap.set(row.question_id, {
          id: row.question_id,
          question: row.question_text,
          explanation: row.explanation,
          paragraph: row.paragraph,
          imageUrl: row.image_url,
          instruction: row.instruction,
          options: [],
          correctAnswer: null
        });
      }

      const question = questionsMap.get(row.question_id);
      question.options.push(row.choice_text);
      
      if (row.is_correct) {
        question.correctAnswer = row.choice_text;
      }
    });

    const questions = Array.from(questionsMap.values());

    res.json({
      success: true,
      exam: {
        exam_id: exam.exam_id,
        title: exam.title,
        duration: exam.duration || 60
      },
      questions: questions,
      totalQuestions: questions.length
    });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});


// 
app.post('/auth/register/student', async (req, res) => {
  const { 
    email, 
    password,
    first_name, 
    last_name, 
    phone, 
    school_name, 
    grade_level,
    stream,
    referral_code
  } = req.body;
  console.log('Received registration data:', req.body);

  console.log('Registering student:', { email, first_name, school_name, grade_level });
const referral_code1 = parseInt(referral_code);
  // 1️⃣ Validation
  if (!email || !password || !first_name || !last_name || !phone || !school_name || !grade_level) {
    return res.status(400).json({ 
      success: false, 
      message: 'All required fields must be filled' 
    });
  }

  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();

    // 2️⃣ Check if email already exists
    const [existingUsers] = await connection.query(
      'SELECT user_id FROM users WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      await connection.rollback();
      return res.status(400).json({
        success: false,
        message: 'Email already exists'
      });
    }

    // 3️⃣ If referral code provided → verify it exists in students table
    let referredByStudentId = null;
    if (referral_code1) {
      const [referrer] = await connection.query(
        'SELECT id FROM students WHERE id = ?',
        [referral_code1]
      );

      if (referrer.length === 0) {
        await connection.rollback();
        return res.status(400).json({
          success: false,
          message: 'Invalid referral code'
        });
      }

      // If valid, store it for later insert
      referredByStudentId = referral_code1;
    }

    // 4️⃣ Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 5️⃣ Insert into users table
    const [userResult] = await connection.query(
      `INSERT INTO users 
      (email, password_hash, role, first_name, last_name, phone) 
      VALUES (?, ?, 'student', ?, ?, ?)`,
      [email, hashedPassword, first_name, last_name, phone]
    );

    const userId = userResult.insertId;

    // 6️⃣ Insert into students table
    const [studentResult] = await connection.query(
      `INSERT INTO students 
      (user_id, school_name, grade_level, stream, referred_by, registration_date) 
      VALUES (?, ?, ?, ?, ?, NOW())`,
      [userId, school_name, grade_level, stream || null, referredByStudentId]
    );

    // 7️⃣ If referral was valid → update the referral count for that student
    if (referredByStudentId) {
      await connection.query(
        `UPDATE students 
         SET referral_count = COALESCE(referral_count, 0) + 1 
         WHERE id = ?`,
        [referredByStudentId]
      );
    }

    // 8️⃣ Commit changes
    await connection.commit();

    res.status(201).json({
      success: true,
      message: 'Registration successful!',
      studentId: studentResult.insertId
    });

  } catch (err) {
    await connection.rollback();
    console.error('Registration error:', err);
    
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({
        success: false,
        message: 'Email already exists'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Registration failed. Please try again.'
    });
  } finally {
    connection.release();
  }
});



// / Get dashboard stats + top referrers
app.get('/api/admin/dashboard/stats', authenticate, async (req, res) => {
  console.log('Fetching dashboard stats');
  try {
    // Basic stats
    const totalStudents = await pool.query('SELECT COUNT(*) as count FROM students');
    const weeklyReg = await pool.query('SELECT COUNT(*) as count FROM students WHERE registration_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)');
    const schools = await pool.query('SELECT COUNT(DISTINCT school_name) as count FROM students WHERE school_name IS NOT NULL AND school_name != ""');
    const activeReferrals = await pool.query('SELECT COUNT(*) as count FROM students WHERE referral_count > 0');

    // Top Referrers - REMOVED HTML COMMENT
    const topReferrers = await pool.query(
      `SELECT 
        s.referral_count,
        s.school_name,
        u.first_name, 
        u.last_name, 
        u.email,
        u.phone
       FROM students s 
       JOIN users u ON s.user_id = u.user_id
       WHERE s.referral_count > 0 
       ORDER BY s.referral_count DESC 
       LIMIT 10`
    );

    console.log('✅ Stats fetched successfully');

    res.json({
      totalStudents: totalStudents[0][0].count,
      thisWeekRegistrations: weeklyReg[0][0].count,
      totalSchools: schools[0][0].count,
      activeReferrals: activeReferrals[0][0].count,
      topReferrers: topReferrers[0]
    });
    
  } catch (error) {
    console.error('❌ Database error:', error);
    res.status(500).json({ 
      error: 'Database query failed: ' + error.message
    });
  }
});

// Get dashboard stats + top referrers
// Get dashboard stats + top referrers
app.get('/api/admin/dashboard/stats', authenticate, async (req, res) => {
  console.log('Fetching dashboard stats');
  try {
    // Basic stats - USING CORRECT COLUMN NAMES
    const [totalStudents] = await pool.query(
      'SELECT COUNT(*) as count FROM students'
    );
    
    const [weeklyReg] = await pool.query(
      'SELECT COUNT(*) as count FROM students WHERE registration_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)'
    );
    
    const [schools] = await pool.query(
      'SELECT COUNT(DISTINCT school_name) as count FROM students WHERE school_name IS NOT NULL AND school_name != ""'
    );
    
    const [activeReferrals] = await pool.query(
      'SELECT COUNT(*) as count FROM students WHERE referral_count > 0'
    );

    // Top Referrers - CORRECT JOIN WITH YOUR SCHEMA
    const [topReferrers] = await pool.query(
      `SELECT 
        s.referral_count,
        s.school_name,
        u.first_name, 
        u.last_name, 
        u.email,
        u.phone
       FROM students s 
       JOIN users u ON s.user_id = u.user_id  <!-- CORRECT JOIN -->
       WHERE s.referral_count > 0 
       ORDER BY s.referral_count DESC 
       LIMIT 10`
    );

    console.log('✅ Stats fetched successfully:', {
      totalStudents: totalStudents[0].count,
      weeklyReg: weeklyReg[0].count,
      schools: schools[0].count,
      activeReferrals: activeReferrals[0].count,
      topReferrersCount: topReferrers.length
    });

    res.json({
      // Basic Stats
      totalStudents: totalStudents[0].count,
      thisWeekRegistrations: weeklyReg[0].count,
      totalSchools: schools[0].count,
      activeReferrals: activeReferrals[0].count,
      
      // Top Referrers List
      topReferrers: topReferrers
    });
    
  } catch (error) {
    console.error('❌ Database error:', error);
    res.status(500).json({ 
      error: 'Database query failed',
      details: error.message,
      sqlMessage: error.sqlMessage 
    });
  }
});


app.get('/user/:userid/referrals', authenticate, async (req, res) => {
  console.log('Fetching referral data for user:', req.params.userid);
  try {
    const userId = req.params.userid;

    // First, get the student ID for this user
    const [studentRows] = await pool.execute(
      'SELECT id FROM students WHERE user_id = ?',
      [userId]
    );

    if (studentRows.length === 0) {
      return res.json({
        success: true,
        data: {
          referral_id: userId,
          referral_count: 0,
          total_earnings: 0,
          referrals: []
        }
      });
    }

    const studentId = studentRows[0].id;

    // Get referral count and referred students - JOIN with users table to get names
    const [referrals] = await pool.execute(`
      SELECT 
        s.id,
        u.first_name,
        u.last_name,
        s.school_name,
        s.grade_level,
        s.stream,
        s.registration_date,
        s.created_at
      FROM students s
      JOIN users u ON s.user_id = u.user_id
      WHERE s.referred_by = ?
      ORDER BY s.created_at DESC
    `, [studentId]);

    // Calculate total earnings
    const totalEarnings = Math.floor(referrals.length / 2);

    res.json({
      success: true,
      data: {
        referral_id: studentId, // This is the actual referral code
        referral_count: referrals.length,
        total_earnings: totalEarnings,
        referrals: referrals.map(ref => ({
          id: ref.id,
          first_name: ref.first_name,
          last_name: ref.last_name,
          school_name: ref.school_name,
          grade_level: ref.grade_level,
          stream: ref.stream,
          registration_date: ref.registration_date,
          created_at: ref.created_at
        }))
      }
    });

  } catch (error) {
    console.error('Error fetching referral data:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching referral data'
    });
  }
});



app.post('/students/list', authenticate, async (req, res) => {
  console.log('Fetching all students list');
  try {
    const { page = 1, limit = 50 } = req.body;
    const offset = (page - 1) * limit;

    // Minimal test query
    const testQuery = `
      SELECT 
        u.user_id,
        u.first_name,
        u.last_name,
        u.email,
        s.school_name,
        s.grade_level
      FROM students s
      INNER JOIN users u ON s.user_id = u.user_id
      ORDER BY s.created_at DESC
      LIMIT ${parseInt(limit)} OFFSET ${parseInt(offset)}
    `;

    console.log('Executing test query:', testQuery);

    const [students] = await pool.query(testQuery);

    // Simple count
    const [countResult] = await pool.query('SELECT COUNT(*) as total FROM students');
    const totalStudents = countResult[0].total;
    const totalPages = Math.ceil(totalStudents / limit);

    res.json({
      success: true,
      data: {
        students: students,
        pagination: {
          current_page: parseInt(page),
          total_pages: totalPages,
          total_students: totalStudents,
          has_next: page < totalPages,
          has_prev: page > 1
        }
      }
    });

  } catch (error) {
    console.error('Error fetching students list:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching students list',
      error: error.message
    });
  }
});






// ---- PING endpoint ----
// Records last_active, starts new session, closes stale sessions
app.post('/api/ping', async (req, res) => {
  const { userId } = req.body;
  const inactivityThresholdMinutes = 2; // consider inactive after 2 minutes
  const now = new Date();
  console.log(`Ping received from user ${userId} at ${now.toISOString()}`);

  try {
    // 1️⃣ Update last_active for this user
    await pool.query(
      'UPDATE users SET last_active = NOW() WHERE user_id = ?',
      [userId]
    );

    // 2️⃣ Close stale sessions
    const [staleSessions] = await pool.query(`
      SELECT os.id, u.last_active
      FROM online_sessions os
      JOIN users u ON u.user_id = os.user_id
      WHERE os.session_end IS NULL
        AND u.last_active < NOW() - INTERVAL ? MINUTE
    `, [inactivityThresholdMinutes]);

    await Promise.all(
      staleSessions.map(session =>
        pool.query(
          'UPDATE online_sessions SET session_end = ? WHERE id = ?',
          [session.last_active, session.id]
        )
      )
    );

    // 3️⃣ Start new session for this user if none exists
    await pool.query(`
      INSERT INTO online_sessions (user_id, session_start)
      SELECT ?, NOW()
      WHERE NOT EXISTS (
        SELECT 1 FROM online_sessions WHERE user_id = ? AND session_end IS NULL
      )
    `, [userId, userId]);

    res.sendStatus(200);
  } catch (err) {
    console.error('Ping error:', err);
    res.sendStatus(500);
  }
});

// ---- Online users endpoint ----
app.get('/api/online', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT user_id, first_name, last_name
      FROM users
      WHERE last_active >= NOW() - INTERVAL 1 MINUTE
    `);
    res.json({ online_users: rows });
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});



app.get("/health", async (req, res) => {
  try {
    // Simple ping to DB
    const [rows] = await pool.query("SELECT 1");
    res.status(200).send("✅ Backend & Database OK");
  } catch (err) {
    console.error("DB ping failed:", err.message);
    res.status(503).send("❌ Database connection failed");
  }
})




// 🏁 Start Server after DB check
const PORT = process.env.PORT || 3000;
(async () => {
  await checkDBConnection();
  app.listen(PORT, () => {
    console.log(`🚀 TiDB-backed API running on port ${PORT}`);
  });
})();
   

















