require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const xss = require('xss');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'Hospital_Secure_Key_2025';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

app.use(helmet({ contentSecurityPolicy: false }));
app.use(bodyParser.json());
app.use(cors());
app.use(express.static(__dirname));
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'mysql',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'survey_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// 初始化数据库
async function initDB() {
  try {
    const connection = await pool.getConnection();
    
    const sql = `
      CREATE TABLE IF NOT EXISTS feedbacks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        type VARCHAR(255),
        department VARCHAR(255),
        target_role VARCHAR(255),
        target_name VARCHAR(255),
        description TEXT,
        submitter_name VARCHAR(255),
        submitter_phone VARCHAR(20),
        ip_address VARCHAR(45),
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    await connection.query(sql);
    console.log('✓ MySQL 数据库初始化成功');
    connection.release();
  } catch (error) {
    console.error('✗ 数据库初始化失败:', error.message);
  }
}

// 测试连接
pool.getConnection()
  .then(connection => {
    console.log('✓ MySQL 连接成功');
    connection.release();
    initDB();
  })
  .catch(err => {
    console.error('✗ MySQL 连接失败:', err.message);
  });

const now = () => new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });

const submitLimiter = rateLimit({ 
  windowMs: 10 * 60 * 1000, 
  max: 10, 
  message: { success: false, message: "操作过于频繁，请稍后再试" } 
});

// 提交反馈
app.post('/api/submit', submitLimiter, async (req, res) => {
  let { 
    type, department, targetRole, targetName, 
    description, submitterName, submitterPhone 
  } = req.body;
  
  if (!type || !department || !targetRole || !description || !submitterName) {
    return res.json({ success: false, message: "缺少必要字段" });
  }
  
  try {
    const connection = await pool.getConnection();
    const ip = req.ip || req.connection.remoteAddress;
    
    const sql = `
      INSERT INTO feedbacks 
      (type, department, target_role, target_name, description, submitter_name, submitter_phone, ip_address) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    
    await connection.query(sql, [
      xss(type),
      xss(department),
      xss(targetRole),
      xss(targetName || ''),
      xss(description),
      xss(submitterName),
      xss(submitterPhone || ''),
      ip
    ]);
    
    connection.release();
    res.json({ success: true, message: "反馈提交成功" });
  } catch (error) {
    console.error('提交失败:', error);
    res.status(500).json({ success: false, message: "提交失败" });
  }
});

// 获取反馈列表（需要认证）
app.get('/api/feedbacks', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: "未授权" });
  }
  
  try {
    jwt.verify(token, JWT_SECRET);
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT * FROM feedbacks ORDER BY created_at DESC');
    connection.release();
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(401).json({ success: false, message: "认证失败" });
  }
});

// 登录
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, message: "密码错误" });
  }
});

// 更新反馈状态
app.put('/api/feedbacks/:id', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: "未授权" });
  }
  
  try {
    jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const { status } = req.body;
    
    const connection = await pool.getConnection();
    await connection.query('UPDATE feedbacks SET status = ? WHERE id = ?', [status, id]);
    connection.release();
    
    res.json({ success: true, message: "更新成功" });
  } catch (error) {
    res.status(401).json({ success: false, message: "操作失败" });
  }
});

app.listen(PORT, () => {
  console.log(`服务器运行在 ${PORT} 端口`);
});
