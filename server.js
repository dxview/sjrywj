require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const xss = require('xss');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'Hospital_Secure_Key_025';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

const mysql = require('mysql2/promise');

// MySQL 连接池
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || 'mysql',
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'sjrywj',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function initDB() {
  try {
    const connection = await pool.getConnection();
    await connection.query(`
      CREATE TABLE IF NOT EXISTS feedbacks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        type VARCHAR(50),
        department VARCHAR(100),
        target_role VARCHAR(100),
        target_name VARCHAR(100),
        description TEXT,
        submitter_name VARCHAR(100),
        submitter_phone VARCHAR(50),
        ip_address VARCHAR(50),
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    connection.release();
    console.log('✅ MySQL 数据库初始化成功');
    console.log('📍 数据库连接状态: 已连接');
  } catch (error) {
    console.error('❌ 数据库初始化失败:', error.message);
    console.error('请确保 MySQL 服务已启动并且环境变量已配置');
  }
}

initDB();

// 限流设置
const submitLimiter = rateLimit({ 
  windowMs: 10 * 60 * 1000, 
  max: 10, 
  message: { success: false, message: "操作过于频繁，请稍后再试" },
  skip: (req) => {
    // 在生产环境中跳过本地请求
    return req.ip === '127.0.0.1' || req.ip === '::1';
  },
  keyGenerator: (req) => {
    // 使用 X-Forwarded-For 头来获取真实 IP
    return req.headers['x-forwarded-for'] || req.ip;
  }
});

// 提交反馈
app.post('/api/submit', submitLimiter, async (req, res) => {
  let { 
    type, department, targetRole, targetName, 
    description, submitterName, submitterPhone 
  } = req.body;

  targetRole = xss(targetRole);
  targetName = xss(targetName);
  description = xss(description);
  submitterName = xss(submitterName);
  submitterPhone = xss(submitterPhone);

  const ipAddress = req.ip || req.connection.remoteAddress;

  console.log('收到反馈提交: {');
  console.log(`  type: '${type}',`);
  console.log(`  department: '${department}',`);
  console.log(`  targetRole: '${targetRole}',`);
  console.log(`  targetName: '${targetName}',`);
  console.log(`  description: '${description}',`);
  console.log(`  submitterName: '${submitterName}',`);
  console.log(`  submitterPhone: '${submitterPhone}'`);
  console.log('}');

  try {
const connection = await pool.getConnection();
const [result] = await connection.query(
  `INSERT INTO feedbacks (type, department, target_role, target_name, description, submitter_name, submitter_phone, ip_address) 
   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  [type, department, targetRole, targetName, description, submitterName, submitterPhone, ipAddress]
);
connection.release();
    
    console.log(`✅ 反馈提交成功，ID: ${result.rows[0].id}`);
    res.json({ success: true, message: "提交成功", id: result.rows[0].id });
  } catch (error) {
    console.error('❌ 提交失败:', error.message);
    res.status(500).json({ success: false, message: "提交失败" });
  }
});

// 管理员登录
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, message: "密码错误" });
  }
});

// 获取反馈列表
app.get('/api/admin/list', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  try {
    jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT * FROM feedbacks ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(401).json({ success: false, message: "认证失败" });
  }
});

// 删除反馈
app.delete('/api/admin/delete/:id', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  try {
    jwt.verify(token, JWT_SECRET);
    await pool.query('DELETE FROM feedbacks WHERE id = $1', [req.params.id]);
    res.json({ success: true, message: "删除成功" });
  } catch (error) {
    res.status(401).json({ success: false, message: "认证失败" });
  }
});

// 测试数据库连接
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) as count FROM feedbacks');
    res.json({ 
      success: true, 
      message: "数据库连接正常", 
      count: parseInt(result.rows[0].count),
      database: "PostgreSQL"
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`🚀 服务器运行在 ${PORT} 端口`);
  console.log(`📱 前端访问: http://localhost:${PORT}`);
  console.log(`🔧 管理后台: http://localhost:${PORT}/admin.html`);
  console.log(`🗄️  数据库测试: http://localhost:${PORT}/api/test-db`);
});
