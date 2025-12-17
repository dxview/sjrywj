require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
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

app.use(helmet({ contentSecurityPolicy: false }));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
app.use(cors());
app.use(express.static(__dirname));


let db;


async function initDB() {
  try {

    const fs = require('fs');
    const dataDir = '/data';
    
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
      console.log('📁 创建 /data 目录');
    }
    
    db = await open({
      filename: '/data/hospital_feedback.db',
      driver: sqlite3.Database
    });
    
    await db.exec(`
      CREATE TABLE IF NOT EXISTS feedbacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT,
        department TEXT,
        target_role TEXT,
        target_name TEXT,
        description TEXT,
        submitter_name TEXT,
        submitter_phone TEXT,
        ip_address TEXT,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('✅ SQLite 数据库初始化成功');
    console.log('📍 数据库位置: /data/hospital_feedback.db');
  } catch (error) {
    console.error('❌ 数据库初始化失败:', error.message);
  }
}

initDB();


const submitLimiter = rateLimit({ 
  windowMs: 10 * 60 * 1000, 
  max: 10, 
  message: { success: false, message: "操作过于频繁，请稍后再试" } 
});

app.post('/api/submit', submitLimiter, async (req, res) => {
  let { 
    type, department, targetRole, targetName, 
    description, submitterName, submitterPhone 
  } = req.body;
  
  if (!type || !department || !targetRole || !description) {
    console.log('❌ 缺少必要字段:', { type, department, targetRole, description });
    return res.json({ success: false, message: "缺少必要字段" });
  }
  
  try {
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
    
    console.log('收到反馈提交:', { type, department, targetRole, targetName, description, submitterName, submitterPhone });
    
    const sql = `
      INSERT INTO feedbacks 
      (type, department, target_role, target_name, description, submitter_name, submitter_phone, ip_address) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    
    const values = [
      xss(type),
      xss(department),
      xss(targetRole),
      xss(targetName || ''),
      xss(description),
      xss(submitterName),
      xss(submitterPhone || ''),
      ip
    ];
    
    const result = await db.run(sql, values);
    
    console.log('✅ 反馈提交成功，ID:', result.lastID);
    res.json({ success: true, message: "反馈提交成功", id: result.lastID });
  } catch (error) {
    console.error('❌ 提交失败:', error);
    res.status(500).json({ success: false, message: "提交失败: " + error.message });
  }
});

app.get('/api/feedbacks', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: "未授权" });
  }
  
  try {
    jwt.verify(token, JWT_SECRET);
    const rows = await db.all('SELECT * FROM feedbacks ORDER BY created_at DESC');
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(401).json({ success: false, message: "认证失败" });
  }
});

app.post('/api/login', (req, res) => {
  const { password } = req.body;
  
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, message: "密码错误" });
  }
});

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, message: "密码错误" });
  }
});

app.get('/api/admin/list', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: "未授权" });
  }
  
  try {
    jwt.verify(token, JWT_SECRET);
    const rows = await db.all('SELECT * FROM feedbacks ORDER BY created_at DESC');
    res.json(rows);
  } catch (error) {
    res.status(401).json({ success: false, message: "认证失败" });
  }
});

app.put('/api/feedbacks/:id', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: "未授权" });
  }
  
  try {
    jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const { status } = req.body;
    
    await db.run('UPDATE feedbacks SET status = ? WHERE id = ?', [status, id]);
    
    res.json({ success: true, message: "更新成功" });
  } catch (error) {
    res.status(401).json({ success: false, message: "操作失败" });
  }
});

app.put('/api/admin/update/:id', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: "未授权" });
  }
  
  try {
    jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const { status } = req.body;
    
    await db.run('UPDATE feedbacks SET status = ? WHERE id = ?', [status, id]);
    
    res.json({ success: true, message: "更新成功" });
  } catch (error) {
    res.status(401).json({ success: false, message: "操作失败" });
  }
});

app.delete('/api/admin/delete/:id', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: "未授权" });
  }
  
  try {
    jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    await db.run('DELETE FROM feedbacks WHERE id = ?', [id]);
    
    res.json({ success: true, message: "删除成功" });
  } catch (error) {
    res.status(401).json({ success: false, message: "操作失败" });
  }
});

app.get('/api/test-db', async (req, res) => {
  try {
    const result = await db.get('SELECT COUNT(*) as count FROM feedbacks');
    res.json({ 
      success: true, 
      message: "数据库连接正常", 
      feedbackCount: result.count 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: "数据库连接失败", 
      error: error.message 
    });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 服务器运行在 ${PORT} 端口`);
  console.log(`📱 前端访问: http://localhost:${PORT}`);
  console.log(`🔧 管理后台: http://localhost:${PORT}/admin.html`);
  console.log(`🗄️  数据库测试: http://localhost:${PORT}/api/test-db`);
});
