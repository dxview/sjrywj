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
const JWT_SECRET = process.env.JWT_SECRET || 'Hospital_Secure_Key_2025';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// 信任代理设置（修复 X-Forwarded-For 警告）
app.set('trust proxy', true);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
app.use(cors());
app.use(express.static(__dirname));

// PostgreSQL 连接池
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// 数据库初始化
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS feedbacks (
        id SERIAL PRIMARY KEY,
        type VARCHAR(50),
        department VARCHAR(100),
        target_role VARCHAR(100),
        target_name VARCHAR(100),
        description TEXT,
        submitter_name VARCHAR(100),
        submitter_phone VARCHAR(),
        ip_address VARCHAR(),
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('✅ PostgreSQL 数据库初始化成功');
    console.log('📍 数据库连接: ', process.env.DATABASE_URL ? '已配置' : '未配置');
  } catch (error) {
    console.error('❌ 数据库初始化失败:', error.message);
  }
}

initDB();
