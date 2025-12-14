require('dotenv').config(); // 加载 .env 环境变量
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken'); // 新增：JWT
const xss = require('xss'); // 新增：XSS过滤

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// 检查配置
if (!JWT_SECRET || !ADMIN_PASSWORD) {
    console.error("严重错误：未设置 .env 配置文件，服务无法启动。");
    process.exit(1);
}

// 1. 安全中间件
app.use(helmet({ contentSecurityPolicy: false }));
app.use(bodyParser.json());
app.use(cors()); // 生产环境建议配置 origin 限制域名

// 2. 静态文件托管
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) res.set('Content-Type', 'text/html; charset=utf-8');
    }
}));
app.use(express.static(__dirname));

// 3. 数据库连接
const db = new sqlite3.Database('./survey.db', (err) => {
    if (err) console.error("DB Error:", err.message);
    else {
        console.log('SQLite Connected Securely.');
        db.run(`CREATE TABLE IF NOT EXISTS surveys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            department TEXT NOT NULL, 
            target TEXT NOT NULL, 
            name TEXT NOT NULL, 
            description TEXT NOT NULL,
            ip_address TEXT, 
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    }
});

// 辅助：北京时间
function getBeijingTime() {
    const now = new Date();
    const Y = now.getFullYear();
    const M = String(now.getMonth() + 1).padStart(2, '0');
    const D = String(now.getDate()).padStart(2, '0');
    const h = String(now.getHours()).padStart(2, '0');
    const m = String(now.getMinutes()).padStart(2, '0');
    const s = String(now.getSeconds()).padStart(2, '0');
    return `${Y}-${M}-${D} ${h}:${m}:${s}`;
}

// --- API 1: 用户提交 (增加 XSS 过滤) ---
const submitLimiter = rateLimit({ windowMs: 10*60*1000, max: 20, message: "提交过于频繁，请稍后再试" });

app.post('/api/submit', submitLimiter, (req, res) => {
    let { type, department, target, name, description } = req.body;
    
    if (!type || !department || !target || !name || !description) {
        return res.status(400).json({success: false, message: "缺少必填项"});
    }
    
    // ★★★ 安全过滤：防止用户输入恶意脚本 ★★★
    type = xss(type);
    department = xss(department);
    target = xss(target);
    name = xss(name);
    description = xss(description);
    
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const createdAt = getBeijingTime();
    
    const sql = `INSERT INTO surveys (type, department, target, name, description, ip_address, created_at) VALUES (?,?,?,?,?,?,?)`;
    
    db.run(sql, [type, department, target, name, description, ip, createdAt], function(err) {
        if(err) {
            console.error("DB Write Error:", err.message);
            return res.status(500).json({success: false, message: "数据库写入错误"});
        }
        res.json({success: true, message: "提交成功", id: this.lastID});
    });
});

// --- API 2: 管理员登录 (发放 JWT Token) ---
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    // 比对密码
    if (password === ADMIN_PASSWORD) {
        // 生成 Token，有效期 24 小时
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ success: true, token: token });
    } else {
        res.status(401).json({ success: false, message: "密码错误" });
    }
});

// --- 中间件：验证 JWT Token ---
const verifyToken = (req, res, next) => {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(' ');
        const token = bearer[1];
        jwt.verify(token, JWT_SECRET, (err, authData) => {
            if (err) return res.status(403).json({ error: "Token无效或已过期" });
            req.authData = authData;
            next();
        });
    } else {
        res.status(403).json({ error: "未授权访问" });
    }
};

// --- API 3: 获取列表 (受保护) ---
app.get('/api/admin/feedbacks', verifyToken, (req, res) => {
    db.all("SELECT * FROM surveys ORDER BY created_at DESC", [], (err, rows) => {
        if (err) {
            console.error("DB Read Error:", err.message);
            res.status(500).json({ success: false, message: "数据库读取错误" });
        } else {
            res.json({ success: true, data: rows });
        }
    });
});

// --- API 4: 删除记录 (受保护) ---
app.delete('/api/admin/feedbacks/:id', verifyToken, (req, res) => {
    db.run("DELETE FROM surveys WHERE id = ?", req.params.id, function(err) {
        if (err) {
            console.error("DB Delete Error:", err.message);
            res.status(500).json({ success: false, message: "删除失败" });
        } else {
            res.json({ success: true, message: "删除成功" });
        }
    });
});

// --- API 5: 统计数据 (受保护) ---
app.get('/api/admin/statistics', verifyToken, (req, res) => {
    const today = getBeijingTime().split(' ')[0];
    
    // 获取总数统计
    db.all(`
        SELECT 
            COUNT(*) as total,
            COUNT(CASE WHEN type = 'praise' THEN 1 END) as praise,
            COUNT(CASE WHEN type = 'complaint' THEN 1 END) as complaint,
            COUNT(CASE WHEN date(created_at) = date(?) THEN 1 END) as today
        FROM surveys
    `, [today], (err, totalStats) => {
        if (err) {
            console.error("DB Statistics Error:", err.message);
            return res.status(500).json({ success: false, message: "统计查询错误" });
        }
        
        const stats = totalStats[0];
        res.json({ 
            success: true, 
            data: {
                total: stats.total,
                praise: stats.praise,
                complaint: stats.complaint,
                today: stats.today,
                thisWeek: stats.total, // 简化版，可以后续优化
                thisMonth: stats.total
            }
        });
    });
});

// 启动
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Security Server running on port ${PORT}`);
});