const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// ---------------------------------------------------------
// 🛡️ 1. สร้าง Pattern ของ Error Response (ผ่าน Constraint!)
// ---------------------------------------------------------
const errorHandler = (err, req, res, next) => {
    const statusCode = err.statusCode || 500;
    res.status(statusCode).json({
        error: {
            code: err.code || "INTERNAL_SERVER_ERROR",
            message: err.message || "เกิดข้อผิดพลาดในระบบ",
            details: err.details || {}
        }
    });
};

// ---------------------------------------------------------
// 🔐 2. Middleware สำหรับเช็ค JWT Token (ข้อ 1.2)
// ---------------------------------------------------------
const jwt = require('jsonwebtoken');
const SECRET_KEY = "my_super_secret_key"; // ของจริงควรอยู่ใน .env

const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, SECRET_KEY, (err, user) => {
            if (err) {
                return next({ statusCode: 401, code: "UNAUTHORIZED", message: "Token หมดอายุหรือไม่ถูกต้อง กรุณา Refresh" }); // ตอบ 401 ตามโจทย์เป๊ะ
            }
            req.user = user;
            next();
        });
    } else {
        next({ statusCode: 401, code: "UNAUTHORIZED", message: "ไม่มี Token" });
    }
};

// ตัวอย่าง Route ที่ต้อง Login ถึงจะเข้าได้
app.get('/api/protected', authenticateJWT, (req, res) => {
    res.json({ message: "คุณเข้าถึงข้อมูลได้!", user: req.user });
});

// นำ Error Handler มาต่อท้ายสุดเสมอ
app.use(errorHandler);

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});