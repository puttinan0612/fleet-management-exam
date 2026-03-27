const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise'); // ใช้แบบ promise เพื่อให้ใช้ async/await ได้
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// ==========================================
// 1. ตั้งค่าการเชื่อมต่อฐานข้อมูล MySQL
// ==========================================
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '123456', // <--- แก้ตรงนี้ให้ตรงกับรหัสที่คุณใช้เข้าจอดำ
    database: 'fleet_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Secret Key สำหรับ JWT (ของจริงควรเก็บใน .env)
const JWT_SECRET = 'super_secret_fleet_key_2026';
const REFRESH_SECRET = 'super_secret_refresh_key_2026';

// ==========================================
// 2. Middleware: จัดการ Error ให้ตรง Pattern ตามโจทย์ (ห้ามละเมิด)
// ==========================================
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

// ==========================================
// 3. API ข้อ 1.1: Login เพื่อรับ JWT Tokens
// ==========================================
app.post('/auth/login', async (req, res, next) => {
    try {
        const { username, password } = req.body;

        // ดึงข้อมูล user จากฐานข้อมูล
        const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        const user = rows[0];

        // ถ้าไม่เจอ user หรือรหัสผ่าน (ที่เข้ารหัสด้วย bcrypt) ไม่ตรงกัน
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return next({ 
                statusCode: 401, 
                code: "INVALID_CREDENTIALS", 
                message: "Username หรือ Password ไม่ถูกต้อง" 
            });
        }

        // สร้าง Access Token (อายุ 15 นาที) ตามโจทย์
        const accessToken = jwt.sign(
            { id: user.id, username: user.username, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '15m' }
        );

        // สร้าง Refresh Token (อายุ 7 วัน) ตามโจทย์
        const refreshToken = jwt.sign(
            { id: user.id }, 
            REFRESH_SECRET, 
            { expiresIn: '7d' }
        );

        res.json({
            message: "Login สำเร็จ",
            accessToken,
            refreshToken,
            user: { id: user.id, username: user.username, role: user.role }
        });

    } catch (error) {
        next(error);
    }
});

// ==========================================
// 4. API ข้อ 1.2: JWT Middleware สำหรับ Protect Routes
// ==========================================
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1]; // แยกเอาคำว่า Bearer ออก

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                // ถ้า Token หมดอายุหรือไม่ถูกต้อง ตอบ 401 พร้อม error schema
                return next({ 
                    statusCode: 401, 
                    code: "UNAUTHORIZED", 
                    message: "Token หมดอายุหรือไม่ถูกต้อง กรุณา refresh token",
                    details: { expiredAt: err.expiredAt }
                });
            }
            req.user = user; // เก็บข้อมูล user ไว้ใช้ใน route ถัดไป
            next();
        });
    } else {
        next({ statusCode: 401, code: "MISSING_TOKEN", message: "ไม่พบ Authorization Token" });
    }
};

// ตัวอย่าง Route ที่ต้อง Login ถึงจะเข้าได้ (ไว้ทดสอบ)
app.get('/api/me', authenticateJWT, (req, res) => {
    res.json({ message: "ข้อมูลส่วนตัวของคุณ", user: req.user });
});

// ==========================================
// ตัวช่วยพิเศษ: API สำหรับสร้าง User แอดมิน
// ==========================================
app.get('/setup', async (req, res) => {
    try {
        // เข้ารหัสผ่าน "123456" ด้วย bcrypt ตามที่โจทย์บังคับ
        const hashedPassword = await bcrypt.hash('123456', 10);
        
        // ยัดลง Database
        await db.query(
            "INSERT IGNORE INTO users (id, username, password, role) VALUES ('usr_999', 'testadmin', ?, 'ADMIN')", 
            [hashedPassword]
        );
        
        res.send('✅ สร้าง user สำเร็จ! กลับไปที่ Thunder Client แล้วลอง Login ด้วย username: testadmin และ password: 123456 ได้เลยครับ');
    } catch (e) {
        res.send('❌ Error: ' + e.message);
    }
});

// ==========================================
// 5. API ข้อ 2.1: เพิ่มข้อมูลรถ (POST /vehicles)
// ==========================================
app.post('/vehicles', authenticateJWT, async (req, res, next) => {
    try {
        const { 
            license_plate, type, brand, model, year, 
            fuel_type, mileage_km, last_service_km, next_service_km 
        } = req.body;

        // --- 1. Input Validation (ตรวจสอบข้อมูล) ---
        const errors = {};
        if (!license_plate) errors.license_plate = "ต้องระบุป้ายทะเบียน";
        
        // ตรวจสอบ Enum ของประเภทรถ
        const validTypes = ['TRUCK', 'VAN', 'MOTORCYCLE', 'PICKUP'];
        if (!type || !validTypes.includes(type)) {
            errors.type = `ประเภทรถต้องเป็น ${validTypes.join(', ')}`;
        }
        
        if (!next_service_km) errors.next_service_km = "ต้องระบุระยะทางเข้าซ่อมรอบถัดไป";

        // ถ้ามี Error แม้แต่อย่างเดียว ให้เตะกลับพร้อม Schema ที่โจทย์บังคับ
        if (Object.keys(errors).length > 0) {
            return next({
                statusCode: 400,
                code: "VALIDATION_ERROR",
                message: "ข้อมูลไม่ถูกต้องหรือไม่ครบถ้วน",
                details: errors
            });
        }

        // --- 2. สร้าง ID และบันทึกลง MySQL ---
        const id = 'veh_' + Date.now(); // สร้าง ID อัตโนมัติ (เช่น veh_171000...)
        const status = 'IDLE'; // ค่าเริ่มต้น

        await db.query(
            `INSERT INTO vehicles 
            (id, license_plate, type, status, brand, model, year, fuel_type, mileage_km, last_service_km, next_service_km) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, license_plate, type, status, brand, model, year, fuel_type, mileage_km || 0, last_service_km || 0, next_service_km]
        );

        // --- 3. ตอบกลับเมื่อบันทึกสำเร็จ ---
        res.status(201).json({
            message: "เพิ่มข้อมูลรถสำเร็จ",
            vehicle: { id, license_plate, status }
        });

    } catch (error) {
        next(error);
    }
});

// ==========================================
// 6. API ข้อ 2.2: ดึงรายชื่อรถทั้งหมด (GET /vehicles)
// ==========================================
app.get('/vehicles', authenticateJWT, async (req, res, next) => {
    try {
        // 1. รับค่าสำหรับการแบ่งหน้า (Pagination) และกรองข้อมูล (Filters) จาก Query String
        const page = parseInt(req.query.page) || 1; // ถ้าไม่ส่งมาให้หน้าแรกเป็น 1
        const limit = parseInt(req.query.limit) || 10; // ถ้าไม่ส่งมาให้ดึงมา 10 รายการ
        const status = req.query.status;
        const type = req.query.type;

        const offset = (page - 1) * limit;

        // 2. สร้างเงื่อนไข WHERE แบบ Dynamic (ตามที่ผู้ใช้ส่ง Filter มา)
        let whereClauses = [];
        let queryValues = [];

        if (status) {
            whereClauses.push("status = ?");
            queryValues.push(status);
        }
        if (type) {
            whereClauses.push("type = ?");
            queryValues.push(type);
        }

        // ประกอบร่างคำสั่ง WHERE
        let whereSQL = "";
        if (whereClauses.length > 0) {
            whereSQL = "WHERE " + whereClauses.join(" AND ");
        }

        // 3. Query หาจำนวนข้อมูลทั้งหมด (เอาไว้ทำเลขหน้าใน Frontend)
        const [countResult] = await db.query(`SELECT COUNT(*) as total FROM vehicles ${whereSQL}`, queryValues);
        const totalItems = countResult[0].total;
        const totalPages = Math.ceil(totalItems / limit);

        // 4. Query ดึงข้อมูลจริง (ใส่ LIMIT และ OFFSET ต่อท้าย)
        const sql = `SELECT * FROM vehicles ${whereSQL} ORDER BY id DESC LIMIT ? OFFSET ?`;
        
        // เอา limit และ offset เติมเข้าไปใน array ของตัวแปร
        const finalValues = [...queryValues, limit, offset];
        const [vehicles] = await db.query(sql, finalValues);

        // 5. ตอบกลับพร้อม Meta Data
        res.json({
            data: vehicles,
            meta: {
                current_page: page,
                limit: limit,
                total_items: totalItems,
                total_pages: totalPages
            }
        });

    } catch (error) {
        next(error);
    }
});

// ==========================================
// 7. API ข้อ 3.1: สร้าง Trip พร้อม Checkpoints อัตโนมัติ (POST /trips)
// ==========================================
app.post('/trips', authenticateJWT, async (req, res, next) => {
    // ดึง Connection แยกออกมาเพื่อทำ Transaction
    const connection = await db.getConnection(); 
    
    try {
        const { 
            vehicle_id, driver_id, origin, destination, 
            distance_km, cargo_type, cargo_weight_kg 
        } = req.body;

        // 1. ตรวจสอบข้อมูลเบื้องต้น
        if (!vehicle_id || !origin || !destination) {
            return next({
                statusCode: 400,
                code: "VALIDATION_ERROR",
                message: "ต้องระบุรถ (vehicle_id), ต้นทาง (origin) และ ปลายทาง (destination)",
                details: { vehicle_id, origin, destination }
            });
        }

        // เริ่มต้น Transaction! (ถ้าระหว่างนี้มี Error จะ Rollback กลับทั้งหมด)
        await connection.beginTransaction();

        // 2. สร้าง Trip ใหม่
        const tripId = 'trp_' + Date.now();
        const tripStatus = 'SCHEDULED';
        const startedAt = new Date(); // ให้เริ่มเดินทางทันที (เพื่อความง่ายในการทดสอบ)

        await connection.query(
            `INSERT INTO trips 
            (id, vehicle_id, driver_id, status, started_at, origin, destination, distance_km, cargo_type, cargo_weight_kg) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [tripId, vehicle_id, driver_id, tripStatus, startedAt, origin, destination, distance_km, cargo_type, cargo_weight_kg]
        );

        // 3. สร้าง Checkpoint 1 (ต้นทาง)
        const cp1Id = 'cp_' + Date.now() + '_1';
        await connection.query(
            `INSERT INTO checkpoints (id, trip_id, sequence, status, location_name, purpose) 
            VALUES (?, ?, ?, ?, ?, ?)`,
            [cp1Id, tripId, 1, 'ARRIVED', origin, 'PICKUP'] // ต้นทางถือว่า Arrived แล้ว
        );

        // 4. สร้าง Checkpoint 2 (ปลายทาง)
        const cp2Id = 'cp_' + Date.now() + '_2';
        await connection.query(
            `INSERT INTO checkpoints (id, trip_id, sequence, status, location_name, purpose) 
            VALUES (?, ?, ?, ?, ?, ?)`,
            [cp2Id, tripId, 2, 'PENDING', destination, 'DELIVERY'] // ปลายทางรอไปถึง (Pending)
        );

        // ยืนยันการบันทึกข้อมูลทั้งหมด (Commit)
        await connection.commit();

        // 5. ตอบกลับการสร้างสำเร็จ
        res.status(201).json({
            message: "สร้าง Trip และ Checkpoint อัตโนมัติสำเร็จ",
            trip: {
                id: tripId,
                status: tripStatus,
                origin: origin,
                destination: destination
            },
            checkpoints: [
                { id: cp1Id, sequence: 1, location: origin, status: 'ARRIVED' },
                { id: cp2Id, sequence: 2, location: destination, status: 'PENDING' }
            ]
        });

    } catch (error) {
        // ถ้ามี Error เกิดขึ้นตรงไหนก็ตาม ให้ย้อนกลับข้อมูลทั้งหมด (Rollback)
        await connection.rollback();
        next(error);
    } finally {
        // คืน Connection กลับสู่ Pool เสมอ
        connection.release();
    }
});

// ==========================================
// 8. API ข้อ 3.2: อัปเดต Checkpoint และจบ Trip อัตโนมัติ (PATCH)
// ==========================================
app.patch('/trips/:id/checkpoints/:checkpointId', authenticateJWT, async (req, res, next) => {
    const connection = await db.getConnection();
    try {
        const { id: tripId, checkpointId } = req.params;
        const { status, notes } = req.body;

        // 1. ตรวจสอบ Status ที่อนุญาต
        const validStatuses = ['PENDING', 'ARRIVED', 'DEPARTED', 'SKIPPED'];
        if (!validStatuses.includes(status)) {
            return next({ statusCode: 400, code: "VALIDATION_ERROR", message: "Status ไม่ถูกต้อง ต้องเป็น PENDING, ARRIVED, DEPARTED หรือ SKIPPED" });
        }

        await connection.beginTransaction();

        // 2. ดึงข้อมูล Checkpoint ปัจจุบันมาดูก่อนว่ามีไหม
        const [cpRows] = await connection.query(
            `SELECT * FROM checkpoints WHERE id = ? AND trip_id = ?`,
            [checkpointId, tripId]
        );

        if (cpRows.length === 0) {
            await connection.rollback();
            return next({ statusCode: 404, code: "NOT_FOUND", message: "ไม่พบ Checkpoint นี้ในระบบ" });
        }

        const currentCp = cpRows[0];

        // 3. Business Logic: ห้ามข้ามลำดับ! (เช็คว่ามี Checkpoint ก่อนหน้าที่ยัง PENDING อยู่ไหม)
        const [pendingPrev] = await connection.query(
            `SELECT id FROM checkpoints WHERE trip_id = ? AND sequence < ? AND status = 'PENDING'`,
            [tripId, currentCp.sequence]
        );

        if (pendingPrev.length > 0) {
            await connection.rollback();
            return next({ 
                statusCode: 400, 
                code: "SEQUENCE_ERROR", 
                message: "ไม่สามารถข้ามลำดับได้ ต้องอัปเดต Checkpoint ก่อนหน้าให้เสร็จก่อน" 
            });
        }

        // 4. อัปเดตสถานะ Checkpoint (ถ้า ARRIVED ให้ประทับเวลาด้วย)
        const arrivedAt = (status === 'ARRIVED') ? new Date() : null;
        await connection.query(
            `UPDATE checkpoints SET status = ?, notes = ?, arrived_at = COALESCE(?, arrived_at) WHERE id = ?`,
            [status, notes || null, arrivedAt, checkpointId]
        );

        // 5. Business Logic: ถ้าเป็น Checkpoint สุดท้าย และเพิ่งถึง (ARRIVED) ให้ปิด Trip (COMPLETED)
        const [maxSeqRows] = await connection.query(
            `SELECT MAX(sequence) as max_seq FROM checkpoints WHERE trip_id = ?`,
            [tripId]
        );
        const isLastCheckpoint = currentCp.sequence === maxSeqRows[0].max_seq;

        let tripCompleted = false;
        if (isLastCheckpoint && status === 'ARRIVED') {
            await connection.query(
                `UPDATE trips SET status = 'COMPLETED', ended_at = NOW() WHERE id = ?`,
                [tripId]
            );
            tripCompleted = true;
        }

        await connection.commit();

        res.json({
            message: "อัปเดต Checkpoint สำเร็จ",
            checkpoint_id: checkpointId,
            new_status: status,
            is_trip_completed: tripCompleted
        });

    } catch (error) {
        await connection.rollback();
        next(error);
    } finally {
        connection.release();
    }
});

// ==========================================
// 9. API ข้อ 4: Alert Engine ตรวจสอบระยะซ่อมบำรุง (GET /alerts/maintenance)
// ==========================================
app.get('/alerts/maintenance', authenticateJWT, async (req, res, next) => {
    try {
        // Query หารถที่ใกล้ถึงระยะซ่อมบำรุง (เหลือน้อยกว่าหรือเท่ากับ 1000 กม. หรือทะลุเป้าไปแล้วคือติดลบ)
        const [vehicles] = await db.query(`
            SELECT id, license_plate, mileage_km, next_service_km 
            FROM vehicles 
            WHERE (next_service_km - mileage_km) <= 1000
        `);

        // วนลูปเพื่อสร้างข้อความเตือน (Warning Message) ให้แต่ละคัน
        const alerts = vehicles.map(v => {
            const remaining = v.next_service_km - v.mileage_km;
            let message = "";
            
            if (remaining < 0) {
                message = `🚨 อันตราย! เลยกำหนดซ่อมบำรุงมาแล้ว ${Math.abs(remaining)} กม.`;
            } else {
                message = `⚠️ เตรียมตัว! ใกล้ถึงกำหนดซ่อมบำรุง (เหลืออีก ${remaining} กม.)`;
            }

            return {
                vehicle_id: v.id,
                license_plate: v.license_plate,
                mileage_km: v.mileage_km,
                next_service_km: v.next_service_km,
                warning_message: message
            };
        });

        res.json({
            message: "ตรวจสอบการแจ้งเตือนสำเร็จ",
            total_alerts: alerts.length,
            alerts: alerts
        });

    } catch (error) {
        next(error);
    }
});

// นำ Error Handler มาใช้เป็นตัวสุดท้ายเสมอ
app.use(errorHandler);

// เริ่มรัน Serve
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Fleet Backend รันแล้วที่พอร์ต http://localhost:${PORT}`);
});