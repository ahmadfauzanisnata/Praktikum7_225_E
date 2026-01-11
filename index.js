const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const port = 3001;
const saltRounds = 10;

// Koneksi ke database MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'afi21092004',
    database: 'api_db',
    port: 3307,
    charset: 'utf8mb4'
});

db.connect((err) => {
    if (err) {
        console.error('Koneksi database gagal:', err);
        console.error('Detail error:', err.message);
    } else {
        console.log('✅ Terhubung ke database MySQL (api_db)');
        
        // Test query untuk memastikan koneksi berhasil
        db.query('SELECT 1 + 1 AS result', (err, results) => {
            if (err) {
                console.error('❌ Tes koneksi gagal:', err.message);
            } else {
                console.log('✅ Tes koneksi sukses:', results);
            }
        });
    }
});

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: 'secret-key-yang-sangat-rahasia',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true
    }
}));

// --- Helper Functions ---
function checkKeyStatus(expiryDate) {
    if (!expiryDate) return 'OFF';
    const now = new Date();
    const expiry = new Date(expiryDate);
    return (expiry.getTime() + 86400000) > now.getTime() ? 'ON' : 'OFF';
}

function generateApiKey() {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let apiKey = '';
    const segments = [8, 4, 4, 4, 12];

    segments.forEach((segmentLength, index) => {
        for (let i = 0; i < segmentLength; i++) {
            apiKey += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        if (index < segments.length - 1) apiKey += '-';
    });
    return apiKey;
}

// --- Middlewares ---
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

function isAdmin(req, res, next) {
    if (req.session.userId && req.session.role === 'admin') {
        next();
    } else {
        res.redirect('/admin/login');
    }
}

function isUser(req, res, next) {
    if (req.session.userId && req.session.role === 'user') {
        next();
    } else {
        res.redirect('/login');
    }
}

function apiAuthMiddleware(req, res, next) {
    const apiKey = req.headers['x-api-key'] || req.query.api_key;

    if (!apiKey) {
        return res.status(401).json({ 
            success: false, 
            message: 'Akses Ditolak: API Key tidak ditemukan.' 
        });
    }

    const query = 'SELECT expires_at FROM api_keys WHERE api_key = ?';
    db.query(query, [apiKey], (err, keys) => {
        if (err) {
            console.error('Error database saat otentikasi API Key:', err.message);
            console.error('Query:', query);
            console.error('API Key:', apiKey);
            return res.status(500).json({ success: false, message: 'Kesalahan Server Internal.' });
        }

        if (keys.length === 0) {
            return res.status(403).json({ success: false, message: 'Akses Ditolak: API Key tidak valid.' });
        }

        const key = keys[0];
        const status = checkKeyStatus(key.expires_at);

        if (status === 'OFF') {
            return res.status(403).json({ success: false, message: 'Akses Ditolak: API Key telah kadaluarsa.' });
        }

        req.apiKey = apiKey;
        next();
    });
}

// --- Debug Route untuk Cek Database ---
app.get('/debug/database', (req, res) => {
    const queries = [
        'SHOW TABLES',
        'DESCRIBE users',
        'DESCRIBE api_keys',
        'SELECT COUNT(*) as user_count FROM users',
        'SELECT COUNT(*) as api_key_count FROM api_keys'
    ];

    const results = {};
    let completed = 0;

    queries.forEach((query, index) => {
        db.query(query, (err, result) => {
            results[query] = { error: err, data: result };
            completed++;

            if (completed === queries.length) {
                res.json(results);
            }
        });
    });
});

// --- Routes ---

// Halaman utama
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <title>API Platform</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }
                .container {
                    text-align: center;
                    color: white;
                    max-width: 600px;
                }
                h1 {
                    font-size: 2.5rem;
                    margin-bottom: 20px;
                }
                p {
                    font-size: 1.1rem;
                    margin-bottom: 30px;
                    line-height: 1.6;
                }
                .buttons {
                    display: flex;
                    gap: 15px;
                    justify-content: center;
                    flex-wrap: wrap;
                }
                .btn {
                    padding: 12px 24px;
                    background: white;
                    color: #667eea;
                    text-decoration: none;
                    border-radius: 8px;
                    font-weight: bold;
                    transition: all 0.3s;
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                }
                .btn:hover {
                    transform: translateY(-3px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }
                .debug-link {
                    margin-top: 30px;
                    font-size: 0.9rem;
                }
                .debug-link a {
                    color: rgba(255,255,255,0.8);
                    text-decoration: none;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚀 API Platform</h1>
                <p>Generate and manage your API keys. Access powerful APIs for weather, payments, geolocation, and more.</p>
                <div class="buttons">
                    <a href="/login" class="btn">🔑 Login</a>
                    <a href="/register" class="btn">📝 Register</a>
                    <a href="/admin/login" class="btn">⚡ Admin Login</a>
                    <a href="/api/docs" class="btn">📚 API Docs</a>
                </div>
                <div class="debug-link">
                    <a href="/debug/database">🔧 Debug Database</a>
                </div>
            </div>
        </body>
        </html>
    `);
});

// --- Authentication Routes ---

// Halaman login
app.get('/login', (req, res) => {
    if (req.session.userId) {
        if (req.session.role === 'admin') {
            return res.redirect('/admin/dashboard');
        } else {
            return res.redirect('/user/dashboard');
        }
    }
    res.send(getLoginForm());
});

// Halaman register
app.get('/register', (req, res) => {
    if (req.session.userId) {
        if (req.session.role === 'admin') {
            return res.redirect('/admin/dashboard');
        } else {
            return res.redirect('/user/dashboard');
        }
    }
    res.send(getRegisterForm());
});

// Proses login - DIPERBAIKI
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    
    console.log('Login attempt for:', email);
    
    if (!email || !password) {
        return res.status(400).send(getErrorHtml('Email dan password wajib diisi!'));
    }

    // Query yang DIPERBAIKI
    const query = 'SELECT id, email, password, first_name, last_name, role FROM users WHERE email = ?';
    
    console.log('Executing query:', query, 'with email:', email);
    
    db.query(query, [email], async (err, users) => {
        if (err) {
            console.error('❌ Error saat login:', err.message);
            console.error('SQL Error:', err.sql);
            return res.status(500).send(getErrorHtml('Terjadi kesalahan server: ' + err.message));
        }

        console.log('Query result:', users);

        if (users.length === 0) {
            console.log('User tidak ditemukan');
            return res.status(401).send(getErrorHtml('Email atau password salah.'));
        }

        const user = users[0];
        console.log('User found:', user.email, 'Role:', user.role);
        
        // Untuk testing, jika password adalah 'admin123' (plain text)
        // Hapus ini di production!
        if (password === 'admin123' && user.email === 'admin@api.com') {
            console.log('Admin login with default password');
            req.session.userId = user.id;
            req.session.email = user.email;
            req.session.firstName = user.first_name || 'Admin';
            req.session.lastName = user.last_name || '';
            req.session.role = user.role || 'admin';
            
            // Hash password untuk admin
            const hashedPassword = await bcrypt.hash('admin123', saltRounds);
            db.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id], (err) => {
                if (err) console.error('Error updating password:', err);
            });
            
            return res.redirect('/admin/dashboard');
        }

        // Check password dengan bcrypt
        const match = await bcrypt.compare(password, user.password);
        console.log('Password match:', match);
        
        if (match) {
            req.session.userId = user.id;
            req.session.email = user.email;
            req.session.firstName = user.first_name || '';
            req.session.lastName = user.last_name || '';
            req.session.role = user.role || 'user';

            console.log('Login successful, redirecting...');
            
            if (user.role === 'admin') {
                res.redirect('/admin/dashboard');
            } else {
                res.redirect('/user/dashboard');
            }
        } else {
            console.log('Password salah');
            res.status(401).send(getErrorHtml('Email atau password salah.'));
        }
    });
});

// Proses register - DIPERBAIKI
app.post('/register', async (req, res) => {
    const { firstName, lastName, email, password, confirmPassword } = req.body;
    
    console.log('Register attempt for:', email);
    
    if (!firstName || !lastName || !email || !password || !confirmPassword) {
        return res.status(400).send(getErrorHtml('Semua kolom wajib diisi!'));
    }

    if (password !== confirmPassword) {
        return res.status(400).send(getErrorHtml('Password dan konfirmasi password tidak cocok!'));
    }

    try {
        // Cek apakah email sudah terdaftar
        const checkQuery = 'SELECT id FROM users WHERE email = ?';
        db.query(checkQuery, [email], async (err, results) => {
            if (err) {
                console.error('❌ Error cek email:', err.message);
                return res.status(500).send(getErrorHtml('Terjadi kesalahan server.'));
            }

            if (results.length > 0) {
                return res.status(400).send(getErrorHtml('Email sudah terdaftar!'));
            }

            // Hash password dan simpan user
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const insertQuery = 'INSERT INTO users (first_name, last_name, email, password, role) VALUES (?, ?, ?, ?, ?)';
            
            console.log('Inserting user with query:', insertQuery);
            
            db.query(insertQuery, [firstName, lastName, email, hashedPassword, 'user'], (err, result) => {
                if (err) {
                    console.error('❌ Error simpan user:', err.message);
                    console.error('SQL Error:', err.sql);
                    return res.status(500).send(getErrorHtml('Gagal menyimpan data user: ' + err.message));
                }

                console.log('User registered successfully, ID:', result.insertId);

                // Auto login setelah register
                req.session.userId = result.insertId;
                req.session.email = email;
                req.session.firstName = firstName;
                req.session.lastName = lastName;
                req.session.role = 'user';
                
                // Create free subscription for new user
                const subscriptionQuery = `
                    INSERT INTO subscriptions (user_id, plan_type, max_api_keys, max_requests_per_day, 
                    rate_limit_per_minute, access_to_services, starts_at, ends_at, status)
                    VALUES (?, 'free', 3, 1000, 60, '["1", "3"]', NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY), 'active')
                `;
                
                db.query(subscriptionQuery, [result.insertId], (err) => {
                    if (err) console.error('Error creating subscription:', err);
                });
                
                res.redirect('/user/dashboard');
            });
        });
    } catch (error) {
        console.error('❌ Error register:', error);
        res.status(500).send(getErrorHtml('Terjadi kesalahan server.'));
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error logout:', err);
        }
        res.redirect('/');
    });
});

// --- User Routes ---

// Dashboard User - DIPERBAIKI
app.get('/user/dashboard', isUser, (req, res) => {
    const userId = req.session.userId;
    
    console.log('Loading user dashboard for user ID:', userId);
    
    // Query yang DIPERBAIKI
    const query = `
        SELECT id, name as api_name, api_key, expires_at as expiry_date, created_at 
        FROM api_keys 
        WHERE user_id = ? AND status = 'active'
        ORDER BY created_at DESC
    `;
    
    db.query(query, [userId], (err, apiKeys) => {
        if (err) {
            console.error('❌ Error mengambil API keys:', err.message);
            console.error('Query:', query);
            console.error('User ID:', userId);
            return res.status(500).send(`
                <h1>Error</h1>
                <p>Gagal mengambil data API Key.</p>
                <p>Error: ${err.message}</p>
                <a href="/">Kembali ke Home</a>
            `);
        }
        
        console.log('API Keys found:', apiKeys.length);
        
        // Hitung total API keys dan active keys
        const totalKeys = apiKeys.length;
        const activeKeys = apiKeys.filter(k => checkKeyStatus(k.expiry_date) === 'ON').length;
        
        res.send(getUserDashboardHtml(req.session.firstName, req.session.email, apiKeys, totalKeys, activeKeys));
    });
});

// Generate API Key (User) - DIPERBAIKI
app.post('/user/generate-api-key', isUser, (req, res) => {
    const { apiName } = req.body;
    
    console.log('Generating API Key for user:', req.session.userId);
    
    if (!apiName) {
        return res.status(400).json({ success: false, message: 'Nama API Key wajib diisi!' });
    }

    const apiKey = generateApiKey();
    const expiresAt = new Date();
    expiresAt.setFullYear(expiresAt.getFullYear() + 1);

    // Query yang DIPERBAIKI
    const query = `
        INSERT INTO api_keys (user_id, name, api_key, expires_at, status, environment) 
        VALUES (?, ?, ?, ?, 'active', 'development')
    `;
    
    db.query(query, [req.session.userId, apiName, apiKey, expiresAt], (err, result) => {
        if (err) {
            console.error('❌ Gagal menyimpan API Key:', err.message);
            console.error('Query:', query);
            return res.status(500).json({
                success: false,
                message: 'Gagal menyimpan API Key ke database: ' + err.message
            });
        }
        
        console.log('API Key created successfully, ID:', result.insertId);
        
        res.json({
            success: true,
            apiName: apiName,
            apiKey: apiKey,
            message: '✅ API Key berhasil dibuat.'
        });
    });
});

// Delete API Key (User) - DIPERBAIKI
// Delete API Key (User) - HARD DELETE VERSION
app.post('/user/api-keys/delete/:id', isUser, (req, res) => {
    const keyId = req.params.id;
    const userId = req.session.userId;
    
    console.log('=== USER DELETE API KEY REQUEST ===');
    console.log('User ID:', userId);
    console.log('API Key ID:', keyId);
    
    const query = 'DELETE FROM api_keys WHERE id = ? AND user_id = ?';
    
    db.query(query, [keyId, userId], (err, result) => {
        if (err) {
            console.error('❌ Error deleting API Key:', err.message);
            console.error('SQL Error:', err);
            return res.redirect('/user/dashboard?message=Error+deleting+API+Key&type=error');
        }
        
        if (result.affectedRows === 0) {
            console.log('API Key not found or permission denied');
            return res.redirect('/user/dashboard?message=API+Key+not+found+or+permission+denied&type=error');
        }
        
        console.log('✅ API Key deleted successfully');
        console.log('Deleted rows:', result.affectedRows);
        
        res.redirect('/user/dashboard?message=API+Key+deleted+successfully&type=success');
    });
});

// --- Admin Routes ---

// Admin Login (alternatif)
app.get('/admin/login', (req, res) => {
    if (req.session.userId && req.session.role === 'admin') {
        return res.redirect('/admin/dashboard');
    }
    res.send(getAdminLoginForm());
});

// Dashboard Admin - DIPERBAIKI
// Dashboard Admin - DIPERBAIKI dengan message support
app.get('/admin/dashboard', isAdmin, (req, res) => {
    const message = req.query.message || '';
    const messageType = req.query.type || '';
    
    console.log('Loading admin dashboard with message:', message);
    
    const usersQuery = 'SELECT id, first_name, last_name, email, role, status, created_at FROM users ORDER BY id DESC';
    const apiKeysQuery = `
        SELECT ak.id, ak.name as api_name, ak.api_key, ak.expires_at as expiry_date, 
               ak.status, ak.created_at,
               u.email, u.first_name, u.last_name 
        FROM api_keys ak 
        JOIN users u ON ak.user_id = u.id 
        ORDER BY ak.id DESC
    `;

    db.query(usersQuery, (err, users) => {
        if (err) {
            console.error('❌ Error mengambil users:', err.message);
            return res.status(500).send(`
                <h1>Error</h1>
                <p>Gagal mengambil data user.</p>
                <p>Error: ${err.message}</p>
                <a href="/admin/dashboard">Refresh</a>
            `);
        }

        db.query(apiKeysQuery, (err, apiKeys) => {
            if (err) {
                console.error('❌ Error mengambil API keys:', err.message);
                return res.status(500).send(`
                    <h1>Error</h1>
                    <p>Gagal mengambil data API Key.</p>
                    <p>Error: ${err.message}</p>
                    <a href="/admin/dashboard">Refresh</a>
                `);
            }

            res.send(getAdminDashboardHtml(req.session.email, users, apiKeys, message, messageType));
        });
    });
});

// Edit User (Admin) - DIPERBAIKI
app.get('/admin/users/edit/:id', isAdmin, (req, res) => {
    const userId = req.params.id;
    const query = 'SELECT id, first_name, last_name, email, role, status FROM users WHERE id = ?';

    db.query(query, [userId], (err, users) => {
        if (err || users.length === 0) {
            console.error('Error fetching user:', err?.message);
            return res.status(404).send('User tidak ditemukan.');
        }
        res.send(getEditUserForm(users[0]));
    });
});

app.post('/admin/users/update/:id', isAdmin, (req, res) => {
    const userId = req.params.id;
    const { firstName, lastName, email, role, status } = req.body;

    if (!firstName || !lastName || !email || !role || !status) {
        return res.status(400).send('Semua kolom user harus diisi!');
    }

    const query = 'UPDATE users SET first_name = ?, last_name = ?, email = ?, role = ?, status = ? WHERE id = ?';
    db.query(query, [firstName, lastName, email, role, status, userId], (err) => {
        if (err) {
            console.error('❌ Gagal mengupdate user:', err.message);
            return res.status(500).send('Gagal mengupdate user ke database: ' + err.message);
        }
        res.redirect('/admin/dashboard');
    });
});

// Delete User (Admin) - HARD DELETE VERSION
app.post('/admin/users/delete/:id', isAdmin, (req, res) => {
    const userId = req.params.id;
    
    console.log('=== DELETE USER REQUEST ===');
    console.log('Deleting user ID:', userId);
    console.log('Admin ID:', req.session.userId);
    
    // Cek apakah admin mencoba menghapus dirinya sendiri
    if (parseInt(userId) === req.session.userId) {
        console.log('ERROR: Admin cannot delete themselves');
        return res.send(`
            <!DOCTYPE html>
            <html>
            <head><title>Error</title></head>
            <body>
                <h1>Error</h1>
                <p>You cannot delete your own account!</p>
                <a href="/admin/dashboard">Back to Dashboard</a>
            </body>
            </html>
        `);
    }
    
    // Mulai transaction untuk menghapus semua data terkait
    db.beginTransaction((err) => {
        if (err) {
            console.error('Error starting transaction:', err);
            return res.status(500).send('Error starting transaction');
        }
        
        // 1. Hapus semua API keys user ini
        const deleteApiKeysQuery = 'DELETE FROM api_keys WHERE user_id = ?';
        db.query(deleteApiKeysQuery, [userId], (err, apiResult) => {
            if (err) {
                console.error('Error deleting API keys:', err);
                return db.rollback(() => {
                    res.status(500).send('Error deleting API keys');
                });
            }
            console.log('Deleted API keys:', apiResult.affectedRows);
            
            // 2. Hapus subscriptions user
            const deleteSubsQuery = 'DELETE FROM subscriptions WHERE user_id = ?';
            db.query(deleteSubsQuery, [userId], (err, subResult) => {
                if (err) {
                    console.error('Error deleting subscriptions:', err);
                    return db.rollback(() => {
                        res.status(500).send('Error deleting subscriptions');
                    });
                }
                console.log('Deleted subscriptions:', subResult.affectedRows);
                
                // 3. Hapus payments user
                const deletePaymentsQuery = 'DELETE FROM payments WHERE user_id = ?';
                db.query(deletePaymentsQuery, [userId], (err, paymentResult) => {
                    if (err) {
                        console.error('Error deleting payments:', err);
                        return db.rollback(() => {
                            res.status(500).send('Error deleting payments');
                        });
                    }
                    console.log('Deleted payments:', paymentResult.affectedRows);
                    
                    // 4. Hapus notifications user
                    const deleteNotifQuery = 'DELETE FROM notifications WHERE user_id = ?';
                    db.query(deleteNotifQuery, [userId], (err, notifResult) => {
                        if (err) {
                            console.error('Error deleting notifications:', err);
                            return db.rollback(() => {
                                res.status(500).send('Error deleting notifications');
                            });
                        }
                        console.log('Deleted notifications:', notifResult.affectedRows);
                        
                        // 5. Hapus user itu sendiri
                        const deleteUserQuery = 'DELETE FROM users WHERE id = ?';
                        db.query(deleteUserQuery, [userId], (err, userResult) => {
                            if (err) {
                                console.error('Error deleting user:', err);
                                return db.rollback(() => {
                                    res.status(500).send('Error deleting user');
                                });
                            }
                            
                            // Commit transaction
                            db.commit((err) => {
                                if (err) {
                                    console.error('Error committing transaction:', err);
                                    return db.rollback(() => {
                                        res.status(500).send('Error committing transaction');
                                    });
                                }
                                
                                console.log('✅ User deleted successfully');
                                console.log('Deleted user rows:', userResult.affectedRows);
                                
                                // Redirect dengan pesan sukses
                                res.redirect('/admin/dashboard?message=User+deleted+successfully&type=success');
                            });
                        });
                    });
                });
            });
        });
    });
});


// Delete API Key (Admin) - HARD DELETE VERSION
app.post('/admin/api-keys/delete/:id', isAdmin, (req, res) => {
    const keyId = req.params.id;
    
    console.log('=== DELETE API KEY REQUEST ===');
    console.log('Deleting API Key ID:', keyId);
    
    const query = 'DELETE FROM api_keys WHERE id = ?';
    
    db.query(query, [keyId], (err, result) => {
        if (err) {
            console.error('❌ Error deleting API Key:', err.message);
            console.error('SQL Error:', err);
            
            // Redirect dengan pesan error
            return res.redirect('/admin/dashboard?message=Error+deleting+API+Key: ' + encodeURIComponent(err.message) + '&type=error');
        }
        
        if (result.affectedRows === 0) {
            console.log('API Key not found');
            return res.redirect('/admin/dashboard?message=API+Key+not+found&type=error');
        }
        
        console.log('✅ API Key deleted successfully');
        console.log('Deleted rows:', result.affectedRows);
        
        // Redirect dengan pesan sukses
        res.redirect('/admin/dashboard?message=API+Key+deleted+successfully&type=success');
    });
});

// --- API Endpoints ---

// API Documentation
app.get('/api/docs', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <title>API Documentation</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    padding: 20px; 
                    max-width: 1200px; 
                    margin: 0 auto;
                }
                h1 { color: #333; }
                .endpoint { 
                    background: #f5f5f5; 
                    padding: 20px; 
                    margin: 15px 0; 
                    border-left: 4px solid #007bff; 
                    border-radius: 5px;
                }
                code { 
                    background: #e9ecef; 
                    padding: 5px 10px; 
                    border-radius: 3px; 
                    font-family: 'Courier New', monospace;
                }
                .method { 
                    display: inline-block; 
                    padding: 5px 10px; 
                    border-radius: 3px; 
                    color: white; 
                    font-weight: bold;
                }
                .get { background: #28a745; }
                .post { background: #007bff; }
                .put { background: #ffc107; color: #000; }
                .delete { background: #dc3545; }
            </style>
        </head>
        <body>
            <h1>📚 API Documentation</h1>
            
            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/users</h3>
                <p>Get all users (requires API Key)</p>
                <p><strong>Header:</strong> <code>X-API-Key: your-api-key</code></p>
                <p><strong>Response:</strong> List of users</p>
            </div>
            
            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/api-keys</h3>
                <p>Get all API keys (requires API Key)</p>
                <p><strong>Header:</strong> <code>X-API-Key: your-api-key</code></p>
            </div>
            
            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/weather</h3>
                <p>Get weather data for a city</p>
                <p><strong>Parameters:</strong> <code>?city=Jakarta</code></p>
                <p><strong>Header:</strong> <code>X-API-Key: your-api-key</code></p>
            </div>
            
            <a href="/">← Back to Home</a>
        </body>
        </html>
    `);
});

// Protected API Endpoints - DIPERBAIKI
app.get('/api/users', apiAuthMiddleware, (req, res) => {
    const usersQuery = 'SELECT id, first_name, last_name, email, role, created_at FROM users WHERE status = "active" ORDER BY id DESC';
    db.query(usersQuery, (err, users) => {
        if (err) {
            console.error('❌ Gagal mengambil data user untuk API:', err.message);
            return res.status(500).json({ success: false, message: 'Kesalahan Server Internal.' });
        }
        res.json({ success: true, count: users.length, data: users });
    });
});

app.get('/api/api-keys', apiAuthMiddleware, (req, res) => {
    const apiKeysQuery = `
        SELECT ak.id, ak.name as api_name, ak.api_key, ak.expires_at as expiry_date, 
               ak.status, ak.created_at,
               u.email as user_email 
        FROM api_keys ak 
        JOIN users u ON ak.user_id = u.id 
        WHERE ak.status = 'active'
        ORDER BY ak.id DESC
    `;
    
    db.query(apiKeysQuery, (err, apiKeys) => {
        if (err) {
            console.error('❌ Gagal mengambil data API Key untuk API:', err.message);
            return res.status(500).json({ success: false, message: 'Kesalahan Server Internal.' });
        }

        const dataWithStatus = apiKeys.map(key => ({
            id: key.id,
            api_name: key.api_name,
            api_key: key.api_key,
            user_email: key.user_email,
            created_at: key.created_at,
            expiry_date: key.expiry_date,
            status: checkKeyStatus(key.expiry_date)
        }));

        res.json({ success: true, count: dataWithStatus.length, data: dataWithStatus });
    });
});

// Sample API endpoint
app.get('/api/weather', apiAuthMiddleware, (req, res) => {
    const city = req.query.city || 'Jakarta';
    const weatherData = {
        location: city,
        temperature: Math.floor(Math.random() * 10) + 25,
        condition: "Partly Cloudy",
        humidity: Math.floor(Math.random() * 30) + 60,
        wind_speed: Math.floor(Math.random() * 10) + 5,
        unit: "celsius",
        timestamp: new Date().toISOString(),
        provider: "API Platform Weather Service"
    };
    res.json({ success: true, data: weatherData });
});

// --- HTML Helper Functions ---

function getBaseHtml(title, bodyContent) {
    return `
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <title>${title}</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                :root {
                    --primary: #6c63ff;
                    --primary-dark: #5a52d5;
                    --dark: #2c3e50;
                    --light: #f8f9fa;
                    --success: #2ecc71;
                    --danger: #e74c3c;
                }

                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    min-height: 100vh; 
                    padding: 20px;
                }
                
                .card { 
                    background: white; 
                    padding: 40px; 
                    border-radius: 20px; 
                    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); 
                    width: 100%; 
                    max-width: 450px; 
                }
                
                h2 { 
                    text-align: center; 
                    color: var(--dark); 
                    margin-bottom: 25px; 
                    font-size: 1.8rem; 
                }
                
                .form-group { 
                    margin-bottom: 20px; 
                }
                
                label { 
                    display: block; 
                    margin-bottom: 8px; 
                    font-weight: 600; 
                    color: var(--dark); 
                }
                
                input, select { 
                    width: 100%; 
                    padding: 15px; 
                    border: 2px solid #e0e0e0; 
                    border-radius: 10px; 
                    box-sizing: border-box; 
                    font-size: 1rem;
                }
                
                input:focus, select:focus {
                    border-color: var(--primary);
                    outline: none;
                    box-shadow: 0 0 0 3px rgba(108, 99, 255, 0.1);
                }
                
                button { 
                    background: var(--primary); 
                    color: white; 
                    border: none; 
                    padding: 15px; 
                    border-radius: 10px; 
                    cursor: pointer; 
                    width: 100%; 
                    margin-top: 15px; 
                    font-weight: 600;
                    font-size: 1rem;
                    transition: background 0.3s;
                }
                
                button:hover { 
                    background: var(--primary-dark); 
                }
                
                .link-container { 
                    text-align: center; 
                    margin-top: 25px; 
                    font-size: 0.9em; 
                }
                
                .link-container a { 
                    color: var(--primary); 
                    text-decoration: none; 
                    font-weight: 600;
                }
                
                .link-container a:hover { 
                    text-decoration: underline; 
                }
                
                .error-box { 
                    background: #ffe0e0; 
                    border: 2px solid var(--danger); 
                    color: #cc0000; 
                    padding: 15px; 
                    border-radius: 10px; 
                    text-align: center; 
                    margin-bottom: 20px; 
                }
            </style>
        </head>
        <body>
            <div class="card">
                ${bodyContent}
            </div>
        </body>
        </html>
    `;
}

function getErrorHtml(message) {
    const content = `
        <div class="error-box">
            <h3><i class="fas fa-exclamation-circle"></i> Error</h3>
            <p>${message}</p>
        </div>
        <div class="link-container">
            <a href="/login"><i class="fas fa-arrow-left"></i> Kembali ke Login</a>
        </div>
        <div class="link-container">
            <a href="/">🏠 Kembali ke Home</a>
        </div>
    `;
    return getBaseHtml('Error', content);
}

function getLoginForm() {
    const content = `
        <h2><i class="fas fa-sign-in-alt"></i> Login</h2>
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" placeholder="Email Anda" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Password Anda" required>
            </div>
            <button type="submit"><i class="fas fa-sign-in-alt"></i> Login</button>
        </form>
        <div class="link-container">
            Belum punya akun? <a href="/register">Register Sekarang</a>
        </div>
        <div class="link-container">
            <a href="/admin/login"><i class="fas fa-user-shield"></i> Login sebagai Admin</a>
        </div>
        <div class="link-container">
            <a href="/">🏠 Kembali ke Home</a>
        </div>
    `;
    return getBaseHtml('Login', content);
}

function getRegisterForm() {
    const content = `
        <h2><i class="fas fa-user-plus"></i> Register</h2>
        <form method="POST" action="/register">
            <div class="form-group">
                <label for="firstName">Nama Depan</label>
                <input type="text" id="firstName" name="firstName" placeholder="Nama Depan" required>
            </div>
            <div class="form-group">
                <label for="lastName">Nama Belakang</label>
                <input type="text" id="lastName" name="lastName" placeholder="Nama Belakang" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" placeholder="Email" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Password (min. 6 karakter)" required>
            </div>
            <div class="form-group">
                <label for="confirmPassword">Konfirmasi Password</label>
                <input type="password" id="confirmPassword" name="confirmPassword" placeholder="Ulangi Password" required>
            </div>
            <button type="submit"><i class="fas fa-user-plus"></i> Register</button>
        </form>
        <div class="link-container">
            Sudah punya akun? <a href="/login">Login Sekarang</a>
        </div>
        <div class="link-container">
            <a href="/">🏠 Kembali ke Home</a>
        </div>
    `;
    return getBaseHtml('Register', content);
}

function getAdminLoginForm() {
    const content = `
        <h2><i class="fas fa-user-shield"></i> Admin Login</h2>
        <p style="text-align: center; margin-bottom: 20px; color: #666;">Masuk sebagai Administrator</p>
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="email">Email Admin</label>
                <input type="email" id="email" name="email" placeholder="admin@api.com" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="admin123" required>
            </div>
            <button type="submit"><i class="fas fa-sign-in-alt"></i> Login sebagai Admin</button>
        </form>
        <div class="link-container">
            <a href="/login"><i class="fas fa-user"></i> Login sebagai User</a>
        </div>
        <div class="link-container">
            <a href="/">🏠 Kembali ke Home</a>
        </div>
    `;
    return getBaseHtml('Admin Login', content);
}

// ============================================
// USER DASHBOARD HTML
// ============================================
// ============================================
// USER DASHBOARD HTML - DIPERBAIKI
// ============================================
function getUserDashboardHtml(firstName, email, apiKeys, totalKeys, activeKeys) {
    const apiKeyRows = apiKeys.map(k => {
        const status = checkKeyStatus(k.expiry_date);
        const statusClass = status === 'ON' ? 'status-on' : 'status-off';
        const expiryDate = k.expiry_date ? new Date(k.expiry_date).toLocaleDateString('id-ID') : 'N/A';
        const createdDate = k.created_at ? new Date(k.created_at).toLocaleDateString('id-ID') : 'N/A';
        
        return `
            <tr>
                <td>${k.api_name}</td>
                <td><code class="api-key">${k.api_key}</code></td>
                <td><span class="${statusClass}">${status}</span></td>
                <td>${expiryDate}</td>
                <td>${createdDate}</td>
                <td>
                    <button onclick="copyKey('${k.api_key}')" class="action-btn copy-btn">
                        <i class="fas fa-copy"></i> Salin
                    </button>
                    <form method="POST" action="/user/api-keys/delete/${k.id}" style="display: inline;" 
                          onsubmit="return confirm('Hapus API Key ${k.api_name}?')">
                        <button type="submit" class="action-btn delete-btn">
                            <i class="fas fa-trash"></i> Hapus
                        </button>
                    </form>
                </td>
            </tr>
        `;
    }).join('') || '<tr><td colspan="6" style="text-align: center;">Belum ada API Key. Buat yang pertama!</td></tr>';

    return `
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <title>User Dashboard - API Platform</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                :root {
                    --primary: #6c63ff;
                    --primary-dark: #5a52d5;
                    --secondary: #ff6584;
                    --accent: #36d1dc;
                    --dark: #2c3e50;
                    --light: #f8f9fa;
                    --success: #2ecc71;
                    --warning: #f39c12;
                    --danger: #e74c3c;
                }

                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }

                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: #f5f5f5;
                    min-height: 100vh;
                }

                .dashboard-container {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }

                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border-radius: 15px;
                    padding: 25px;
                    margin-bottom: 30px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
                }

                .user-info h1 {
                    font-size: 1.8rem;
                    margin-bottom: 5px;
                }

                .user-info p {
                    opacity: 0.9;
                }

                .header-actions {
                    display: flex;
                    gap: 15px;
                }

                .btn {
                    padding: 12px 24px;
                    border-radius: 8px;
                    border: none;
                    cursor: pointer;
                    font-weight: 600;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    transition: all 0.3s;
                    text-decoration: none;
                    font-size: 0.95rem;
                }

                .btn-primary {
                    background: white;
                    color: #667eea;
                }

                .btn-primary:hover {
                    background: #f8f9fa;
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }

                .btn-logout {
                    background: rgba(255,255,255,0.2);
                    color: white;
                    border: 1px solid rgba(255,255,255,0.3);
                }

                .btn-logout:hover {
                    background: rgba(255,255,255,0.3);
                    transform: translateY(-2px);
                }

                .main-content {
                    display: grid;
                    grid-template-columns: 250px 1fr;
                    gap: 30px;
                }

                .sidebar {
                    background: white;
                    border-radius: 15px;
                    padding: 25px;
                    height: fit-content;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.05);
                }

                .sidebar h2 {
                    color: var(--dark);
                    margin-bottom: 20px;
                    font-size: 1.3rem;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }

                .nav-menu {
                    list-style: none;
                }

                .nav-menu li {
                    margin-bottom: 10px;
                }

                .nav-menu a {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    padding: 12px 15px;
                    border-radius: 10px;
                    color: var(--dark);
                    text-decoration: none;
                    transition: all 0.3s;
                }

                .nav-menu a:hover {
                    background: rgba(108, 99, 255, 0.1);
                    color: var(--primary);
                }

                .nav-menu a.active {
                    background: var(--primary);
                    color: white;
                }

                .content-area {
                    background: white;
                    border-radius: 15px;
                    padding: 30px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.05);
                }

                .section-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 30px;
                }

                .section-header h2 {
                    color: var(--dark);
                    font-size: 1.5rem;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }

                .create-api-form {
                    background: rgba(108, 99, 255, 0.05);
                    border-radius: 12px;
                    padding: 25px;
                    margin-bottom: 30px;
                    border: 2px dashed rgba(108, 99, 255, 0.3);
                }

                .form-row {
                    display: flex;
                    gap: 15px;
                    margin-bottom: 20px;
                }

                .form-group {
                    flex: 1;
                }

                .form-group label {
                    display: block;
                    margin-bottom: 8px;
                    color: var(--dark);
                    font-weight: 500;
                }

                .form-group input {
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #e0e0e0;
                    border-radius: 8px;
                    font-size: 1rem;
                    transition: all 0.3s;
                }

                .form-group input:focus {
                    border-color: var(--primary);
                    outline: none;
                    box-shadow: 0 0 0 3px rgba(108, 99, 255, 0.1);
                }

                .stats-cards {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }

                .stat-card {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border-radius: 12px;
                    padding: 25px;
                    text-align: center;
                    transition: transform 0.3s;
                }

                .stat-card:hover {
                    transform: translateY(-5px);
                }

                .stat-card i {
                    font-size: 2.5rem;
                    margin-bottom: 15px;
                    opacity: 0.9;
                }

                .stat-card h3 {
                    font-size: 2rem;
                    margin-bottom: 10px;
                }

                .stat-card p {
                    opacity: 0.9;
                    font-size: 0.9rem;
                }

                .api-keys-table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }

                .api-keys-table th {
                    background: #f8f9fa;
                    color: var(--dark);
                    padding: 15px;
                    text-align: left;
                    font-weight: 600;
                    border-bottom: 2px solid #e0e0e0;
                }

                .api-keys-table td {
                    padding: 15px;
                    border-bottom: 1px solid #eee;
                }

                .api-keys-table tr:hover {
                    background: #f9f9f9;
                }

                .api-key {
                    background: #f8f9fa;
                    padding: 8px 12px;
                    border-radius: 6px;
                    font-family: 'Courier New', monospace;
                    font-size: 0.9rem;
                    display: inline-block;
                    max-width: 300px;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }

                .status-on, .status-off {
                    padding: 6px 12px;
                    border-radius: 20px;
                    font-size: 0.85rem;
                    font-weight: 600;
                    display: inline-block;
                }

                .status-on {
                    background: rgba(46, 204, 113, 0.1);
                    color: var(--success);
                }

                .status-off {
                    background: rgba(243, 156, 18, 0.1);
                    color: var(--warning);
                }

                .action-btn {
                    padding: 8px 15px;
                    border-radius: 6px;
                    border: none;
                    cursor: pointer;
                    font-size: 0.9rem;
                    display: inline-flex;
                    align-items: center;
                    gap: 5px;
                    margin-right: 5px;
                    transition: all 0.3s;
                }

                .copy-btn {
                    background: rgba(52, 152, 219, 0.1);
                    color: #3498db;
                    border: 1px solid rgba(52, 152, 219, 0.2);
                }

                .copy-btn:hover {
                    background: #3498db;
                    color: white;
                }

                .delete-btn {
                    background: rgba(231, 76, 60, 0.1);
                    color: var(--danger);
                    border: 1px solid rgba(231, 76, 60, 0.2);
                }

                .delete-btn:hover {
                    background: var(--danger);
                    color: white;
                }

                .success-message {
                    background: rgba(46, 204, 113, 0.1);
                    border: 1px solid var(--success);
                    color: var(--success);
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                    display: none;
                }

                .error-message {
                    background: rgba(231, 76, 60, 0.1);
                    border: 1px solid var(--danger);
                    color: var(--danger);
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                    display: none;
                }

                @media (max-width: 992px) {
                    .main-content {
                        grid-template-columns: 1fr;
                    }
                    
                    .header {
                        flex-direction: column;
                        gap: 20px;
                        text-align: center;
                    }
                    
                    .form-row {
                        flex-direction: column;
                    }
                }

                @media (max-width: 768px) {
                    .header-actions {
                        flex-direction: column;
                        width: 100%;
                    }
                    
                    .btn {
                        width: 100%;
                        justify-content: center;
                    }
                    
                    .api-keys-table {
                        display: block;
                        overflow-x: auto;
                    }
                    
                    .stats-cards {
                        grid-template-columns: 1fr;
                    }
                }
            </style>
        </head>
        <body>
            <div class="dashboard-container">
                <div class="header">
                    <div class="user-info">
                        <h1>👋 Selamat datang, ${firstName}!</h1>
                        <p>${email} | Role: User</p>
                    </div>
                    <div class="header-actions">
                        <a href="/api/docs" class="btn btn-primary">
                            <i class="fas fa-book"></i> API Documentation
                        </a>
                        <a href="/logout" class="btn btn-logout">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </a>
                    </div>
                </div>

                <div class="main-content">
                    <div class="sidebar">
                        <h2><i class="fas fa-bars"></i> Menu</h2>
                        <ul class="nav-menu">
                            <li><a href="#api-keys" class="active"><i class="fas fa-key"></i> API Keys</a></li>
                            <li><a href="#usage"><i class="fas fa-chart-bar"></i> Usage Analytics</a></li>
                            <li><a href="#billing"><i class="fas fa-credit-card"></i> Billing</a></li>
                            <li><a href="#settings"><i class="fas fa-cog"></i> Settings</a></li>
                            <li><a href="#support"><i class="fas fa-question-circle"></i> Support</a></li>
                        </ul>
                    </div>

                    <div class="content-area">
                        <div class="section-header">
                            <h2><i class="fas fa-key"></i> API Keys Management</h2>
                            <button class="btn btn-primary" onclick="showCreateForm()" style="background: #667eea; color: white;">
                                <i class="fas fa-plus"></i> Create New API Key
                            </button>
                        </div>

                        <div id="messageContainer"></div>

                        <div class="create-api-form" id="createForm" style="display: none;">
                            <form id="apiKeyForm">
                                <div class="form-row">
                                    <div class="form-group">
                                        <label for="apiName">API Key Name</label>
                                        <input type="text" id="apiName" name="apiName" 
                                               placeholder="e.g., Production API, Test Environment" required>
                                    </div>
                                </div>
                                <button type="submit" class="btn btn-primary" style="background: #667eea; color: white;">
                                    <i class="fas fa-key"></i> Generate API Key
                                </button>
                            </form>
                        </div>

                        <div class="stats-cards">
                            <div class="stat-card">
                                <i class="fas fa-key"></i>
                                <h3>${totalKeys}</h3>
                                <p>Total API Keys</p>
                            </div>
                            <div class="stat-card">
                                <i class="fas fa-check-circle"></i>
                                <h3>${activeKeys}</h3>
                                <p>Active Keys</p>
                            </div>
                            <div class="stat-card">
                                <i class="fas fa-clock"></i>
                                <h3>365</h3>
                                <p>Days Validity</p>
                            </div>
                        </div>

                        <div id="api-keys">
                            <h3 style="margin-bottom: 20px; color: var(--dark);">Your API Keys</h3>
                            <table class="api-keys-table">
                                <thead>
                                    <tr>
                                        <th>Name</th>
                                        <th>API Key</th>
                                        <th>Status</th>
                                        <th>Expires</th>
                                        <th>Created</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${apiKeyRows}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <script>
                function showCreateForm() {
                    const form = document.getElementById('createForm');
                    const isVisible = form.style.display === 'block';
                    form.style.display = isVisible ? 'none' : 'block';
                    
                    // Reset form dan pesan
                    document.getElementById('apiKeyForm').reset();
                    document.getElementById('messageContainer').innerHTML = '';
                }

                function copyKey(key) {
                    navigator.clipboard.writeText(key).then(() => {
                        showMessage('✅ API Key copied to clipboard!', 'success');
                    }).catch(err => {
                        console.error('Failed to copy:', err);
                        showMessage('❌ Failed to copy API Key', 'error');
                    });
                }

                function showMessage(message, type) {
                    const messageContainer = document.getElementById('messageContainer');
                    const messageClass = type === 'success' ? 'success-message' : 'error-message';
                    
                    messageContainer.innerHTML = \`
                        <div class="\${messageClass}" style="display: block;">
                            <i class="fas \${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
                            \${message}
                        </div>
                    \`;
                    
                    // Auto-hide setelah 5 detik
                    setTimeout(() => {
                        messageContainer.innerHTML = '';
                    }, 5000);
                }

                // Handle form submission dengan AJAX
                document.getElementById('apiKeyForm').addEventListener('submit', async function(e) {
                    e.preventDefault();
                    
                    const apiName = document.getElementById('apiName').value.trim();
                    
                    if (!apiName) {
                        showMessage('❌ Please enter API Key name', 'error');
                        return;
                    }
                    
                    // Show loading
                    const submitBtn = this.querySelector('button[type="submit"]');
                    const originalText = submitBtn.innerHTML;
                    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
                    submitBtn.disabled = true;
                    
                    try {
                        // Kirim request ke server
                        const response = await fetch('/user/generate-api-key', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                            },
                            body: new URLSearchParams({
                                apiName: apiName
                            })
                        });
                        
                        const result = await response.json();
                        
                        if (result.success) {
                            // Tampilkan API Key yang baru dibuat
                            showMessage(\`✅ API Key created successfully! Key: \${result.apiKey}\`, 'success');
                            
                            // Copy ke clipboard
                            navigator.clipboard.writeText(result.apiKey).then(() => {
                                console.log('API Key copied to clipboard');
                            });
                            
                            // Reset form
                            document.getElementById('apiKeyForm').reset();
                            
                            // Sembunyikan form setelah 2 detik
                            setTimeout(() => {
                                document.getElementById('createForm').style.display = 'none';
                                // Refresh halaman untuk menampilkan API Key baru
                                setTimeout(() => {
                                    location.reload();
                                }, 1000);
                            }, 2000);
                        } else {
                            showMessage(\`❌ Error: \${result.message}\`, 'error');
                        }
                    } catch (error) {
                        console.error('Error creating API Key:', error);
                        showMessage('❌ Failed to create API Key. Please try again.', 'error');
                    } finally {
                        // Restore button
                        submitBtn.innerHTML = originalText;
                        submitBtn.disabled = false;
                    }
                });

                // Cek jika ada error atau success message dari URL parameter
                const urlParams = new URLSearchParams(window.location.search);
                const message = urlParams.get('message');
                const messageType = urlParams.get('type');
                
                if (message) {
                    showMessage(decodeURIComponent(message), messageType || 'info');
                }
            </script>
        </body>
        </html>
    `;
}

// ============================================
// ADMIN DASHBOARD HTML
// ============================================
function getAdminDashboardHtml(adminEmail, users, apiKeys) {
    const userRows = users.map(u => `
        <tr>
            <td>${u.id}</td>
            <td>${u.first_name} ${u.last_name}</td>
            <td>${u.email}</td>
            <td><span class="role-badge role-${u.role}">${u.role}</span></td>
            <td><span class="status-badge status-${u.status}">${u.status}</span></td>
            <td>${u.created_at ? new Date(u.created_at).toLocaleString('id-ID') : 'N/A'}</td>
            <td class="action-cell">
                <a href="/admin/users/edit/${u.id}" class="action-btn edit-btn"><i class="fas fa-edit"></i> Edit</a>
                <form method="POST" action="/admin/users/delete/${u.id}" onsubmit="return confirm('Apakah Anda yakin ingin menghapus user ${u.first_name} ${u.last_name}?');" style="display: inline;">
                    <button type="submit" class="action-btn delete-btn"><i class="fas fa-trash"></i> Delete</button>
                </form>
            </td>
        </tr>
    `).join('') || '<tr><td colspan="7" style="text-align: center;">Tidak ada data user.</td></tr>';

    const apiKeyRows = apiKeys.map(k => {
        const status = checkKeyStatus(k.expiry_date);
        const statusClass = status === 'ON' ? 'status-on' : 'status-off';
        const expiryDate = k.expiry_date ? new Date(k.expiry_date).toLocaleDateString('id-ID') : 'N/A';
        
        return `
            <tr>
                <td>${k.id}</td>
                <td>${k.api_name}</td>
                <td><code class="api-key-value">${k.api_key.substring(0, 10)}...</code></td>
                <td><span class="${statusClass}">${status}</span></td>
                <td>${expiryDate}</td>
                <td>${k.first_name} ${k.last_name}<br><small>${k.email}</small></td>
                <td>${k.created_at ? new Date(k.created_at).toLocaleString('id-ID') : 'N/A'}</td>
                <td class="action-cell">
                    <form method="POST" action="/admin/api-keys/delete/${k.id}" onsubmit="return confirm('Hapus API Key ${k.api_name}?');">
                        <button type="submit" class="action-btn delete-btn"><i class="fas fa-trash"></i> Delete</button>
                    </form>
                </td>
            </tr>
        `;
    }).join('') || '<tr><td colspan="8" style="text-align: center;">Tidak ada data API Key.</td></tr>';

    return `
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <title>Admin Dashboard - API Platform</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                :root {
                    --primary: #6c63ff;
                    --primary-dark: #5a52d5;
                    --secondary: #ff6584;
                    --accent: #36d1dc;
                    --dark: #2c3e50;
                    --light: #f8f9fa;
                    --success: #2ecc71;
                    --warning: #f39c12;
                    --danger: #e74c3c;
                }

                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }

                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: #f5f5f5;
                    min-height: 100vh;
                }

                .dashboard-container {
                    max-width: 1400px;
                    margin: 0 auto;
                    padding: 20px;
                }

                .header {
                    background: linear-gradient(135deg, #2c3e50 0%, #4a69bd 100%);
                    color: white;
                    border-radius: 15px;
                    padding: 25px;
                    margin-bottom: 30px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
                }

                .header h1 {
                    font-size: 1.8rem;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }

                .user-info {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                }

                .btn {
                    padding: 10px 20px;
                    border-radius: 8px;
                    border: none;
                    cursor: pointer;
                    font-weight: 600;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    transition: all 0.3s;
                    text-decoration: none;
                    font-size: 0.95rem;
                }

                .btn-logout {
                    background: rgba(255,255,255,0.2);
                    color: white;
                    border: 1px solid rgba(255,255,255,0.3);
                }

                .btn-logout:hover {
                    background: rgba(255,255,255,0.3);
                    transform: translateY(-2px);
                }

                .stats-cards {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }

                .stat-card {
                    background: white;
                    border-radius: 12px;
                    padding: 25px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.05);
                    text-align: center;
                    transition: transform 0.3s;
                }

                .stat-card:hover {
                    transform: translateY(-5px);
                }

                .stat-card i {
                    font-size: 2.5rem;
                    margin-bottom: 15px;
                    color: var(--primary);
                }

                .stat-card h3 {
                    font-size: 2rem;
                    color: var(--dark);
                    margin-bottom: 10px;
                }

                .stat-card p {
                    color: #666;
                    font-size: 0.9rem;
                }

                .section-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin: 40px 0 20px;
                    padding-bottom: 10px;
                    border-bottom: 2px solid #eee;
                }

                .section-header h2 {
                    color: var(--dark);
                    font-size: 1.5rem;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }

                .table-container {
                    background: white;
                    border-radius: 12px;
                    padding: 25px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.05);
                    overflow-x: auto;
                    margin-bottom: 30px;
                }

                table {
                    width: 100%;
                    border-collapse: collapse;
                }

                th {
                    background: #f8f9fa;
                    color: var(--dark);
                    padding: 15px;
                    text-align: left;
                    font-weight: 600;
                    border-bottom: 2px solid #e0e0e0;
                }

                td {
                    padding: 15px;
                    border-bottom: 1px solid #eee;
                }

                tr:hover {
                    background: #f9f9f9;
                }

                .role-badge, .status-badge {
                    padding: 5px 10px;
                    border-radius: 20px;
                    font-size: 0.85rem;
                    font-weight: 600;
                    display: inline-block;
                }

                .role-admin {
                    background: rgba(108, 99, 255, 0.1);
                    color: var(--primary);
                }

                .role-user {
                    background: rgba(52, 152, 219, 0.1);
                    color: #3498db;
                }

                .status-active {
                    background: rgba(46, 204, 113, 0.1);
                    color: var(--success);
                }

                .status-inactive {
                    background: rgba(149, 165, 166, 0.1);
                    color: #95a5a6;
                }

                .status-suspended {
                    background: rgba(231, 76, 60, 0.1);
                    color: var(--danger);
                }

                .status-on, .status-off {
                    padding: 6px 12px;
                    border-radius: 20px;
                    font-size: 0.85rem;
                    font-weight: 600;
                    display: inline-block;
                }

                .status-on {
                    background: rgba(46, 204, 113, 0.1);
                    color: var(--success);
                }

                .status-off {
                    background: rgba(243, 156, 18, 0.1);
                    color: var(--warning);
                }

                .api-key-value {
                    background: #f8f9fa;
                    padding: 5px 10px;
                    border-radius: 6px;
                    font-family: 'Courier New', monospace;
                    font-size: 0.9rem;
                }

                .action-cell {
                    display: flex;
                    gap: 8px;
                }

                .action-btn {
                    padding: 8px 15px;
                    border-radius: 6px;
                    border: none;
                    cursor: pointer;
                    font-size: 0.9rem;
                    display: flex;
                    align-items: center;
                    gap: 5px;
                    transition: all 0.3s;
                }

                .edit-btn {
                    background: rgba(243, 156, 18, 0.1);
                    color: var(--warning);
                    border: 1px solid rgba(243, 156, 18, 0.2);
                }

                .edit-btn:hover {
                    background: var(--warning);
                    color: white;
                }

                .delete-btn {
                    background: rgba(231, 76, 60, 0.1);
                    color: var(--danger);
                    border: 1px solid rgba(231, 76, 60, 0.2);
                }

                .delete-btn:hover {
                    background: var(--danger);
                    color: white;
                }

                @media (max-width: 768px) {
                    .header {
                        flex-direction: column;
                        gap: 20px;
                        text-align: center;
                    }
                    
                    .user-info {
                        flex-direction: column;
                    }
                    
                    .stats-cards {
                        grid-template-columns: 1fr;
                    }
                    
                    .table-container {
                        padding: 15px;
                    }
                    
                    table {
                        font-size: 0.9rem;
                    }
                    
                    th, td {
                        padding: 10px;
                    }
                    
                    .action-cell {
                        flex-direction: column;
                        gap: 5px;
                    }
                }
            </style>
        </head>
        <body>
            <div class="dashboard-container">
                <div class="header">
                    <h1><i class="fas fa-tachometer-alt"></i> Admin Dashboard</h1>
                    <div class="user-info">
                        <span>Welcome, <strong>${adminEmail}</strong></span>
                        <a href="/logout" class="btn btn-logout">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </a>
                    </div>
                </div>

                <div class="stats-cards">
                    <div class="stat-card">
                        <i class="fas fa-users"></i>
                        <h3>${users.length}</h3>
                        <p>Total Users</p>
                    </div>
                    <div class="stat-card">
                        <i class="fas fa-key"></i>
                        <h3>${apiKeys.length}</h3>
                        <p>Total API Keys</p>
                    </div>
                    <div class="stat-card">
                        <i class="fas fa-user-shield"></i>
                        <h3>${users.filter(u => u.role === 'admin').length}</h3>
                        <p>Admin Users</p>
                    </div>
                    <div class="stat-card">
                        <i class="fas fa-check-circle"></i>
                        <h3>${users.filter(u => u.status === 'active').length}</h3>
                        <p>Active Users</p>
                    </div>
                </div>

                <div class="section-header">
                    <h2><i class="fas fa-users"></i> Users Management (${users.length})</h2>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${userRows}
                        </tbody>
                    </table>
                </div>

                <div class="section-header">
                    <h2><i class="fas fa-key"></i> API Keys Management (${apiKeys.length})</h2>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>API Key</th>
                                <th>Status</th>
                                <th>Expires</th>
                                <th>Owner</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${apiKeyRows}
                        </tbody>
                    </table>
                </div>
            </div>

            <script>
                function copyKey(key) {
                    navigator.clipboard.writeText(key).then(() => {
                        alert('✅ API Key copied to clipboard!');
                    }).catch(err => {
                        console.error('Failed to copy:', err);
                        alert('❌ Failed to copy API Key');
                    });
                }
            </script>
        </body>
        </html>
    `;
}

// ============================================
// EDIT USER FORM HTML
// ============================================
function getEditUserForm(user) {
    const content = `
        <h2><i class="fas fa-user-edit"></i> Edit User: ${user.first_name} ${user.last_name}</h2>
        <form method="POST" action="/admin/users/update/${user.id}">
            <div class="form-group">
                <label for="firstName">First Name</label>
                <input type="text" id="firstName" name="firstName" value="${user.first_name || ''}" required>
            </div>
            <div class="form-group">
                <label for="lastName">Last Name</label>
                <input type="text" id="lastName" name="lastName" value="${user.last_name || ''}" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" value="${user.email || ''}" required>
            </div>
            <div class="form-group">
                <label for="role">Role</label>
                <select id="role" name="role" required>
                    <option value="user" ${user.role === 'user' ? 'selected' : ''}>User</option>
                    <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
                </select>
            </div>
            <div class="form-group">
                <label for="status">Status</label>
                <select id="status" name="status" required>
                    <option value="active" ${user.status === 'active' ? 'selected' : ''}>Active</option>
                    <option value="inactive" ${user.status === 'inactive' ? 'selected' : ''}>Inactive</option>
                    <option value="suspended" ${user.status === 'suspended' ? 'selected' : ''}>Suspended</option>
                </select>
            </div>
            <button type="submit"><i class="fas fa-save"></i> Save Changes</button>
        </form>
        <div class="link-container">
            <a href="/admin/dashboard"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
        </div>
    `;
    return getBaseHtml('Edit User', content);
}

app.listen(port, () => {
    console.log(`🚀 Server berjalan di http://localhost:${port}`);
    console.log(`📊 Debug database: http://localhost:${port}/debug/database`);
    console.log(`👤 Admin login: http://localhost:${port}/admin/login`);
    console.log(`🔐 Default admin: admin@api.com / admin123`);
});