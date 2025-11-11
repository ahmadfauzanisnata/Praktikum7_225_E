const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const crypto = require('crypto');

const app = express();
const port = 3000;

// Koneksi ke database MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'afi21092004',
    database: 'api_db',
    port: 3307
});

// Cek koneksi database
db.connect((err) => {
    if (err) {
        console.error('Koneksi database gagal:', err);
    } else {
        console.log('Terhubung ke database MySQL (api_db)');
    }
});

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Route halaman utama
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// ✅ Route untuk generate API key + validasi input
app.post('/generate-api-key', (req, res) => {
    const { apiName } = req.body;

    // Validasi tipe data & isi
    if (!apiName || typeof apiName !== 'string' || apiName.trim().length < 3) {
        return res.status(400).json({
            success: false,
            message: 'Nama API Key tidak valid. Minimal 3 karakter dan bertipe string.'
        });
    }

    const apiKey = generateApiKey();

    // Simpan ke tabel masuk_api
    const query = 'INSERT INTO masuk_api (api_name, api_key) VALUES (?, ?)';
    db.query(query, [apiName, apiKey], (err, result) => {
        if (err) {
            console.error('Gagal menyimpan API Key:', err);
            return res.status(500).json({
                success: false,
                message: 'Gagal menyimpan API Key ke database',
                error: err.sqlMessage
            });
        }

        res.status(201).json({
            success: true,
            apiName: apiName,
            apiKey: apiKey,
            insertedId: result.insertId,
            message: '✅ API Key berhasil dibuat dan disimpan ke database.'
        });
    });
});

// Fungsi generate API Key
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

// Route halaman tentang
app.get('/about', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Tentang Kami</title>
            <link rel="stylesheet" href="/css/style.css">
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="card-header">
                        <h1>Tentang Generator API Key</h1>
                    </div>
                    <div class="card-body">
                        <p>Aplikasi ini membantu Anda membuat API Key yang aman untuk integrasi dengan layanan kami.</p>
                        <a href="/">Kembali ke Generator</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
    `);
});

// Jalankan server
app.listen(port, () => {
    console.log(`Server berjalan di http://localhost:${port}`);
});

db.query('SELECT 1 + 1 AS result', (err, results) => {
    if (err) console.error('Tes koneksi gagal:', err);
    else console.log('Tes koneksi sukses:', results);
});
