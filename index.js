const express = require('express');
const path = require('path');
const app = express();
const port = 3000;

// Middleware untuk menyajikan file statis (CSS, JS, images)
app.use(express.static(path.join(__dirname, 'public')));

// Middleware untuk parsing form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Route untuk halaman utama
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// Route API untuk membuat API Key (POST request)
app.post('/generate-api-key', (req, res) => {
    const { apiName } = req.body;
    
    // Validasi input
    if (!apiName) {
        return res.status(400).json({ 
            success: false, 
            message: 'Nama API Key harus diisi' 
        });
    }
    
    // Generate API Key
    const apiKey = generateApiKey();
    
    // Simpan ke database (di sini kita simpan dalam memory untuk contoh)
    // Dalam aplikasi nyata, simpan ke database dengan hash
    
    res.json({
        success: true,
        apiKey: apiKey,
        apiName: apiName,
        message: 'API Key berhasil dibuat'
    });
});

// Fungsi untuk generate API Key
function generateApiKey() {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let apiKey = '';
    const segments = [8, 4, 4, 4, 12];
    
    segments.forEach((segmentLength, index) => {
        for (let i = 0; i < segmentLength; i++) {
            apiKey += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        if (index < segments.length - 1) {
            apiKey += '-';
        }
    });
    
    return apiKey;
}

// Route untuk halaman about
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

app.listen(port, () => {
    console.log(`Server berjalan di http://localhost:${port}`);
});