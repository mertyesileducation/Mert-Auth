<?php
// TOTP ALGORİTMASI (RFC 6238)
function getTotpCode($secret) {
    // QR URI gelirse içindeki secret anahtarını çek
    if (strpos($secret, 'otpauth://') === 0) {
        $parsed = parse_url($secret);
        if (isset($parsed['query'])) {
            parse_str($parsed['query'], $query);
            if (isset($query['secret'])) {
                $secret = $query['secret'];
            }
        }
    }

    $base32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $secret));
    if (empty($base32)) return null;

    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $binary = '';
    for ($i = 0; $i < strlen($base32); $i++) {
        $val = strpos($alphabet, $base32[$i]);
        if ($val !== false) $binary .= sprintf('%05b', $val);
    }

    $secretBytes = '';
    for ($i = 0; $i + 8 <= strlen($binary); $i += 8) {
        $secretBytes .= chr(bindec(substr($binary, $i, 8)));
    }

    if (empty($secretBytes)) return null;

    $timeCounter = pack('J', floor(time() / 30));
    $hash = hash_hmac('sha1', $timeCounter, $secretBytes, true);
    $offset = ord($hash[strlen($hash) - 1]) & 0x0F;

    $otp = (
        ((ord($hash[$offset]) & 0x7F) << 24) |
        ((ord($hash[$offset + 1]) & 0xFF) << 16) |
        ((ord($hash[$offset + 2]) & 0xFF) << 8) |
        (ord($hash[$offset + 3]) & 0xFF)
    ) % 1000000;

    return str_pad((string)$otp, 6, '0', STR_PAD_LEFT);
}

$secret = $_POST['secret'] ?? $_GET['secret'] ?? '';
$label = $_POST['label'] ?? '';
$code = null;
$expiresIn = 30 - (time() % 30);
$activeTab = (!empty($secret) || $_SERVER['REQUEST_METHOD'] === 'POST') ? 'generator' : 'home';

if (!empty($secret)) {
    $code = getTotpCode($secret);
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mert Auth Mega - 2FA Manager</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0b0f19;
            --card-bg: rgba(22, 31, 48, 0.85);
            --card-border: rgba(255, 255, 255, 0.08);
            --primary: #38bdf8;
            --primary-glow: rgba(56, 189, 248, 0.25);
            --accent: #818cf8;
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
            --danger: #ef4444;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Plus Jakarta Sans', sans-serif;
        }

        body {
            background: var(--bg-dark);
            background-image: 
                radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.1) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(129, 140, 248, 0.1) 0px, transparent 50%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        header {
            background: rgba(15, 23, 42, 0.85);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--card-border);
            padding: 16px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 800;
            font-size: 20px;
            color: var(--primary);
            letter-spacing: -0.5px;
        }

        .brand-icon {
            width: 34px;
            height: 34px;
            background: linear-gradient(135deg, #0284c7, #6366f1);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            font-size: 16px;
            box-shadow: 0 0 12px var(--primary-glow);
        }

        .nav-tabs {
            display: flex;
            gap: 6px;
            background: rgba(255, 255, 255, 0.04);
            padding: 4px;
            border-radius: 12px;
            border: 1px solid var(--card-border);
        }

        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-sub);
            padding: 8px 18px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.2s;
        }

        .tab-btn.active {
            background: linear-gradient(135deg, #0284c7, #4f46e5);
            color: #fff;
            box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3);
        }

        main {
            flex: 1;
            max-width: 960px;
            width: 100%;
            margin: 0 auto;
            padding: 30px 20px;
        }

        .view-content {
            display: none;
        }

        .view-content.active {
            display: block;
        }

        .glass-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
            margin-bottom: 20px;
        }

        .hero {
            text-align: center;
            padding: 40px 20px;
        }

        .hero h1 {
            font-size: 34px;
            margin-bottom: 14px;
            background: linear-gradient(135deg, #fff 0%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .hero p {
            color: var(--text-sub);
            margin-bottom: 28px;
            line-height: 1.6;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }

        .cta-btn {
            background: linear-gradient(135deg, #0284c7, #4f46e5);
            color: #fff;
            padding: 12px 26px;
            border-radius: 10px;
            font-weight: 700;
            border: none;
            cursor: pointer;
            font-size: 15px;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 6px 20px var(--primary-glow);
        }

        .cta-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(56, 189, 248, 0.4);
        }

        .grid-features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 16px;
            margin-top: 30px;
        }

        .feature-box {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--card-border);
            padding: 20px;
            border-radius: 14px;
            text-align: left;
        }

        .feature-box h3 {
            font-size: 16px;
            color: var(--primary);
            margin-bottom: 8px;
        }

        .feature-box p {
            font-size: 13px;
            color: var(--text-sub);
            line-height: 1.5;
        }

        .form-group {
            margin-bottom: 18px;
            text-align: left;
        }

        .form-group label {
            display: block;
            font-size: 12px;
            color: var(--text-sub);
            margin-bottom: 6px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        input[type="text"] {
            width: 100%;
            padding: 12px 16px;
            background: #0f172a;
            border: 1px solid var(--card-border);
            color: #fff;
            border-radius: 10px;
            font-size: 14px;
            text-align: center;
            font-family: monospace;
            transition: border-color 0.2s;
        }

        input[type="text"]:focus {
            outline: none;
            border-color: var(--primary);
        }

        .code-display {
            background: #0f172a;
            border: 2px dashed var(--primary);
            border-radius: 16px;
            padding: 24px;
            margin-top: 20px;
            text-align: center;
            position: relative;
        }

        .code-number {
            font-family: 'JetBrains Mono', monospace;
            font-size: 46px;
            font-weight: 700;
            color: var(--primary);
            letter-spacing: 6px;
            margin: 8px 0;
            cursor: pointer;
            text-shadow: 0 0 15px var(--primary-glow);
        }

        .progress-bar-bg {
            width: 100%;
            height: 6px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
            margin-top: 14px;
            overflow: hidden;
        }

        .progress-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #38bdf8, #818cf8);
            width: 100%;
            transition: width 1s linear;
        }

        .saved-keys {
            margin-top: 20px;
        }

        .key-item {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }

        .key-item-info h4 {
            font-size: 14px;
            color: #fff;
        }

        .key-item-info p {
            font-size: 11px;
            color: var(--text-sub);
            font-family: monospace;
        }

        .btn-action {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid var(--card-border);
            color: #fff;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            font-weight: 600;
        }

        .btn-action:hover {
            background: var(--primary);
            color: #000;
        }

        .toast {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            background: #10b981;
            color: #fff;
            padding: 10px 22px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 14px;
            display: none;
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.3);
            z-index: 1000;
        }
    </style>
    <script>
        window.switchTab = function(tabName) {
            var homeView = document.getElementById('homeView');
            var generatorView = document.getElementById('generatorView');
            var btnHome = document.getElementById('btnHome');
            var btnGen = document.getElementById('btnGen');

            if (tabName === 'home') {
                if(homeView) homeView.classList.add('active');
                if(generatorView) generatorView.classList.remove('active');
                if(btnHome) btnHome.classList.add('active');
                if(btnGen) btnGen.classList.remove('active');
            } else {
                if(generatorView) generatorView.classList.add('active');
                if(homeView) homeView.classList.remove('active');
                if(btnGen) btnGen.classList.add('active');
                if(btnHome) btnHome.classList.remove('active');
            }
        };

        window.copyCode = function() {
            var codeEl = document.getElementById('codeText');
            if(!codeEl) return;
            var text = codeEl.innerText.replace(/\s/g, '');
            navigator.clipboard.writeText(text);
            
            var toast = document.getElementById('toast');
            if(toast) {
                toast.style.display = 'block';
                setTimeout(function(){ toast.style.display = 'none'; }, 2000);
            }
        };

        window.saveKey = function(secret) {
            var name = prompt("Bu anahtar için bir isim girin (ör. Gmail, Instagram):") || "Anahtar";
            var saved = JSON.parse(localStorage.getItem('merta_keys') || '[]');
            saved.push({ name: name, secret: secret });
            localStorage.setItem('merta_keys', JSON.stringify(saved));
            window.renderSavedKeys();
        };

        window.deleteKey = function(index) {
            var saved = JSON.parse(localStorage.getItem('merta_keys') || '[]');
            saved.splice(index, 1);
            localStorage.setItem('merta_keys', JSON.stringify(saved));
            window.renderSavedKeys();
        };

        window.useKey = function(secret) {
            var input = document.getElementById('secretInput');
            if(input) {
                input.value = secret;
                document.getElementById('totpForm').submit();
            }
        };

        window.renderSavedKeys = function() {
            var container = document.getElementById('savedKeysContainer');
            if(!container) return;
            var saved = JSON.parse(localStorage.getItem('merta_keys') || '[]');
            
            if(saved.length === 0) {
                container.innerHTML = '<p style="font-size: 12px; color: var(--text-sub); text-align: center;">Henüz kaydedilmiş bir anahtar yok.</p>';
                return;
            }

            var html = '';
            for(var i = 0; i < saved.length; i++) {
                html += '<div class="key-item">' +
                    '<div class="key-item-info"><h4>' + saved[i].name + '</h4><p>' + saved[i].secret.substring(0, 10) + '...</p></div>' +
                    '<div style="display:flex; gap:6px;">' +
                    '<button class="btn-action" onclick="window.useKey(\'' + saved[i].secret + '\')">Kod Üret</button>' +
                    '<button class="btn-action" style="color:#ef4444;" onclick="window.deleteKey(' + i + ')">Sil</button>' +
                    '</div></div>';
            }
            container.innerHTML = html;
        };

        document.addEventListener('DOMContentLoaded', function() {
            window.renderSavedKeys();
        });
    </script>
</head>
<body>

<header>
    <div class="brand">
        <div class="brand-icon">🔑</div>
        Mert Auth Mega
    </div>
    <nav class="nav-tabs">
        <button id="btnHome" class="tab-btn <?php echo $activeTab === 'home' ? 'active' : ''; ?>" onclick="window.switchTab('home')">Anasayfa</button>
        <button id="btnGen" class="tab-btn <?php echo $activeTab === 'generator' ? 'active' : ''; ?>" onclick="window.switchTab('generator')">Kod Al</button>
    </nav>
</header>

<main>
    <!-- ANASAYFA EKRANI -->
    <section id="homeView" class="view-content <?php echo $activeTab === 'home' ? 'active' : ''; ?>">
        <div class="glass-card hero">
            <h1>Güvenli ve Anlık TOTP Kod Üreteci</h1>
            <p>2FA doğrulamalarınız için Secret Key veya QR URI metninizi girin, 30 saniyelik canlı zaman senkronize kodlarınızı anında üretin.</p>
            <button class="cta-btn" onclick="window.switchTab('generator')">Kod Oluşturucuya Git →</button>

            <div class="grid-features">
                <div class="feature-box">
                    <h3>⚡ Standart RFC 6238</h3>
                    <p>Google Authenticator, Authy ve Microsoft Authenticator ile %100 uyumludur.</p>
                </div>
                <div class="feature-box">
                    <h3>💾 Yerel Kayıt Defteri</h3>
                    <p>Anahtarlarınızı sunucuya göndermeden tarayıcınızın hafızasında güvenle saklayabilirsiniz.</p>
                </div>
                <div class="feature-box">
                    <h3>🔒 Tam Gizlilik</h3>
                    <p>Secret key verileriniz veritabanına kaydedilmez, her şey anlık hesaplanır.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- KOD AL EKRANI -->
    <section id="generatorView" class="view-content <?php echo $activeTab === 'generator' ? 'active' : ''; ?>">
        <div style="max-width: 520px; margin: 0 auto;">
            <div class="glass-card" style="text-align: center;">
                <h2 style="margin-bottom: 18px; font-size: 20px;">2FA Kod Oluşturucu</h2>
                
                <form method="POST" action="" id="totpForm">
                    <div class="form-group">
                        <label>Secret Key veya QR URI Metni</label>
                        <input type="text" id="secretInput" name="secret" value="<?php echo htmlspecialchars($secret); ?>" placeholder="Örn: JBSWY3DPEHPK3PXP" required autocomplete="off">
                    </div>
                    <button type="submit" class="cta-btn" style="width: 100%; justify-content: center;">Giriş Kodunu Üret</button>
                </form>

                <?php if ($code): ?>
                    <div class="code-display">
                        <div style="font-size: 12px; color: var(--text-sub);">Kopyalamak için Koda Tıklayın</div>
                        <div class="code-number" id="codeText" onclick="window.copyCode()"><?php echo substr($code, 0, 3) . ' ' . substr($code, 3); ?></div>
                        <div style="font-size: 13px; color: var(--text-sub);">
                            Yenilenmeye Kalan Süre: <strong id="timerText" style="color: var(--primary);"><?php echo $expiresIn; ?></strong> sn
                        </div>
                        <div class="progress-bar-bg">
                            <div class="progress-bar-fill" id="progressFill"></div>
                        </div>
                    </div>

                    <div style="margin-top: 15px;">
                        <button class="btn-action" onclick="window.saveKey('<?php echo htmlspecialchars($secret); ?>')">⭐ Bu Anahtarı Kaydet</button>
                    </div>
                <?php elseif (!empty($secret)): ?>
                    <div style="margin-top: 18px; color: var(--danger); font-size: 13px;">
                        Geçersiz veya okunamayan Secret Key! Lütfen kontrol edin.
                    </div>
                <?php endif; ?>
            </div>

            <!-- KAYITLI ANAHTARLAR -->
            <div class="glass-card saved-keys">
                <h3 style="font-size: 15px; margin-bottom: 14px; color: var(--text-main);">Kayıtlı Anahtarlarım</h3>
                <div id="savedKeysContainer"></div>
            </div>
        </div>
    </section>
</main>

<div class="toast" id="toast">Kod Panoya Kopyalandı!</div>

<?php if ($code): ?>
<script>
    (function() {
        var expiresIn = <?php echo $expiresIn; ?>;
        var totalTime = 30;

        function updateTimer() {
            var timerEl = document.getElementById('timerText');
            var fillEl = document.getElementById('progressFill');

            if(timerEl) timerEl.innerText = expiresIn;
            if(fillEl) {
                var pct = (expiresIn / totalTime) * 100;
                fillEl.style.width = pct + '%';
            }

            if (expiresIn <= 0) {
                window.location.reload();
            }
            expiresIn--;
        }

        updateTimer();
        setInterval(updateTimer, 1000);
    })();
</script>
<?php endif; ?>

</body>
</html>
