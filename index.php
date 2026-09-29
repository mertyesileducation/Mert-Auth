<?php
// TOTP ALGORİTMASI (RFC 6238)
function getTotpCode($secret) {
    // QR URİ gelirse temizle
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
$code = null;
$expiresIn = 30 - (time() % 30);

if (!empty($secret)) {
    $code = getTotpCode($secret);
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mert Auth Mega</title>
    <style>
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: #0f172a;
            color: #f8fafc;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }
        .box {
            background: #1e293b;
            border: 1px solid #334155;
            padding: 30px;
            border-radius: 16px;
            width: 100%;
            max-width: 400px;
            text-align: center;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
        }
        h1 {
            font-size: 24px;
            margin-bottom: 20px;
            color: #38bdf8;
        }
        input[type="text"] {
            width: 100%;
            padding: 12px;
            background: #0f172a;
            border: 1px solid #334155;
            color: #fff;
            border-radius: 8px;
            font-size: 15px;
            box-sizing: border-box;
            margin-bottom: 12px;
            text-align: center;
            font-family: monospace;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #38bdf8;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #0284c7;
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: bold;
            cursor: pointer;
        }
        button:hover {
            background: #0369a1;
        }
        .result {
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #334155;
        }
        .code {
            font-size: 42px;
            font-weight: bold;
            color: #38bdf8;
            letter-spacing: 6px;
            margin: 10px 0;
            cursor: pointer;
            font-family: monospace;
        }
        .timer {
            font-size: 13px;
            color: #94a3b8;
        }
        .toast {
            position: fixed;
            bottom: 20px;
            background: #22c55e;
            color: #fff;
            padding: 10px 20px;
            border-radius: 8px;
            display: none;
            font-weight: bold;
        }
    </style>
</head>
<body>

<div class="box">
    <h1>Mert Auth Mega</h1>
    
    <form method="POST">
        <input type="text" name="secret" value="<?php echo htmlspecialchars($secret); ?>" placeholder="Secret Key girin..." required autocomplete="off">
        <button type="submit">Giriş Kodunu Üret</button>
    </form>

    <?php if ($code): ?>
        <div class="result">
            <div style="font-size: 12px; color: #94a3b8;">Giriş Kodunuz (Tıkla Kopyala):</div>
            <div class="code" id="codeText" onclick="copyCode()"><?php echo substr($code, 0, 3) . ' ' . substr($code, 3); ?></div>
            <div class="timer">Kalan Süre: <strong id="timer"><?php echo $expiresIn; ?></strong> sn</div>
        </div>
    <?php elseif (!empty($secret)): ?>
        <div class="result" style="color: #ef4444;">Geçersiz Secret Key!</div>
    <?php endif; ?>
</div>

<div class="toast" id="toast">Kod Kopyalandı!</div>

<script>
    function copyCode() {
        const text = document.getElementById('codeText').innerText.replace(/\s/g, '');
        navigator.clipboard.writeText(text);
        const toast = document.getElementById('toast');
        toast.style.display = 'block';
        setTimeout(() => toast.style.display = 'none', 2000);
    }

    <?php if ($code): ?>
    let timeLeft = <?php echo $expiresIn; ?>;
    setInterval(() => {
        timeLeft--;
        if (timeLeft <= 0) {
            window.location.reload();
        } else {
            document.getElementById('timer').innerText = timeLeft;
        }
    }, 1000);
    <?php endif; ?>
</script>

</body>
</html>
