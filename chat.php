<?php

$envFile = dirname(__DIR__) . '/.env/.env';

if (!is_readable($envFile)) {
    http_response_code(500);
    die('Server misconfiguration.');
}

foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
    $line = trim($line);
    if ($line === '' || $line[0] === '#' || !str_contains($line, '=')) continue;
    [$k, $v] = explode('=', $line, 2);
    putenv(trim($k) . '=' . trim($v));
}
$pepper = getenv('APP_PEPPER');
if ($pepper === false || strlen($pepper) < 32) {
    http_response_code(500);
    die('Server misconfiguration.');
}
/* ================= Crypto (V2 ONLY) ================= */
function deriveKeyV2(string $salt) {
    $pepper = getenv('APP_PEPPER');
    $secret = $salt . "\n" . $pepper;
    return hash_pbkdf2('sha256', $secret, 'SecureTextTool:v2', 200000, 32, true);
}
function encryptTextV2(string $plainText, string $salt) {
    $key = deriveKeyV2($salt);
    $nonce = random_bytes(12);
    $tag = '';
    $aad = 'SecureTextTool:v2';
    $ct = openssl_encrypt($plainText, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, 16);
    return 'v2:' . base64_encode($nonce . $tag . $ct);
}
function decryptTextV2(string $cipherText, string $salt) {
    if (!str_starts_with($cipherText, 'v2:')) return false;
    $blob = base64_decode(substr($cipherText, 3), true);
    if ($blob === false || strlen($blob) < 29) return false;

    $key = deriveKeyV2($salt);
    return openssl_decrypt(
        substr($blob, 28),
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        substr($blob, 0, 12),
        substr($blob, 12, 16),
        'SecureTextTool:v2'
    );
}

/* ================= API MODE ================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax'])) {
    header('Content-Type: application/json');

    $text = trim($_POST['text'] ?? '');
    $salt = $_POST['salt'] ?? '';

    if ($salt === '') {
        echo json_encode(['ok' => false, 'error' => 'Salt is required.']);
        exit;
    }

    $cryptoText = str_starts_with($text, 'v2:') ? $text : 'v2:' . $text;
    $pt = decryptTextV2($cryptoText, $salt);
    $out = ($pt === false) ? encryptTextV2($text, $salt) : $pt;

    if (str_starts_with($out, 'v2:')) $out = substr($out, 3);
    echo json_encode(['ok' => true, 'result' => $out]);
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Secure Magic</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
:root {
  --bg: #ffffff;
  --fg: #000000;
  --box: #f4f4f4;
  --border: #ccc;
}

[data-theme="dark"] {
  --bg: #121212;
  --fg: #eaeaea;
  --box: #1e1e1e;
  --border: #333;
}

*{box-sizing:border-box}
body {
  font-family: Arial, sans-serif;
  background: var(--bg);
  color: var(--fg);
  padding:16px;
}
.container{max-width:900px;margin:auto}
label{font-weight:bold}
textarea,input,button{
  width:100%;padding:8px;margin-top:6px;
  background: var(--box);
  color: var(--fg);
  border:1px solid var(--border);
}
textarea{min-height:120px}
button{cursor:pointer}
.result{margin-top:20px;padding:12px;background:var(--box);border:1px solid var(--border)}
#resultText{white-space:pre-wrap;word-break:break-all}
.salt-wrapper{display:flex;gap:10px;align-items:center}
.salt-wrapper input{flex:1}
.salt-actions{display:flex;gap:8px}
.error{color:#d9534f;margin-top:10px}
.button-row{display:flex;gap:10px;flex-wrap:wrap}
.toggle{
  position:fixed;top:10px;right:10px;
  cursor:pointer;font-size:14px;
}
</style>

<script>
let saltTimer=null;

function toggleSalt(e){
  e.preventDefault();
  const i=document.getElementById('saltInput');
  const l=document.getElementById('toggleSalt');
  if(i.type==='password'){
    i.type='text';l.textContent='🙈 Hide';
    saltTimer=setTimeout(()=>{i.type='password';l.textContent='👁 Show';},5000);
  } else {i.type='password';l.textContent='👁 Show';}
}

function copySalt(e){
  e.preventDefault();
  navigator.clipboard.writeText(document.getElementById('saltInput').value);
}

function clearText(){
  text.value='';resultText.textContent='';error.textContent='';
}

function copyResult(){
  navigator.clipboard.writeText(resultText.textContent);
}

async function processForm(){
  const fd=new FormData();
  fd.append('ajax','1');
  fd.append('salt',saltInput.value);
  fd.append('text',text.value);

  const res=await fetch('',{method:'POST',body:fd});
  const data=await res.json();
  if(!data.ok){error.textContent=data.error;return;}
  error.textContent='';resultText.textContent=data.result;
}

/* 🌗 DARK MODE */
function toggleTheme(){
  const b=document.body;
  const t=b.dataset.theme==='dark'?'':'dark';
  b.dataset.theme=t;
  localStorage.setItem('theme',t);
}

window.onload=()=>{
  const t=localStorage.getItem('theme');
  if(t) document.body.dataset.theme=t;
};
</script>
</head>

<body>
<div class="toggle" onclick="toggleTheme()">🌗 Dark/White Mode</div>

<div class="container">
<h2>🔐 Secure Magic</h2>

<label>Salt</label>
<div class="salt-wrapper">
<input type="password" id="saltInput">
<div class="salt-actions">
  <a href="#" id="toggleSalt" onclick="toggleSalt(event)">👁 Show</a>
  <a href="#" onclick="copySalt(event)">📋 Copy</a>
</div>
</div>

<label>Message</label>
<textarea id="text"></textarea>

<div class="button-row">
  <button onclick="processForm()">DO THE MAGIC</button>
  <button onclick="clearText()">Clear</button>
</div>

<div class="error" id="error"></div>

<div class="result">
<strong>THE MAGIC</strong>
<div id="resultText"></div>
<button onclick="copyResult()">📋 COPY</button>
</div>

</div>
</body>
</html>












