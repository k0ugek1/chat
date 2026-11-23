<?php
declare(strict_types=1);
/*
 * REDLINE Messenger v3 — чат через ВАШ сервер (без WebRTC, PeerJS и внешних CDN).
 * Всё идёт обычным HTTPS на ваш домен, поэтому работает в любых сетях без VPN.
 *
 * Код комнаты — это и «адрес», и «пароль». Его можно придумать самому (например, "наша-база")
 * или получить случайный (например, "волк-луна-4821"). Из кода в браузере выводятся:
 *   • id комнаты (SHA-256) — сервер самого кода никогда не видит;
 *   • ключ шифрования AES-GCM (PBKDF2) — сервер хранит только шифртекст.
 * База данных не нужна: комнаты лежат в JSON-файлах в папке rl_data/.
 */

const DATA_DIR  = __DIR__ . '/rl_data';   // лучше вынести за пределы public_html
const MAX_MSGS  = 300;                    // сколько последних сообщений хранит комната
const ROOM_TTL  = 7 * 86400;              // комната удаляется после 7 дней тишины
const MAX_ROOMS = 2000;

/* ---- ЗВОНКИ (WebRTC) ----
 * Звонки работают только по HTTPS. STUN хватает не всегда (мобильные сети, строгие роутеры):
 * чтобы звонки шли в любых сетях, нужен TURN-сервер. Заполните один из вариантов:
 *   1) TURN_USER + TURN_PASS — постоянный логин/пароль (проще, но виден участникам комнат);
 *   2) TURN_SECRET — общий секрет coturn (static-auth-secret), логины будут временными.
 * Пример: const TURN_URLS = ['turn:turn.example.com:3478?transport=udp','turns:turn.example.com:5349?transport=tcp'];
 */
const STUN_URLS   = ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'];
const TURN_URLS   = [];
const TURN_USER   = '';
const TURN_PASS   = '';
const TURN_SECRET = '';

function jerr(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

function ensure_dir(): void {
    if (!is_dir(DATA_DIR)) {
        @mkdir(DATA_DIR, 0750, true);
        @file_put_contents(DATA_DIR . '/.htaccess',
            "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
        @file_put_contents(DATA_DIR . '/index.html', '');
    }
    if (!is_dir(DATA_DIR) || !is_writable(DATA_DIR)) jerr(500, 'data_dir_not_writable');
}

function room_ok(string $id): bool { return (bool)preg_match('/^([a-f0-9]{24}|p[a-f0-9]{2,200})$/', $id); }
function room_path(string $id): string { return DATA_DIR . '/' . $id . '.json'; }

/** Простое ограничение частоты по IP (защита от подбора кодов). */
function throttle(string $bucket, int $max, int $window): void {
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '0');
    $f  = DATA_DIR . '/' . $bucket . '_' . substr(hash('sha256', $ip), 0, 16) . '.rl';
    $fh = fopen($f, 'c+');
    if (!$fh) return;
    flock($fh, LOCK_EX);
    $d = json_decode((string)stream_get_contents($fh), true);
    $now = time();
    if (!is_array($d) || $now - (int)$d['t'] > $window) $d = ['t' => $now, 'n' => 0];
    $d['n']++;
    ftruncate($fh, 0); rewind($fh); fwrite($fh, json_encode($d)); fflush($fh);
    flock($fh, LOCK_UN); fclose($fh);
    if ($d['n'] > $max) jerr(429, 'rate');
}

/** Атомарно читает/изменяет комнату под блокировкой. */
function with_room(string $id, callable $fn, bool $create = false) {
    $p = room_path($id);
    if (!$create && !is_file($p)) return null;
    $fh = fopen($p, 'c+');
    if (!$fh) jerr(500, 'io');
    flock($fh, LOCK_EX);
    $raw  = stream_get_contents($fh);
    $room = $raw ? json_decode($raw, true) : null;
    if (!is_array($room)) {
        if (!$create) { flock($fh, LOCK_UN); fclose($fh); return null; }
        $room = ['created' => time(), 'seq' => 0, 'msgs' => [], 'members' => []];
    }
    $dirty = $create;
    $res = $fn($room, $dirty);
    if ($dirty) {
        ftruncate($fh, 0); rewind($fh);
        fwrite($fh, json_encode($room, JSON_UNESCAPED_UNICODE));
        fflush($fh);
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return $res;
}

function gc(): void {
    $now = time();
    foreach (glob(DATA_DIR . '/*.rl') ?: [] as $f) if ($now - (int)@filemtime($f) > 86400) @unlink($f);
    $files = glob(DATA_DIR . '/*.json') ?: [];
    foreach ($files as $f) if ($now - (int)@filemtime($f) > ROOM_TTL) @unlink($f);
    if (count($files) > MAX_ROOMS) jerr(503, 'busy');
}

function api(): void {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') jerr(405, 'method');
    $in = json_decode((string)file_get_contents('php://input'), true);
    if (!is_array($in)) jerr(400, 'bad_json');
    ensure_dir();
    $a  = (string)($_GET['a'] ?? '');

    if ($a === 'ice') {
        throttle('i', 300, 3600);
        $ice = [['urls' => STUN_URLS]];
        if (TURN_URLS) {
            if (TURN_SECRET !== '') {
                $u = (time() + 86400) . ':rl';
                $ice[] = ['urls' => TURN_URLS, 'username' => $u, 'credential' => base64_encode(hash_hmac('sha1', $u, TURN_SECRET, true))];
            } elseif (TURN_USER !== '') {
                $ice[] = ['urls' => TURN_URLS, 'username' => TURN_USER, 'credential' => TURN_PASS];
            }
        }
        echo json_encode(['ice' => $ice, 'relay' => count($ice) > 1]);
        return;
    }

    $id = (string)($in['room'] ?? '');
    if (!room_ok($id)) jerr(400, 'bad_room');

    if ($a === 'create') {
        throttle('c', 30, 3600);
        if (random_int(1, 20) === 1) gc();
        $existed = false;
        with_room($id, function (array &$r, bool &$d) use (&$existed) {
            $existed = count($r['members']) > 0;
            $d = true;
        }, true);
        echo json_encode(['room' => $id, 'existed' => $existed]);
        return;
    }

    $me = (string)($in['me'] ?? '');
    if (!preg_match('/^[A-Za-z0-9_-]{16,64}$/', $me)) jerr(400, 'bad_token');
    $h = substr(hash('sha256', $me), 0, 10);

    if ($a === 'poll') {
        $after = max(0, (int)($in['after'] ?? 0));
        $name  = (isset($in['name']) && is_string($in['name'])) ? substr($in['name'], 0, 300) : null;
        $sigAfter = isset($in['sigAfter']) ? (int)$in['sigAfter'] : null;
        $res = with_room($id, function (array &$room, bool &$dirty) use ($h, $after, $name, $sigAfter) {
            $now = time();
            if (!isset($room['members'][$h])) {
                if (count($room['members']) >= 20) return ['err' => 403];
                $room['members'][$h] = ['name' => $name ?? '', 'seen' => 0];
                $dirty = true;
            }
            $m = &$room['members'][$h];
            if ($name !== null && $m['name'] !== $name) { $m['name'] = $name; $dirty = true; }
            if ($now - $m['seen'] >= 4) { $m['seen'] = $now; $dirty = true; }
            unset($m);
            $msgs = [];
            foreach ($room['msgs'] as $x) if ($x['seq'] > $after) $msgs[] = $x;
            $members = [];
            foreach ($room['members'] as $k => $v)
                $members[] = ['id' => $k, 'name' => $v['name'], 'online' => ($now - $v['seen']) <= 20];
            $sigs = [];
            if ($sigAfter !== null) {
                foreach (($room['sigs'] ?? []) as $sg) {
                    if ($sg['id'] > $sigAfter && $sg['from'] !== $h && ($sg['to'] === null || $sg['to'] === $h) && $now - $sg['ts'] <= 90) $sigs[] = $sg;
                }
            }
            return ['msgs' => $msgs, 'members' => $members, 'you' => $h, 'seq' => $room['seq'], 'sigs' => $sigs, 'sid' => $room['sid'] ?? 0, 'now' => $now];
        });
        if ($res === null) { throttle('f', 40, 600); jerr(404, 'room_not_found'); }
        if (isset($res['err'])) jerr($res['err'], 'full');
        echo json_encode($res, JSON_UNESCAPED_UNICODE);
        return;
    }

    if ($a === 'sig') {
        $d  = $in['d'] ?? null;
        $to = $in['to'] ?? null;
        if (!is_string($d) || $d === '' || strlen($d) > 16000) jerr(400, 'bad_signal');
        if ($to !== null && (!is_string($to) || !preg_match('/^[a-f0-9]{10}$/', $to))) jerr(400, 'bad_to');
        $res = with_room($id, function (array &$room, bool &$dirty) use ($h, $d, $to) {
            if (!isset($room['members'][$h])) return ['err' => 403];
            $now = time();
            $room['sid'] = ($room['sid'] ?? 0) + 1;
            $sigs = [];
            foreach (($room['sigs'] ?? []) as $sg) if ($now - $sg['ts'] <= 90) $sigs[] = $sg;
            $sigs[] = ['id' => $room['sid'], 'from' => $h, 'to' => $to, 'd' => $d, 'ts' => $now];
            $room['sigs'] = array_slice($sigs, -40);
            $dirty = true;
            return ['ok' => true];
        });
        if ($res === null) jerr(404, 'room_not_found');
        if (isset($res['err'])) jerr($res['err'], 'denied');
        echo json_encode($res);
        return;
    }

    if ($a === 'send') {
        $t = $in['t'] ?? null;
        if (!is_string($t) || $t === '' || strlen($t) > 16000) jerr(400, 'bad_message');
        $res = with_room($id, function (array &$room, bool &$dirty) use ($h, $t) {
            if (!isset($room['members'][$h])) return ['err' => 403];
            $nowMs = (int)(microtime(true) * 1000);
            $recent = 0;
            foreach ($room['msgs'] as $x) if ($x['u'] === $h && $x['ts'] > $nowMs - 10000) $recent++;
            if ($recent >= 25) return ['err' => 429];
            $room['seq']++;
            $msg = ['seq' => $room['seq'], 'u' => $h, 't' => $t, 'ts' => $nowMs];
            $room['msgs'][] = $msg;
            if (count($room['msgs']) > MAX_MSGS) $room['msgs'] = array_slice($room['msgs'], -MAX_MSGS);
            $room['members'][$h]['seen'] = time();
            $dirty = true;
            return ['msg' => $msg];
        });
        if ($res === null) jerr(404, 'room_not_found');
        if (isset($res['err'])) jerr($res['err'], 'denied');
        echo json_encode($res, JSON_UNESCAPED_UNICODE);
        return;
    }

    jerr(404, 'unknown_action');
}

if (isset($_GET['a'])) { api(); exit; }

header("Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; media-src 'self' blob: data:; base-uri 'none'; form-action 'none'");
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-cache');
?><!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
<meta name="theme-color" content="#0b1119">
<meta name="referrer" content="no-referrer">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<title>REDLINE Messenger</title>
<style>
:root{color-scheme:dark;--bg:#0b1119;--panel:#111a24;--panel2:#172230;--border:#263446;--text:#e8eef6;--muted:#8c9bad;--blue:#4b8df8;--blue2:#3377e8;--green:#39c98a;--red:#e05d70;--amber:#e5a83b;--sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{height:100%;overflow:hidden}
body{margin:0;position:fixed;inset:0;width:100%;background:var(--bg);color:var(--text);font:15px/1.4 Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;overscroll-behavior:none;-webkit-text-size-adjust:100%}
button,input,textarea{font:inherit;color:inherit}button{cursor:pointer;touch-action:manipulation}
.app{position:absolute;left:0;right:0;top:0;height:var(--vh,100%);display:flex;will-change:transform}

/* ---------- home / sidebar ---------- */
.sidebar{width:350px;flex-shrink:0;background:var(--panel);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow-y:auto;padding-top:var(--sat)}
.sidehead{padding:24px 20px 6px}
.brand{font-size:26px;font-weight:800;letter-spacing:1.5px}.brand span{color:var(--blue)}
.tagline{font-size:11px;letter-spacing:1.2px;color:var(--muted);margin-top:4px}
.sidebarbody{padding:14px 20px 20px;display:grid;gap:14px}
.card{padding:14px;background:var(--panel2);border:1px solid var(--border);border-radius:16px;display:grid;gap:10px}
.fieldlabel{color:var(--muted);font-size:12px;letter-spacing:.5px}
.field{width:100%;height:48px;background:#0d141d;border:1px solid var(--border);border-radius:12px;padding:0 14px;outline:none;font-size:16px}
.field:focus{border-color:var(--blue)}
.row{display:flex;gap:8px}.row .field{flex:1;min-width:0}
.iconbtn{width:48px;height:48px;flex-shrink:0;border-radius:12px;border:1px solid #35475f;background:#243246;font-size:20px}
.iconbtn:active{background:#2e405a}
.hint{font-size:12px;color:var(--muted);line-height:1.5}
.btn{width:100%;height:50px;border:0;border-radius:14px;background:var(--blue);color:#fff;font-weight:650;font-size:16px}
.btn:active{background:var(--blue2);transform:scale(.99)}
.btn:disabled{opacity:.5}
.btn.secondary{background:#243246;border:1px solid #35475f}
.btn.ghost{background:transparent;border:1px solid #45658f;color:#bcd6ff;height:44px;font-size:14px}
.btn.danger{background:transparent;border:1px solid #5a3039;color:#f0a0ac;height:44px;font-size:14px}
.btns{display:grid;gap:10px}
.btns.two{grid-template-columns:1fr 1fr}
.roombox{display:none;gap:10px;padding:14px;border:1px solid #34527b;background:#132238;border-radius:16px}
.roomcode{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:22px;font-weight:700;color:#a9cbff;word-break:break-all;user-select:all;-webkit-user-select:all}
.status{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px}
.dot{width:9px;height:9px;border-radius:50%;background:#687789;flex-shrink:0}
.dot.on{background:var(--green);box-shadow:0 0 8px #39c98a66}.dot.warn{background:var(--amber)}
.lock{font-size:12px;line-height:1.5}.lock.ok{color:var(--green)}.lock.bad{color:var(--amber)}
.notice{font-size:13px;color:#b7c5d6;line-height:1.5}.notice:empty{display:none}
.sidebarfoot{margin-top:auto;padding:15px 20px calc(15px + var(--sab));border-top:1px solid var(--border);font-size:11px;color:var(--muted)}

/* ---------- chat ---------- */
.main{flex:1;min-width:0;display:flex;flex-direction:column;background:#0e151e;position:relative}
.chathead{flex-shrink:0;min-height:64px;padding:var(--sat) 10px 0 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;background:#111a24}
.mobiletoggle{display:none;width:40px;height:44px;margin-left:-8px;background:none;border:0;font-size:30px;line-height:1;color:var(--blue)}
.avatar{width:42px;height:42px;flex-shrink:0;border-radius:50%;display:grid;place-items:center;background:linear-gradient(140deg,#3b83ed,#7857d5);font-weight:700;font-size:17px}
.headtext{min-width:0;flex:1}.headtext strong{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:16px}
.headtext small{color:var(--muted);display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.headbtn{width:44px;height:44px;flex-shrink:0;border:0;border-radius:50%;background:transparent;font-size:20px}
.headbtn:active{background:#1c2a3a}
.offline{display:none;background:#3a2d12;color:#f2c76b;font-size:13px;text-align:center;padding:6px 10px}
.chatwrap{flex:1;min-height:0;position:relative;display:flex;flex-direction:column}
.chatarea{flex:1;overflow-y:auto;-webkit-overflow-scrolling:touch;overscroll-behavior:contain;padding:16px;display:flex;flex-direction:column;gap:4px;background:radial-gradient(ellipse at 25% 10%,#172230 0,transparent 50%)}
.welcome{margin:auto;text-align:center;max-width:320px;color:var(--muted);line-height:1.6;padding:20px}.welcome .bigicon{font-size:44px;margin-bottom:10px}
.bubble{max-width:min(78%,620px);padding:8px 12px 6px;border:1px solid #293747;background:#192430;border-radius:18px 18px 18px 5px;overflow-wrap:anywhere;white-space:pre-wrap;margin-top:6px;align-self:flex-start;font-size:16px;line-height:1.4}
.bubble.cont{margin-top:0;border-top-left-radius:5px}
.bubble.mine{align-self:flex-end;background:#244b7b;border-color:#315e91;border-radius:18px 18px 5px 18px}
.bubble.mine.cont{border-top-right-radius:5px}
.bubble .who{font-size:12px;color:#7fb0ff;margin-bottom:2px;font-weight:600}
.bubble .meta{font-size:10px;color:#a5b6c8;text-align:right;margin-top:3px;opacity:.85}
.sys{align-self:center;font-size:12px;color:var(--muted);background:#142030;border-radius:99px;padding:4px 12px;margin:10px 0 4px}
.fab{position:absolute;right:14px;bottom:12px;width:44px;height:44px;border-radius:50%;border:1px solid #35475f;background:#1c2a3b;font-size:18px;display:none;box-shadow:0 4px 14px #0008}
.fab b{position:absolute;top:-6px;right:-4px;min-width:20px;height:20px;border-radius:10px;background:var(--blue);color:#fff;font-size:11px;display:none;place-items:center;padding:0 5px}
.composer{flex-shrink:0;border-top:1px solid var(--border);background:var(--panel);padding:10px 12px calc(10px + var(--sab));display:flex;gap:8px;align-items:flex-end}
.composer textarea{flex:1;min-width:0;border:1px solid var(--border);background:#0d141d;border-radius:22px;padding:11px 16px;outline:none;font-size:16px;line-height:1.35;resize:none;max-height:130px;height:44px;display:block}
.composer textarea:focus{border-color:var(--blue)}
.send{width:44px;height:44px;flex-shrink:0;border:0;border-radius:50%;background:var(--blue);color:#fff;font-size:18px}
.send:disabled,.composer textarea:disabled{opacity:.45}
.hidekb{display:none;width:40px;height:44px;flex-shrink:0;border:0;border-radius:50%;background:transparent;color:var(--muted);font-size:22px}
body.kb .hidekb{display:block}
body.kb .composer{padding-bottom:10px}

.callui{position:fixed;left:0;right:0;top:0;height:var(--vh,100%);z-index:50;display:none;flex-direction:column;background:radial-gradient(ellipse at 50% 20%,#16253a 0,#070c12 70%);padding-top:var(--sat)}
.callui.on{display:flex}
.callstage{flex:1;min-height:0;position:relative;display:flex;align-items:center;justify-content:center}
#remoteVideo{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;background:#000;display:none}
#localVideo{position:absolute;right:14px;top:14px;width:96px;height:132px;object-fit:cover;border-radius:14px;border:1px solid #35475f;background:#000;display:none;z-index:2;transform:scaleX(-1)}
.callinfo{position:relative;z-index:1;text-align:center;text-shadow:0 1px 8px #000a;padding:0 20px}
.bigav{width:112px;height:112px;border-radius:50%;margin:0 auto 16px;display:grid;place-items:center;background:linear-gradient(140deg,#3b83ed,#7857d5);font-size:46px;font-weight:700}
.callui.hasvideo .bigav{display:none}
.callui.hasvideo .callinfo{position:absolute;left:0;right:0;top:calc(var(--sat) + 14px)}
.callname{font-size:24px;font-weight:700}
.callstate{color:#b7c5d6;margin-top:6px;font-variant-numeric:tabular-nums}
.callbar{flex-shrink:0;display:flex;justify-content:center;gap:22px;padding:16px 18px calc(26px + var(--sab));position:relative;z-index:2}
.cbtn{width:66px;height:66px;border-radius:50%;border:0;font-size:26px;background:#243246;color:#fff}
.cbtn.off{background:#fff;color:#111}
.cbtn.end{background:#e0455a}.cbtn.acc{background:#2fb872}
.cbtn:active{transform:scale(.94)}
@media(max-width:720px){
 .sidebar{width:100%;border-right:0}
 .main{display:none}
 body.chat-open .sidebar{display:none}
 body.chat-open .main{display:flex;width:100%}
 .mobiletoggle{display:block}
 .chatarea{padding:12px 10px}
 .bubble{max-width:86%}
 .sidebarbody{padding-top:18px}
}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="sidehead"><div class="brand">RED<span>LINE</span></div><div class="tagline">PRIVATE ENCRYPTED MESSENGER</div></div>
    <div class="sidebarbody">
      <div class="card">
        <label class="fieldlabel" for="nickname">ТВОЙ НИКНЕЙМ</label>
        <input id="nickname" class="field" maxlength="24" placeholder="Например, CART3R" autocomplete="nickname" enterkeyhint="next">
      </div>

      <div class="card" id="connectCard">
        <label class="fieldlabel" for="codeInput">КОД КОМНАТЫ</label>
        <div class="row">
          <input id="codeInput" class="field" placeholder="свой или 🎲 случайный" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" enterkeyhint="go">
          <button id="diceBtn" class="iconbtn" type="button" aria-label="Случайный код">🎲</button>
        </div>
        <div class="hint">Придумай любой код (от 4 символов) и скажи его другу. Чем длиннее и необычнее — тем безопаснее.</div>
        <div class="btns two">
          <button id="createBtn" class="btn">Создать</button>
          <button id="joinBtn" class="btn secondary">Войти</button>
        </div>
      </div>

      <div id="roomBox" class="roombox">
        <button id="openChatBtn" class="btn">Вернуться в чат</button>
        <div class="fieldlabel">ТЕКУЩАЯ КОМНАТА</div>
        <div id="roomCode" class="roomcode"></div>
        <div class="btns two">
          <button id="copyCodeBtn" class="btn ghost">Скопировать код</button>
          <button id="shareBtn" class="btn ghost">Пригласить</button>
        </div>
        <button id="leaveBtn" class="btn danger">Выйти из комнаты</button>
      </div>

      <div id="status" class="status"><span id="statusDot" class="dot"></span><span id="statusText">Не подключено</span></div>
      <div id="lockInfo" class="lock"></div>
      <div id="notice" class="notice" aria-live="polite"></div>
    </div>
    <div class="sidebarfoot">REDLINE · без аккаунтов · без базы данных<br>Трафик идёт только на этот сайт по HTTPS.</div>
  </aside>

  <main class="main">
    <header class="chathead">
      <button class="mobiletoggle" id="backBtn" aria-label="Назад">‹</button>
      <div class="avatar" id="peerAvatar">R</div>
      <div class="headtext"><strong id="peerName">REDLINE CHAT</strong><small id="peerState">Создай комнату или подключись к другу</small></div>
      <button class="headbtn" id="callBtn" aria-label="Позвонить" style="display:none">📞</button>
      <button class="headbtn" id="videoBtn" aria-label="Видеозвонок" style="display:none">🎥</button>
      <button class="headbtn" id="headShare" aria-label="Пригласить" style="display:none">⤴</button>
    </header>
    <div class="offline" id="offline">Нет связи с сервером — пытаюсь переподключиться…</div>
    <div class="chatwrap">
      <section class="chatarea" id="chatArea"><div class="welcome" id="welcome"><div class="bigicon">◈</div><strong>Приватный чат</strong><br>Создай комнату и отправь код другу<br>или введи его код слева.</div></section>
      <button class="fab" id="fab" aria-label="Вниз">↓<b id="fabCount"></b></button>
    </div>
    <form class="composer" id="messageForm">
      <button type="button" class="hidekb" id="hideKb" aria-label="Скрыть клавиатуру">⌄</button>
      <textarea id="messageInput" rows="1" placeholder="Сначала подключись к комнате…" maxlength="4000" disabled autocomplete="off" enterkeyhint="send"></textarea>
      <button class="send" id="sendBtn" disabled aria-label="Отправить">➤</button>
    </form>
  </main>
</div>
<div class="callui" id="callUI">
  <div class="callstage">
    <video id="remoteVideo" autoplay playsinline muted></video>
    <video id="localVideo" autoplay playsinline muted></video>
    <div class="callinfo"><div class="bigav" id="callAv">R</div><div class="callname" id="callName"></div><div class="callstate" id="callState"></div></div>
  </div>
  <audio id="remoteAudio" autoplay playsinline></audio>
  <div class="callbar" id="callBar"></div>
</div>
<script>
(() => {
  const $ = id => document.getElementById(id);
  const nickname=$('nickname'), codeInput=$('codeInput'), createBtn=$('createBtn'), joinBtn=$('joinBtn'), leaveBtn=$('leaveBtn');
  const roomBox=$('roomBox'), roomCodeEl=$('roomCode'), statusText=$('statusText'), statusDot=$('statusDot'), notice=$('notice'), lockInfo=$('lockInfo');
  const chatArea=$('chatArea'), messageInput=$('messageInput'), messageForm=$('messageForm'), sendBtn=$('sendBtn'), fab=$('fab'), fabCount=$('fabCount'), offline=$('offline');

  const store = {
    get(k){ try{ return localStorage.getItem(k); }catch(e){ return null; } },
    set(k,v){ try{ localStorage.setItem(k,v); }catch(e){} },
    del(k){ try{ localStorage.removeItem(k); }catch(e){} }
  };
  const hasCrypto = !!(window.crypto && crypto.subtle);
  const isTouch = matchMedia('(pointer:coarse)').matches;

  let session=null;   // {code}
  let roomId='', aesKey=null;
  let token=store.get('rl_token');
  if(!token || !/^[A-Za-z0-9_-]{16,64}$/.test(token)){ token=rand(16); store.set('rl_token',token); }
  let after=0, you='', pollTimer=null, fails=0, nameSent=false, pollGen=0, unread=0, missed=0;
  let lastSender=null, lastDay='';
  let call=null, sigAfter=null, peers=[], iceCfg=null, ringT=null;
  const seen=new Set(), nameCache=new Map();

  // ---------- utils ----------
  function rand(n){ const b=crypto.getRandomValues(new Uint8Array(n)); return Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''); }
  const hex=u8=>Array.from(u8,b=>b.toString(16).padStart(2,'0')).join('');
  const b64u={
    enc(buf){ let s=''; const a=new Uint8Array(buf); for(let i=0;i<a.length;i+=8192) s+=String.fromCharCode.apply(null,a.subarray(i,i+8192)); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); },
    dec(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='='; return Uint8Array.from(atob(s),c=>c.charCodeAt(0)); }
  };
  function setStatus(text,state){ statusText.textContent=text; statusDot.className='dot'+(state?' '+state:''); $('peerState').textContent=text; }
  function say(t){ notice.textContent=t; }
  function getName(){ const n=nickname.value.trim(); if(!n){ nickname.focus(); say('Сначала введи никнейм.'); return null; } store.set('rl_name',n.slice(0,24)); return n.slice(0,24); }
  const myName=()=>(nickname.value.trim()||store.get('rl_name')||'Друг').slice(0,24);

  async function api(action, body){
    const ctl=new AbortController(); const to=setTimeout(()=>ctl.abort(),10000);   // iOS может «подвесить» запрос после сворачивания
    try{
      const r = await fetch(location.pathname+'?a='+action, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{}),cache:'no-store',signal:ctl.signal});
      let j=null; try{ j=await r.json(); }catch(e){}
      if(!r.ok){ const e=new Error((j&&j.error)||('http_'+r.status)); e.status=r.status; throw e; }
      return j;
    } finally { clearTimeout(to); }
  }

  // ---------- room code ----------
  const WORDS=['волк','лиса','кот','дуб','река','луна','мост','снег','ветер','огонь','море','гора','лес','тигр','сокол','заря','камень','звезда','пламя','туман','гром','лед','песок','трава','берег','остров','ключ','щит','маяк','север','юг','восток','закат','рассвет','холм','озеро','тропа','стрела','факел','комета'];
  function pick(){ return WORDS[crypto.getRandomValues(new Uint32Array(1))[0]%WORDS.length]; }
  function genCode(){ const n=1000+crypto.getRandomValues(new Uint32Array(1))[0]%9000; return pick()+'-'+pick()+'-'+n; }
  function normCode(s){ s=(s||'').trim(); if(s.includes('#')){ try{ s=decodeURIComponent(s.split('#').pop()); }catch(e){ s=s.split('#').pop(); } } return s.toLowerCase().replace(/\s+/g,'-').replace(/[^\p{L}\p{N}_-]/gu,'').slice(0,40); }

  async function derive(code){
    const te=new TextEncoder();
    if(!hasCrypto) return {id:'p'+hex(te.encode(code)),key:null};
    const id=hex(new Uint8Array(await crypto.subtle.digest('SHA-256',te.encode('redline-id:'+code))).slice(0,12));
    const base=await crypto.subtle.importKey('raw',te.encode(code),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:te.encode('redline-key-v2'),iterations:150000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
    return {id,key};
  }

  // ---------- encryption ----------
  async function enc(s){
    if(!aesKey) return 'p:'+s;
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},aesKey,new TextEncoder().encode(s)));
    const out=new Uint8Array(12+ct.length); out.set(iv); out.set(ct,12);
    return 'e:'+b64u.enc(out);
  }
  async function dec(s){
    try{
      if(s.startsWith('p:')) return s.slice(2);
      if(s.startsWith('e:') && aesKey){
        const b=b64u.dec(s.slice(2));
        return new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:b.slice(0,12)},aesKey,b.slice(12)));
      }
    }catch(e){}
    return '🔒 не удалось расшифровать';
  }
  async function decName(blob){ if(!blob) return 'Друг'; if(!nameCache.has(blob)) nameCache.set(blob,(await dec(blob)).slice(0,24)||'Друг'); return nameCache.get(blob); }
  function updateLockInfo(){
    if(!session){ lockInfo.textContent=''; lockInfo.className='lock'; return; }
    const short=session.code.length<8;
    if(aesKey){ lockInfo.textContent='🔒 Сквозное шифрование включено'+(short?' · код короткий, лучше длиннее':''); lockInfo.className='lock '+(short?'bad':'ok'); }
    else { lockInfo.textContent='⚠ Без шифрования: нужен HTTPS.'; lockInfo.className='lock bad'; }
  }

  // ---------- UI ----------
  function setHeader(name){ $('peerName').textContent=name; $('peerAvatar').textContent=(name||'R').charAt(0).toUpperCase(); }
  function clearWelcome(){ const w=$('welcome'); if(w) w.remove(); }
  const nearBottom=()=>chatArea.scrollHeight-chatArea.scrollTop-chatArea.clientHeight<120;
  function scrollDown(smooth){ chatArea.scrollTo({top:chatArea.scrollHeight,behavior:smooth?'smooth':'auto'}); missed=0; fabCount.style.display='none'; fab.style.display='none'; }
  function sysMsg(t){ clearWelcome(); const d=document.createElement('div'); d.className='sys'; d.textContent=t; chatArea.appendChild(d); lastSender=null; }
  function dayLabel(d){ const t=new Date(); const y=new Date(Date.now()-864e5); if(d.toDateString()===t.toDateString()) return 'Сегодня'; if(d.toDateString()===y.toDateString()) return 'Вчера'; return d.toLocaleDateString([], {day:'numeric',month:'long'}); }
  function addMessage(text,name,mine,ts,senderId){
    clearWelcome();
    const wasNear=nearBottom(); const d=new Date(ts||Date.now());
    if(d.toDateString()!==lastDay){ lastDay=d.toDateString(); sysMsg(dayLabel(d)); }
    const cont=lastSender===senderId; lastSender=senderId;
    const b=document.createElement('div'); b.className='bubble'+(mine?' mine':'')+(cont?' cont':'');
    if(!mine && !cont){ const w=document.createElement('div'); w.className='who'; w.textContent=name; b.appendChild(w); }
    const c=document.createElement('div'); c.textContent=text; b.appendChild(c);
    const m=document.createElement('div'); m.className='meta'; m.textContent=d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}); b.appendChild(m);
    chatArea.appendChild(b);
    if(mine||wasNear) scrollDown(false);
    else { missed++; fab.style.display='block'; fabCount.textContent=missed; fabCount.style.display='grid'; }
  }
  function enableComposer(on){ messageInput.disabled=!on; sendBtn.disabled=!on; messageInput.placeholder=on?'Сообщение':'Нет связи…'; }
  function autosize(){ messageInput.style.height='44px'; messageInput.style.height=Math.min(messageInput.scrollHeight,130)+'px'; }

  async function refreshMembers(list){
    const ms=[]; for(const m of list) ms.push({id:m.id,online:m.online,name:await decName(m.name)});
    const others=ms.filter(m=>m.id!==you), online=others.filter(m=>m.online); peers=others;
    if(online.length){ setHeader(online.map(m=>m.name).join(', ')); setStatus('в сети','on'); }
    else if(others.length){ setHeader(others.map(m=>m.name).join(', ')); setStatus('не в сети','warn'); }
    else { setHeader('Ожидание друга'); setStatus('Комната готова · ждём друга','warn'); }
  }

  // ---------- notifications ----------
  let actx=null;
  function beep(){ try{ actx=actx||new (window.AudioContext||window.webkitAudioContext)(); const o=actx.createOscillator(),g=actx.createGain(); o.connect(g);g.connect(actx.destination);o.frequency.value=880;g.gain.setValueAtTime(.06,actx.currentTime);g.gain.exponentialRampToValueAtTime(.0001,actx.currentTime+.25);o.start();o.stop(actx.currentTime+.25);}catch(e){} }
  function updateTitle(){ document.title=(unread?'('+unread+') ':'')+'REDLINE Messenger'; }
  function wake(){ if(!session) return; pollGen++; fails=0; schedulePoll(0); }   // перезапуск опроса после сворачивания
  document.addEventListener('visibilitychange',()=>{ if(!document.hidden){ unread=0; updateTitle(); wake(); fit(); } });
  window.addEventListener('pageshow',wake); window.addEventListener('online',wake); window.addEventListener('focus',wake);

  // ---------- polling ----------
  function schedulePoll(ms){ clearTimeout(pollTimer); if(!session) return; const gen=pollGen; pollTimer=setTimeout(()=>poll(gen),ms); }
  async function poll(gen){
    if(!session || gen!==pollGen) return;
    try{
      const body={room:roomId,me:token,after}; if(sigAfter!==null) body.sigAfter=sigAfter;
      if(!nameSent) body.name=await enc(myName());
      const j=await api('poll',body);
      if(gen!==pollGen) return;
      nameSent=true; you=j.you;
      if(fails>0){ offline.style.display='none'; }
      fails=0; enableComposer(true);
      await refreshMembers(j.members);
      if(sigAfter===null) sigAfter=j.sid||0;
      else for(const sg of (j.sigs||[])){ if(sg.id>sigAfter) sigAfter=sg.id; onSignal(sg,j.now); }
      for(const m of j.msgs){
        if(m.seq>after) after=m.seq;
        if(seen.has(m.seq)) continue; seen.add(m.seq);
        const mine=m.u===you;
        const name=mine?'Вы':await decName((j.members.find(x=>x.id===m.u)||{}).name);
        addMessage(await dec(m.t),name,mine,m.ts,m.u);
        if(!mine && document.hidden){ unread++; updateTitle(); beep(); if(navigator.vibrate) navigator.vibrate(60); }
      }
      schedulePoll(call?600:(document.hidden?5000:1500));
    }catch(e){
      if(gen!==pollGen) return;
      if(e.status===404){ say('Комната не найдена или удалена за неактивность. Проверь код.'); leave(true); return; }
      if(e.status===403){ say('В комнате нет места.'); leave(true); return; }
      if(e.status===429){ say('Слишком много попыток, подожди пару минут.'); }
      fails++; enableComposer(false); offline.style.display='block'; setStatus('Нет связи…','warn');
      schedulePoll(Math.min(1500*Math.pow(2,fails),15000));
    }
  }

  // ---------- room lifecycle ----------
  async function enter(code,created){
    pollGen++; clearTimeout(pollTimer);
    const d=await derive(code);
    session={code}; roomId=d.id; aesKey=d.key;
    store.set('rl_session',JSON.stringify(session));
    after=0; seen.clear(); nameCache.clear(); nameSent=false; fails=0; you=''; lastSender=null; lastDay=''; missed=0; sigAfter=null; peers=[];
    chatArea.innerHTML='';
    roomCodeEl.textContent=code; roomBox.style.display='grid'; leaveBtn.style.display='block';
    $('connectCard').style.display='none'; ['headShare','callBtn','videoBtn'].forEach(i=>$(i).style.display='block');
    document.body.classList.add('chat-open');
    updateLockInfo(); setHeader('Подключение…'); setStatus('Подключение…','warn');
    say(created?'Комната создана. Отправь код другу: '+code:'');
    sysMsg(aesKey?'🔒 Сквозное шифрование':'⚠ Шифрование выключено');
    schedulePoll(0);
  }
  async function createRoom(){
    if(!getName()) return;
    let code=normCode(codeInput.value);
    if(!codeInput.value.trim()){ code=genCode(); codeInput.value=code; }
    if(code.length<4){ say('Код слишком короткий — минимум 4 символа.'); codeInput.focus(); return; }
    createBtn.disabled=true; joinBtn.disabled=true; say('Создаю…');
    try{
      const d=await derive(code);
      const j=await api('create',{room:d.id});
      if(j.existed){ say('Такой код уже занят. Выбери другой — или нажми «Войти», если комната ваша.'); }
      else await enter(code,true);
    }catch(e){ say(e.message==='data_dir_not_writable'?'Сервер: нет прав на запись в папку rl_data/.':e.status===429?'Слишком много попыток, подожди немного.':'Не удалось создать комнату: '+e.message); }
    createBtn.disabled=false; joinBtn.disabled=false;
  }
  async function joinRoom(){
    if(!getName()) return;
    const code=normCode(codeInput.value);
    if(code.length<4){ say('Введи код комнаты друга (от 4 символов).'); codeInput.focus(); return; }
    say('Подключаюсь…');
    await enter(code,false);
  }
  function leave(silent){
    if(call) endCall('Звонок завершён',true);
    pollGen++; clearTimeout(pollTimer); session=null; aesKey=null; roomId=''; store.del('rl_session');
    enableComposer(false); messageInput.placeholder='Сначала подключись к комнате…'; offline.style.display='none';
    roomBox.style.display='none'; leaveBtn.style.display='none'; ['headShare','callBtn','videoBtn'].forEach(i=>$(i).style.display='none'); $('connectCard').style.display='grid';
    document.body.classList.remove('chat-open'); setHeader('REDLINE CHAT'); setStatus('Не подключено','');
    updateLockInfo(); if(!silent) say('Вы вышли из комнаты.');
    chatArea.innerHTML='<div class="welcome" id="welcome"><div class="bigicon">◈</div><strong>Приватный чат</strong><br>Создай комнату и отправь код другу<br>или введи его код слева.</div>';
  }

  async function sendMessage(){
    if(!session) return; const text=messageInput.value.trim(); if(!text) return;
    messageInput.value=''; autosize();
    try{
      const j=await api('send',{room:roomId,me:token,t:await enc(text)});
      const m=j.msg; if(m.seq>after) after=m.seq;
      if(!seen.has(m.seq)){ seen.add(m.seq); addMessage(text,'Вы',true,m.ts,you||'me'); }
    }catch(e){
      messageInput.value=text; autosize();
      say(e.status===429?'Слишком быстро, подожди секунду.':'Не удалось отправить. Проверь связь.');
    }
    messageInput.focus();
  }

  async function share(){
    if(!session) return;
    const url=location.origin+location.pathname+'#'+encodeURIComponent(session.code);
    const text='Заходи в чат REDLINE. Код комнаты: '+session.code;
    try{ if(navigator.share){ await navigator.share({title:'REDLINE',text:text+'\n'+url}); return; } }catch(e){ if(e&&e.name==='AbortError') return; }
    copy(text+'\n'+url,'Приглашение скопировано');
  }
  async function copy(t,ok){ try{ await navigator.clipboard.writeText(t); say(ok||'Скопировано'); }catch(e){ say('Не удалось скопировать. Выдели код вручную.'); } }

  // ---------- звонки (WebRTC, сигнализация через сервер) ----------
  const callUI=$('callUI'), remoteAudio=$('remoteAudio'), remoteVideo=$('remoteVideo'), localVideo=$('localVideo');
  const canCall=()=>!!(window.isSecureContext && navigator.mediaDevices && navigator.mediaDevices.getUserMedia && window.RTCPeerConnection);
  const fmtDur=ms=>{ const t=Math.floor(ms/1000); return String(Math.floor(t/60)).padStart(2,'0')+':'+String(t%60).padStart(2,'0'); };

  async function getIce(){
    if(!iceCfg){ try{ iceCfg=(await api('ice',{})).ice; }catch(e){ iceCfg=[{urls:['stun:stun.l.google.com:19302']}]; } }
    return iceCfg;
  }
  async function sendSig(to,msg){ try{ await api('sig',{room:roomId,me:token,to,d:await enc(JSON.stringify(msg))}); }catch(e){} }
  function mediaError(e){
    const n=e&&e.name;
    if(n==='NotAllowedError'||n==='SecurityError') return 'Нет доступа к микрофону/камере. Разреши доступ в настройках браузера.';
    if(n==='NotFoundError') return 'Микрофон или камера не найдены.';
    return 'Не удалось включить микрофон: '+(e&&e.message||n||'ошибка');
  }
  function setCallStatus(t){ if(call && call.state!=='active') $('callState').textContent=t; }
  function renderBar(){
    const bar=$('callBar'); bar.innerHTML=''; if(!call) return;
    const mk=(cls,ico,label,fn)=>{ const b=document.createElement('button'); b.className='cbtn '+cls; b.textContent=ico; b.setAttribute('aria-label',label); b.addEventListener('click',fn); bar.appendChild(b); };
    if(call.state==='ringing'){ mk('end','✕','Отклонить',()=>endCall('Звонок отклонён',true)); mk('acc','✆','Принять',acceptCall); return; }
    mk(call.muted?'off':'',call.muted?'🔇':'🎤','Микрофон',()=>{ call.muted=!call.muted; call.stream&&call.stream.getAudioTracks().forEach(t=>t.enabled=!call.muted); renderBar(); });
    if(call.video) mk(call.camOff?'off':'',call.camOff?'🚫':'📷','Камера',()=>{ call.camOff=!call.camOff; call.stream&&call.stream.getVideoTracks().forEach(t=>t.enabled=!call.camOff); renderBar(); });
    mk('end','✕','Завершить',()=>endCall('Звонок завершён',true));
  }
  function showCallUI(name,status){
    hideKeyboard();
    $('callName').textContent=name; $('callAv').textContent=(name||'R').charAt(0).toUpperCase(); $('callState').textContent=status;
    callUI.classList.remove('hasvideo'); callUI.classList.add('on'); renderBar();
  }
  function startRing(){ stopRing(); const r=()=>{ beep(); setTimeout(beep,300); if(navigator.vibrate) navigator.vibrate([300,150,300]); }; r(); ringT=setInterval(r,2200); }
  function stopRing(){ clearInterval(ringT); ringT=null; }

  async function prepareMedia(allowAudioOnlyFallback){
    const audio={echoCancellation:true,noiseSuppression:true,autoGainControl:true};
    const video=call.video?{facingMode:'user',width:{ideal:640},height:{ideal:480}}:false;
    try{ call.stream=await navigator.mediaDevices.getUserMedia({audio,video}); }
    catch(e){
      if(call.video && allowAudioOnlyFallback){ call.video=false; call.stream=await navigator.mediaDevices.getUserMedia({audio,video:false}); }
      else throw e;
    }
    if(call.video && call.stream.getVideoTracks().length){ localVideo.srcObject=new MediaStream(call.stream.getVideoTracks()); localVideo.style.display='block'; }
    try{ if(navigator.wakeLock) call.wl=await navigator.wakeLock.request('screen'); }catch(e){}
  }
  async function makePC(){
    const c=call;
    const pc=new RTCPeerConnection({iceServers:await getIce(),bundlePolicy:'max-bundle'});
    c.pc=pc;
    c.stream.getTracks().forEach(t=>pc.addTrack(t,c.stream));
    pc.ontrack=e=>{
      const st=(e.streams&&e.streams[0])||new MediaStream([e.track]);
      remoteAudio.srcObject=st; remoteAudio.play().catch(()=>{});
      if(e.track.kind==='video'){ remoteVideo.srcObject=st; remoteVideo.muted=true; remoteVideo.style.display='block'; callUI.classList.add('hasvideo'); }
    };
    pc.onconnectionstatechange=()=>{
      if(call!==c) return; const st=pc.connectionState;
      if(st==='connected'){ clearTimeout(c.dc); onConnected(); }
      else if(st==='failed') endCall('Не удалось соединиться. Сетям мешает прямое соединение — нужен TURN-сервер (настройка в начале index.php).',true);
      else if(st==='disconnected'){ clearTimeout(c.dc); c.dc=setTimeout(()=>{ if(call===c && pc.connectionState!=='connected') endCall('Связь потеряна',true); },8000); }
    };
    return pc;
  }
  function waitIce(pc){
    return new Promise(res=>{
      if(pc.iceGatheringState==='complete') return res();
      const t=setTimeout(done,4000);
      function chk(){ if(pc.iceGatheringState==='complete') done(); }
      function done(){ clearTimeout(t); pc.removeEventListener('icegatheringstatechange',chk); res(); }
      pc.addEventListener('icegatheringstatechange',chk);
    });
  }
  function onConnected(){
    if(!call || call.state==='active') return;
    clearTimeout(call.timeout); call.state='active'; call.startedAt=Date.now();
    $('callState').textContent='00:00';
    call.tick=setInterval(()=>{ if(call) $('callState').textContent=fmtDur(Date.now()-call.startedAt); },1000);
    remoteAudio.play().catch(()=>{}); renderBar();
  }

  async function startCall(video){
    if(call) return;
    if(!session) return;
    if(!canCall()){ say('Звонки работают только по HTTPS (и в современном браузере). Включите HTTPS на сайте.'); return; }
    const online=peers.filter(p=>p.online);
    if(!online.length){ say('Друг сейчас не в сети — позвонить некому.'); return; }
    const peer=online[0];
    const c=call={id:rand(8),peer:peer.id,role:'caller',video:!!video,state:'calling',pc:null,stream:null,muted:false,camOff:false};
    showCallUI(peer.name,'Включаю микрофон…');
    try{ await prepareMedia(false); }catch(e){ endCall(mediaError(e),false); return; }
    if(call!==c) return;
    try{
      const pc=await makePC();
      await pc.setLocalDescription(await pc.createOffer());
      await waitIce(pc);
      if(call!==c) return;
      await sendSig(peer.id,{t:'offer',cid:c.id,sdp:pc.localDescription.sdp,video:c.video});
      setCallStatus('Вызываем…'); c.timeout=setTimeout(()=>endCall('Нет ответа',true),45000);
    }catch(e){ endCall('Не удалось начать звонок: '+(e.message||e),true); }
  }
  function startIncoming(from,m){
    const p=peers.find(x=>x.id===from)||{name:'Друг'};
    const c=call={id:m.cid,peer:from,role:'callee',video:!!m.video,offer:m.sdp,state:'ringing',pc:null,stream:null,muted:false,camOff:false};
    showCallUI(p.name,m.video?'Входящий видеозвонок':'Входящий звонок');
    startRing(); if(document.hidden) document.title='📞 Входящий звонок';
    c.timeout=setTimeout(()=>endCall('Пропущенный звонок',false),45000);
  }
  async function acceptCall(){
    const c=call; if(!c || c.state!=='ringing') return;
    stopRing(); clearTimeout(c.timeout); c.state='connecting'; $('callState').textContent='Соединяем…'; renderBar();
    c.timeout=setTimeout(()=>{ if(call===c && c.state!=='active') endCall('Не удалось соединиться',true); },30000);
    try{ await prepareMedia(true); }catch(e){ await sendSig(c.peer,{t:'reject',cid:c.id}); endCall(mediaError(e),false); return; }
    if(call!==c) return;
    try{
      const pc=await makePC();
      await pc.setRemoteDescription({type:'offer',sdp:c.offer});
      await pc.setLocalDescription(await pc.createAnswer());
      await waitIce(pc);
      if(call!==c) return;
      await sendSig(c.peer,{t:'answer',cid:c.id,sdp:pc.localDescription.sdp});
    }catch(e){ endCall('Не удалось принять звонок: '+(e.message||e),true); }
  }
  async function onSignal(sg,serverNow){
    let m; try{ m=JSON.parse(await dec(sg.d)); }catch(e){ return; }
    if(!m||!m.t) return;
    if(m.t==='offer'){
      if(serverNow-sg.ts>40) return;                         // устаревший вызов
      if(call){ if(call.id!==m.cid) sendSig(sg.from,{t:'busy',cid:m.cid}); return; }
      startIncoming(sg.from,m); return;
    }
    if(!call || m.cid!==call.id) return;
    if(m.t==='answer' && call.role==='caller' && call.pc && call.pc.signalingState==='have-local-offer'){
      clearTimeout(call.timeout); call.state='connecting'; $('callState').textContent='Соединяем…';
      call.timeout=setTimeout(()=>{ if(call && call.state!=='active') endCall('Не удалось соединиться',true); },30000);
      try{ await call.pc.setRemoteDescription({type:'answer',sdp:m.sdp}); }catch(e){ endCall('Ошибка соединения',true); }
    } else if(m.t==='busy') endCall('Собеседник занят',false);
    else if(m.t==='reject') endCall('Звонок отклонён',false);
    else if(m.t==='hangup') endCall(call.state==='ringing'?'Пропущенный звонок':'Собеседник завершил звонок',false);
  }
  function endCall(reason,notify){
    const c=call; if(!c) return; call=null;
    clearTimeout(c.timeout); clearTimeout(c.dc); clearInterval(c.tick); stopRing();
    if(notify) sendSig(c.peer,{t:(c.role==='callee'&&c.state==='ringing')?'reject':'hangup',cid:c.id});
    try{ c.pc&&c.pc.close(); }catch(e){}
    if(c.stream) c.stream.getTracks().forEach(t=>t.stop());
    try{ c.wl&&c.wl.release(); }catch(e){}
    remoteAudio.srcObject=null; remoteVideo.srcObject=null; localVideo.srcObject=null;
    remoteVideo.style.display='none'; localVideo.style.display='none';
    callUI.classList.remove('on','hasvideo'); $('callBar').innerHTML='';
    const dur=c.startedAt?' · '+fmtDur(Date.now()-c.startedAt):'';
    if(session){ sysMsg('📞 '+reason+dur); chatArea.scrollTop=chatArea.scrollHeight; }
    say(reason); updateTitle();
  }
  $('callBtn').addEventListener('click',()=>startCall(false));
  $('videoBtn').addEventListener('click',()=>startCall(true));
  window.addEventListener('pagehide',()=>{ if(call) endCall('Звонок завершён',true); });

  // ---------- viewport / keyboard (iOS Safari) ----------
  const appEl=document.querySelector('.app'), vv=window.visualViewport;
  function fit(){
    const h=vv?vv.height:window.innerHeight;
    document.documentElement.style.setProperty('--vh',h+'px');
    appEl.style.transform=vv&&vv.offsetTop?'translateY('+vv.offsetTop+'px)':'';
    if(window.scrollY) window.scrollTo(0,0);
    if(session && nearBottom()) chatArea.scrollTop=chatArea.scrollHeight;
  }
  if(vv){ vv.addEventListener('resize',fit); vv.addEventListener('scroll',fit); }
  window.addEventListener('resize',fit); window.addEventListener('orientationchange',()=>setTimeout(fit,250)); window.addEventListener('scroll',()=>{ if(window.scrollY) window.scrollTo(0,0); });
  fit();
  const hideKeyboard=()=>{ if(document.activeElement && document.activeElement!==document.body) document.activeElement.blur(); };
  messageInput.addEventListener('focus',()=>{ if(isTouch) document.body.classList.add('kb'); setTimeout(fit,50); setTimeout(fit,300); });
  messageInput.addEventListener('blur',()=>{ document.body.classList.remove('kb'); setTimeout(fit,50); setTimeout(fit,300); });
  $('hideKb').addEventListener('pointerdown',e=>e.preventDefault());
  $('hideKb').addEventListener('click',hideKeyboard);
  chatArea.addEventListener('click',()=>{ if(isTouch) hideKeyboard(); });                 // тап по переписке закрывает клавиатуру
  chatArea.addEventListener('touchmove',()=>{ if(document.activeElement===messageInput) hideKeyboard(); },{passive:true});  // как и прокрутка
  $('openChatBtn').addEventListener('click',()=>document.body.classList.add('chat-open'));

  // ---------- events ----------
  $('diceBtn').addEventListener('click',()=>{ codeInput.value=genCode(); });
  createBtn.addEventListener('click',createRoom);
  joinBtn.addEventListener('click',joinRoom);
  leaveBtn.addEventListener('click',()=>leave(false));
  codeInput.addEventListener('keydown',e=>{ if(e.key==='Enter'){ e.preventDefault(); codeInput.value.trim()?joinRoom():createRoom(); } });
  nickname.addEventListener('keydown',e=>{ if(e.key==='Enter'){ e.preventDefault(); codeInput.focus(); } });
  messageForm.addEventListener('submit',e=>{ e.preventDefault(); sendMessage(); });
  sendBtn.addEventListener('pointerdown',e=>e.preventDefault());   // не закрывать клавиатуру
  messageInput.addEventListener('input',autosize);
  messageInput.addEventListener('keydown',e=>{ if(e.key==='Enter' && !e.shiftKey && !isTouch){ e.preventDefault(); sendMessage(); } });
  $('backBtn').addEventListener('click',()=>{ hideKeyboard(); document.body.classList.remove('chat-open'); });
  $('copyCodeBtn').addEventListener('click',()=>session&&copy(session.code,'Код скопирован'));
  $('shareBtn').addEventListener('click',share);
  $('headShare').addEventListener('click',share);
  fab.addEventListener('click',()=>scrollDown(true));
  chatArea.addEventListener('scroll',()=>{ if(nearBottom()){ missed=0; fab.style.display='none'; fabCount.style.display='none'; } else fab.style.display='block'; },{passive:true});

  // ---------- boot ----------
  nickname.value=store.get('rl_name')||'';
  if(!hasCrypto) say('Страница открыта без HTTPS — шифрование недоступно. Включите HTTPS на сайте.');
  const fromHash=location.hash.length>1?normCode(location.hash):'';
  if(fromHash.length>=4){
    codeInput.value=fromHash; history.replaceState(null,'',location.pathname);
    if(nickname.value) joinRoom(); else { say('Введи никнейм и нажми «Войти».'); nickname.focus(); }
  } else {
    try{ const s=JSON.parse(store.get('rl_session')||'null'); if(s&&s.code) enter(s.code,false); }catch(e){}
  }
})();
</script>
</body>
</html>
