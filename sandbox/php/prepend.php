<?php
/**
 * evalhook callback. Logs every eval() payload.
 * SANDBOX_MODE=dump  -> do not execute the eval'd code
 * SANDBOX_MODE=observe -> execute after logging
 *
 * SANDBOX_PROFILE selects a request shape:
 *   default | googlebot | google-referrer | wp-cookie
 */
function __evilbox_apply_profile()
{
    $profile = getenv('SANDBOX_PROFILE') ?: 'default';
    if (empty($_SERVER['REQUEST_METHOD'])) {
        $_SERVER['REQUEST_METHOD'] = 'GET';
    }
    if (empty($_SERVER['HTTP_HOST'])) {
        $_SERVER['HTTP_HOST'] = 'localhost';
    }
    if (empty($_SERVER['REMOTE_ADDR'])) {
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }
    if ($profile === 'googlebot') {
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
        $_SERVER['HTTP_REFERER'] = '';
    } elseif ($profile === 'google-referrer') {
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
        $_SERVER['HTTP_REFERER'] = 'https://www.google.com/';
    } elseif ($profile === 'wp-cookie') {
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
        $_COOKIE['wordpress_logged_in_sandbox'] = 'admin|0|0|sandbox';
        $_COOKIE['wordpress_test_cookie'] = 'WP Cookie check';
    } else {
        if (empty($_SERVER['HTTP_USER_AGENT'])) {
            $_SERVER['HTTP_USER_AGENT'] = 'EvilboxSandbox/1.0';
        }
    }
}

__evilbox_apply_profile();
require_once __DIR__ . '/wp-stubs.php';

function __eval($code, $file)
{
    $dir = '/logs/php';
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    static $n = 0;
    $n++;
    $dump = sprintf('%s/eval-%04d.php', $dir, $n);
    @file_put_contents($dump, $code);
    $header = sprintf("--- eval #%d @ %s ---\n", $n, $file);
    @file_put_contents($dir . '/eval.log', $header . $code . "\n\n", FILE_APPEND);
    $mode = 'dump';
    $modeFile = '/logs/mode';
    if (is_file($modeFile)) {
        $mode = trim((string) @file_get_contents($modeFile));
    }
    if ($mode === 'dump') {
        return false;
    }
}
