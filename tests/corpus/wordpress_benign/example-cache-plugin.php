<?php
/**
 * Plugin Name: Example Cache
 * Description: Local page cache. Benign file_get_contents / file_put_contents and a password field.
 */
if (!defined('ABSPATH')) {
    exit;
}

function example_cache_get($key) {
    $file = WP_CONTENT_DIR . '/cache/' . $key . '.html';
    if (!is_file($file)) {
        return false;
    }
    return file_get_contents($file);
}

function example_cache_set($key, $html) {
    $file = WP_CONTENT_DIR . '/cache/' . $key . '.html';
    return file_put_contents($file, $html);
}

function example_cache_form() {
    echo '<form method="post"><input type="password" name="pwd" /></form>';
}
