<?php
/**
 * Minimal WordPress function stubs so request-driven samples can run in the lab.
 */
if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/wp/');
}
if (!defined('WPINC')) {
    define('WPINC', 'wp-includes');
}
if (!defined('WP_CONTENT_DIR')) {
    define('WP_CONTENT_DIR', '/tmp/wp/wp-content');
}

if (!function_exists('get_option')) {
    function get_option($key, $default = false) {
        return $default;
    }
}
if (!function_exists('update_option')) {
    function update_option($key, $value, $autoload = null) {
        return true;
    }
}
if (!function_exists('add_action')) {
    function add_action($hook, $callback, $priority = 10, $accepted_args = 1) {
        return true;
    }
}
if (!function_exists('add_filter')) {
    function add_filter($hook, $callback, $priority = 10, $accepted_args = 1) {
        return true;
    }
}
if (!function_exists('apply_filters')) {
    function apply_filters($hook, $value) {
        return $value;
    }
}
if (!function_exists('do_action')) {
    function do_action($hook) {
        return null;
    }
}
if (!function_exists('wp_mail')) {
    function wp_mail($to, $subject, $message, $headers = '', $attachments = array()) {
        return true;
    }
}
if (!function_exists('is_admin')) {
    function is_admin() {
        return false;
    }
}
if (!function_exists('is_user_logged_in')) {
    function is_user_logged_in() {
        return !empty($_COOKIE['wordpress_logged_in_sandbox']);
    }
}
if (!function_exists('wp_get_current_user')) {
    function wp_get_current_user() {
        return (object) array('ID' => 0, 'user_login' => '');
    }
}
if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir($time = null, $create_dir = true, $refresh_cache = false) {
        return array(
            'path' => '/tmp/wp/uploads',
            'url' => 'http://localhost/wp-content/uploads',
            'basedir' => '/tmp/wp/uploads',
            'baseurl' => 'http://localhost/wp-content/uploads',
            'error' => false,
        );
    }
}
if (!function_exists('plugin_dir_path')) {
    function plugin_dir_path($file) {
        return rtrim(dirname($file), '/') . '/';
    }
}
if (!function_exists('__')) {
    function __($text, $domain = 'default') {
        return $text;
    }
}
if (!function_exists('_e')) {
    function _e($text, $domain = 'default') {
        echo $text;
    }
}
if (!function_exists('esc_html')) {
    function esc_html($text) {
        return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
    }
}
if (!isset($wpdb)) {
    $wpdb = (object) array('prefix' => 'wp_', 'posts' => 'wp_posts', 'options' => 'wp_options');
}
