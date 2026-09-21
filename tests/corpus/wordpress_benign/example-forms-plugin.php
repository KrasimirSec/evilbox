<?php
/**
 * Plugin Name: Example Forms
 */
if (!defined('ABSPATH')) {
    exit;
}

function example_forms_menu() {
    add_options_page('Example Forms', 'Example Forms', 'manage_options', 'example-forms', 'example_forms_page');
}

add_action('admin_menu', 'example_forms_menu');

function example_forms_page() {
    if (!current_user_can('manage_options')) {
        return;
    }
    $value = get_option('example_forms_notice', '');
    echo '<div class="wrap"><h1>Example Forms</h1><p>' . esc_html($value) . '</p></div>';
}
