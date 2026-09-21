<?php
/**
 * Plugin Name: Example Directory
 * Description: Lists posts in a widget.
 */
if (!defined('ABSPATH')) {
    exit;
}

function example_directory_register() {
    add_action('widgets_init', 'example_directory_widget');
}

function example_directory_widget() {
    return true;
}

function example_directory_render($posts) {
    foreach ($posts as $post) {
        echo esc_html($post->post_title);
    }
}
