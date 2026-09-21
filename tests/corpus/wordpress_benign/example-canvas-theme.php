<?php
/**
 * Theme Name: Example Canvas
 */
if (!defined('ABSPATH')) {
    exit;
}

function example_canvas_setup() {
    add_theme_support('title-tag');
    add_theme_support('post-thumbnails');
}

add_action('after_setup_theme', 'example_canvas_setup');

function example_canvas_assets() {
    wp_enqueue_style('example-canvas', get_stylesheet_uri(), array(), '1.0');
}

add_action('wp_enqueue_scripts', 'example_canvas_assets');
