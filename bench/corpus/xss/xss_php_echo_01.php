<?php
// Practice sample: reflected XSS — request value echoed into HTML.
function greet() {
    echo '<p>Welcome back, ' . $_GET['name'] . '!</p>';
}
