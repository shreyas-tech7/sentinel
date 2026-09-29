<?php
// Practice sample (DVWA fi-style): include of a request-controlled path.
function load_page() {
    $page = $_GET['page'];
    include($page);
}
