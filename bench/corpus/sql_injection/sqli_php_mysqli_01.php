<?php
// Practice sample (DVWA-style): string-built query, no parameterization.
function find_user($conn) {
    $id = $_GET['id'];
    $sql = "SELECT username, email FROM users WHERE id = '" . $id . "'";
    $result = mysqli_query($conn, $sql);
    return mysqli_fetch_all($result, MYSQLI_ASSOC);
}
