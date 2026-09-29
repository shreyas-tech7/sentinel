<?php
// Practice sample: interpolated into PDO::query — prepare() is NOT used.
function search_products($pdo) {
    $name = $_POST['name'];
    $stmt = $pdo->query("SELECT * FROM products WHERE name LIKE '%$name%'");
    return $stmt->fetchAll();
}
