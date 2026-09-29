<?php
// Clean sample: prepared statement, escaped output, quoted command arg.
function find_user(PDO $pdo) {
    $id = $_GET['id'];
    $stmt = $pdo->prepare('SELECT username FROM users WHERE id = :id');
    $stmt->execute(['id' => $id]);
    $row = $stmt->fetch();
    echo '<p>Welcome back, ' . htmlspecialchars($row['username'], ENT_QUOTES) . '</p>';
}

function ping_host() {
    $target = escapeshellarg($_REQUEST['ip']);
    echo shell_exec('ping -c 4 ' . $target);
}
