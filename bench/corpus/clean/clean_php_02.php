<?php
// Clean sample: allowlisted include and int-cast page parameter.
$allowedPages = ['home.php', 'about.php', 'contact.php'];
$page = $_GET['page'];
if (in_array($page, $allowedPages, true)) {
    include($page);
}
$limit = intval($_GET['limit']);
$stmt = $pdo->prepare('SELECT title FROM articles ORDER BY published LIMIT :limit');
$stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
$stmt->execute();
