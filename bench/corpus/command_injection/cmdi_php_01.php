<?php
// Practice sample (DVWA exec-style): user value concatenated into shell call.
function ping_host() {
    $target = $_REQUEST['ip'];
    $cmd = shell_exec('ping -c 4 ' . $target);
    echo "<pre>{$cmd}</pre>";
}
