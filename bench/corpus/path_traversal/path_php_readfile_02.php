<?php
// Practice sample: readfile of a request path without containment check.
function download_attachment() {
    $attachment = $_GET['attachment'];
    readfile('/var/www/uploads/' . $attachment);
}
