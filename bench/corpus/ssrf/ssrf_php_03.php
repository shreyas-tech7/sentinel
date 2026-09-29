<?php
// Practice sample: curl to a user-controlled URL.
function fetch_metadata() {
    $ch = curl_init($_GET['metadata_url']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    return curl_exec($ch);
}
