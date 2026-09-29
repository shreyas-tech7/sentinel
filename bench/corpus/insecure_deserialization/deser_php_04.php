<?php
// Practice sample: unserialize of a request cookie (POP chain risk).
function load_preferences() {
    return unserialize($_COOKIE['preferences']);
}
