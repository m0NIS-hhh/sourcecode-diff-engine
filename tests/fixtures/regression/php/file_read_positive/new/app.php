<?php
$path = $_GET['path'] ?? '';
echo file_get_contents($path);
