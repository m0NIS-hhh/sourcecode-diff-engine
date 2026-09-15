<?php
$name = $_FILES['file']['name'];
$tmp = $_FILES['file']['tmp_name'];
move_uploaded_file($tmp, __DIR__ . "/uploads/" . $name);
