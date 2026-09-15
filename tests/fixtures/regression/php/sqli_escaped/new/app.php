<?php
function load_user($db) {
    $name = mysqli_real_escape_string($db, $_GET["name"]);
    return mysqli_query($db, "select * from users where name = '" . $name . "'");
}
