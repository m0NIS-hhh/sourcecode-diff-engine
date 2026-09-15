<?php
function load_user($db) {
    $name = $_GET["name"];
    return mysqli_query($db, "select * from users where name = '" . $name . "'");
}
