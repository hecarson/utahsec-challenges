<?php
$routes = [
    "/" => "home.php",
    "/home" => "home.php",
    "/login" => "login.php",
    "/profile" => "profile.php",
    "/logout" => "logout.php",
    "/uploadNote" => "uploadNote.php"
];

$uri = parse_url($_SERVER["REQUEST_URI"]);
$path = $uri["path"];

if (str_starts_with($path, "/static")) {
    $success = include $path;
    if (!$success) require "404.php";
    exit();
}
elseif (array_key_exists($path, $routes)) {
    require $routes[$path];
}
else {
    http_response_code(404);
    require "404.php";
    die();
}
?>
