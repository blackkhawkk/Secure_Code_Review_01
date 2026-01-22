<?php
session_start();
require_once 'config/database.php';
require_once 'controllers/AuthController.php';
require_once 'models/UserModel.php';

$database = new Database();
$db = $database->getConnection();
$userModel = new UserModel($db);
$authController = new AuthController($userModel);

$request_method = $_SERVER['REQUEST_METHOD'];
$request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($request_uri === '/api/login' && $request_method === 'POST') {
    $authController->login();
} elseif ($request_uri === '/api/verify-2fa' && $request_method === 'POST') {
    $authController->verify2FA();
} else {
    http_response_code(404);
    echo json_encode(['error' => 'Not found']);
}
