<?php
class AuthMiddleware {
    public static function requireAuth() {
        if (!isset($_SESSION['user_id'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Authentication required']);
            exit;
        }
    }

    public static function getCurrentUser() {
        return [
            'id' => $_SESSION['user_id'] ?? null,
            'username' => $_SESSION['username'] ?? null
        ];
    }

    public static function logout() {
        session_destroy();
        echo json_encode(['success' => true, 'message' => 'Logged out successfully']);
    }
}
