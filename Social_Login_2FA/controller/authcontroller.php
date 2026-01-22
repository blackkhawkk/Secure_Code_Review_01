<?php

class AuthController {

    private $userModel;


    public function __construct($userModel) {

        $this->userModel = $userModel;

    }


    public function login() {

        $username = $_POST['username'] ?? '';

        $password = $_POST['password'] ?? '';

        $two_fa_verified = $_POST['2fa_verified'] ?? 'false';

        

        $user = $this->userModel->getUserByUsername($username);

        

        if ($user && password_verify($password, $user['password'])) {

            if ($user['2fa_enabled'] && $two_fa_verified !== 'true') {

                echo json_encode(['requires_2fa' => true, 'user_id' => $user['id']]);

                return;

            }

            

            $_SESSION['user_id'] = $user['id'];

            $_SESSION['username'] = $user['username'];

            echo json_encode(['success' => true, 'message' => 'Login successful']);

        } else {

            http_response_code(401);

            echo json_encode(['error' => 'Invalid username or password']);

        }

    }


    public function verify2FA() {

        $user_id = $_POST['user_id'] ?? '';

        $otp_code = $_POST['otp_code'] ?? '';

        

        $secret = $this->userModel->get2FASecret($user_id);

        

        if ($this->validateTOTP($secret, $otp_code)) {

            echo json_encode(['verified' => true]);

        } else {

            http_response_code(401);

            echo json_encode(['error' => 'Invalid 2FA code']);

        }

    }


    private function validateTOTP($secret, $code) {

        require_once 'lib/TOTP.php';

        $totp = new TOTP($secret);

        return $totp->verify($code);

    }

}
