<?php

class UserModel {

    private $conn;

    private $table_name = 'users';


    public function __construct($db) {

        $this->conn = $db;

    }


    public function getUserByUsername($username) {

        $query = "SELECT id, username, password, email, 2fa_enabled, 2fa_secret FROM " . $this->table_name . " WHERE username = :username LIMIT 1";

        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':username', $username);

        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);

    }


    public function get2FASecret($user_id) {

        $query = "SELECT 2fa_secret FROM " . $this->table_name . " WHERE id = :id";

        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':id', $user_id);

        $stmt->execute();

        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return $result['2fa_secret'] ?? null;

    }

}
