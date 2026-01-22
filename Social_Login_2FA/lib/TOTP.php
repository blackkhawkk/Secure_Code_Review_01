<?php
class TOTP {
    private $secret;
    private $period = 30;
    private $digits = 6;

    public function __construct($secret) {
        $this->secret = $secret;
    }

    public function verify($code, $window = 1) {
        $time = floor(time() / $this->period);
        for ($i = -$window; $i <= $window; $i++) {
            if ($this->generateCode($time + $i) === $code) {
                return true;
            }
        }
        return false;
    }

    private function generateCode($time) {
        $hash = hash_hmac('sha1', pack('N*', 0) . pack('N*', $time), base64_decode($this->secret), true);
        $offset = ord($hash[19]) & 0xf;
        $code = (unpack('N', substr($hash, $offset, 4))[1] & 0x7fffffff) % pow(10, $this->digits);
        return str_pad($code, $this->digits, '0', STR_PAD_LEFT);
    }
}
