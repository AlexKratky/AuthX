<?php
namespace AlexKratky;

class MissingRecaptchaSecretException extends \Exception
{
    public function __construct() {
        parent::__construct("Missing reCAPTCHA secret code.", 0, null);
    }

    public function __toString() {
        return __CLASS__ . ": {$this->message}\n";
    }
}