<?php
/**
 * @name MissingRecaptchaSecretException.php
 * @link https://alexkratky.com                         Author website
 * @link https://panx.eu/docs/                          Documentation
 * @link https://github.com/AlexKratky/AuthX/           Github Repository
 * @author Alex Kratky <alex@panx.dev>
 * @copyright Copyright (c) 2020 Alex Kratky
 * @license http://opensource.org/licenses/mit-license.php MIT License
 * @description MissingRecaptchaSecretException.
 */

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