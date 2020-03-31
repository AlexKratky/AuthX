<?php

declare (strict_types = 1);

namespace AlexKratky;

use AlexKratky\AuthModel;
use AlexKratky\PanxUtils;
use AlexKratky\MissingRecaptchaSecretException;

class AuthValidator {

    /**
     * @var AuthModel
     */
    protected $authModel;
    protected $recaptchaEnabled = true;
    protected $recaptchaSecret = null;

    public function __construct() {
        $this->authModel = new AuthModel();
    }

    /**
     * Validates recaptcha.
     * @param string $token The recaptcha code.
     * @return bool Returns true if the recaptcha is valid, false otherwise.
     */
    public function validRecaptcha(?string $token): bool {
        if($this->recaptchaEnabled === false || $this->isCaptchaNeeded() === false) {
            return true;
        }
        if($this->recaptchaSecret === null) throw new MissingRecaptchaSecretException();
        $client = new GuzzleHttp\Client();

        $response = $client->post(
            'https://www.google.com/recaptcha/api/siteverify',
            ['form_params' =>
                [
                    'secret' => $this->recaptchaSecret,
                    'response' => $token,
                ],
            ]
        );

        $body = json_decode((string) $response->getBody());
        return $body->success;
    }


    public function validateRecaptcha($code) {
        if(!$this->validRecaptcha($code)) {
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.invalidRecaptcha", true);
            return false;
        }
        return true;
    }

    public function validatePassword($password) {
        if($password === null || strlen($password) < 6) {
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.passwordError", true);
            return false;
        }
        return true;
    }

    public function forgotSaveMessage($wasPasswordReseted) {
        if($wasPasswordReseted) {
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.passwordWasReseted", true);
            return true;
        }
        $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.invalidCombination", true);
        return false;
    }

    public function validateEmail($mail) {
        if (!filter_var($mail, FILTER_VALIDATE_EMAIL)) {
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.invalidMail", true);
            return false;
        }
        return true;
    }

    public function checkEmail($mail) {
        if(!$this->authModel->checkMail($mail)) {
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.mailTaken", true);
            return false;
        }
        return true;
    }

    public function validateName($user) {
        if(!ctype_alnum($user) || strlen($user) < 4) {
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.usernameError", true);
            return false;
        }
        return true;
    }

    public function checkName($user) {
        if(!$this->authModel->checkName($user)) {
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.usernameTaken", true);
            return false;
        }
        return true;
    }

    public function verifyPassword($password) {
        if(!password_verify($password, $_SESSION["password"])) {
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.currentPasswordError", true);
            return false;
        }
        return true;
    }

    public function isDataFilled() {
        if(!$this->request->workWith("POST", array("email", "username", "password", "accept"))) {
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.fillAllData", true);
            return false;
        }
        return true;
    }

    public function validateCheckBox($checkbox) {
        if($checkbox != "on") {
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.agreementError", true);
            return false;
        }
    }

    public function verifyKey($isKeyValid) {
        if (!$isKeyValid) {
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.invalid2FA", true);
            return false;
        } 
        return true;
    }

}
