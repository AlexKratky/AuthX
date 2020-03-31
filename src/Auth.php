<?php
/**
 * @name Auth.php
 * @link https://alexkratky.cz                          Author website
 * @link https://panx.eu/docs/                          Documentation
 * @link https://github.com/AlexKratky/panx-framework/  Github Repository
 * @author Alex Kratky <info@alexkratky.cz>
 * @copyright Copyright (c) 2019 Alex Kratky
 * @license http://opensource.org/licenses/mit-license.php MIT License
 * @description Class to authentification users. Part of panx-framework.
 */

declare (strict_types = 1);

namespace AlexKratky;

use AlexKratky\User;
use AlexKratky\Route;
use AlexKratky\Request;
use AlexKratky\AuthModel;
use AlexKratky\PanxUtils;
use AlexKratky\AuthValidator;
use PragmaRX\Google2FAQRCode\Google2FA;

class Auth extends AuthValidator {

    /**
     * @var Request
     */
    private $request;

    /**
     * @var AuthModel
     */
    protected $authModel;

    /**
     * @var PragmaRX\Google2FAQRCode\Google2FA
     */
    private $twoFA;

    /**
     * @var User
     */
    private $user;

    protected $recaptchaEnabled = true;
    protected $recaptchaSecret = null;

    /**
     * Create a instance of Auth.
     * @param bool $logout If sets to false, it will try to login the user.
     */
    public function __construct(User $user, bool $logout = false) {
        $this->request = $GLOBALS["request"] ?? new Request();
        $this->authModel = new AuthModel();
        $this->twoFA = new PragmaRX\Google2FAQRCode\Google2FA();
        $this->user = $user;
        if(!$logout) {
            if(!empty($_SESSION["username"]) && !empty($_SESSION["password"])) {
                $this->login($_SESSION["username"], $_SESSION["password"]);
            }
        }
    }

    /**
     * @return bool Returns true if the user is logined (and if he has 2FA enabled, then he will need to enter the 2FA code to be 'logined'), false otherwise.
     */
    public function isLogined(): bool {
        if(!empty($this->user->id)) {
            return true;
        }
        return false;
    }

    /**
     * Tries to login user, if the user have 2fa enabled, redirects to alias 'login-2fa'.
     * @param string|null $username The username from session or null,
     * @param string|null $password The password from session or null,
     * @param bool $r Determines if the user want to remember login.
     * @return bool Returns true if the user was logined, false otherise.
     */
    public function login(?string $username = null, ?string $password = null, bool $r = false) {
        if($this->loginFromCookies()) {
            return true;
        }
        $login_from_session = true;
        if($username === null || $password === null) {
            if($this->request->getPost('username') !== null && $this->request->getPost('password') !== null) {
                $username = $this->request->getPost('username');
                $password = $this->request->getPost('password');
                if(!$this->validateRecaptcha($this->request->getPost('g-recaptcha-response'))) return false;
                $login_from_session = false;
            } else {
                return false;
            }
        }
        return $this->verifyLogin($username, $password, $login_from_session, $r);
    }

    public function verifyLogin(?string $username = null, ?string $password = null, bool $login_from_session = true, bool $r = false) {
        if($this->authModel->verifyLogin($username, $password, $login_from_session)) {
            $data = $this->authModel->loadData($username);
            if(!$this->authModel->isEnabled2FA($data["ID"]) || $this->request->getPost('2fa_code') !== null || (isset($_SESSION["2fa_passed"]) && $_SESSION["2fa_passed"] == true)) {
                $twofacheck = false;
                if($this->request->getPost('2fa_code') !== null) {
                    $secret = $this->authModel->get2FASecret($data["ID"]);
                    if($this->verifyKey($this->twoFA->verifyKey($secret, $this->request->getPost('2fa_code')))) return false;
                    $_SESSION["2fa_passed"] = true;
                    $twofacheck = true;
                }

                $this->fillData($data);

                if((!$login_from_session && $this->request->getPost('remember') === "on") || ($twofacheck && $r && isset($_SESSION["remember_login"]) && $_SESSION["remember_login"] = true)) {
                    $token = $this->authModel->updateRememberToken($data["ID"]);
                    setcookie("REMEMBER_TOKEN", $token, time() + 86400 * 30, "/", "", false, true);
                    setcookie("USERNAME", $data["USERNAME"], time() + 86400 * 30, "/", "", false, true);
                }

                $_SESSION["username"] = $data["USERNAME"];
                $_SESSION["password"] = $data["PASSWORD"];
                return true;
            } else {
                $_SESSION["username"] = $data["USERNAME"];
                $_SESSION["remember_login"] = $this->request->getPost('remember') == "on";
                $_SESSION["password"] = $data["PASSWORD"];
                $_SESSION["2fa_passed"] = false;
                if($this->request->getUrl()->getLink()[1] != "login-2fa" && $this->request->getUrl()->getLink()[1] != "logout") {
                    PanxUtils::aliasredirect("login-2fa");
                }
            }
        } else {
            $_SESSION["remember_login"] = null;
            $_SESSION["username"] = null;
            $_SESSION["password"] = null;
            $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.invalidUsernameOrPass", true);
            return false;
        }
    }

    /**
     * Tries to login user from cookies.
     * @return bool Returns true if the user was successfully logined from cookies, false otherwise.
     */
    public function loginFromCookies(): bool {
        if($this->authModel->loginFromCookies()) {
            $data = $this->authModel->loadData($_COOKIE["USERNAME"]);
            
            $this->fillData($data);

            $_SESSION["username"] = $data["USERNAME"];
            $_SESSION["password"] = $data["PASSWORD"];
            return true;
        } else {
            return false;
        }
    }

    /**
     * @return array Returns the array containing the data about 2FA. [0] => SECRET; [1] => URL of QR code.
     */
    public function twoFactorAuthData(): array {
        if(empty($_SESSION["2fa_secret"])) {
            $secret = $this->twoFA->generateSecretKey();
            $_SESSION["2fa_secret"] = $secret;
        } else {
            $secret = $_SESSION["2fa_secret"];
        }

        $url = $this->twoFA->getQRCodeInline(
            $GLOBALS["CONFIG"]["basic"]["APP_NAME"],
            $this->username,
            $secret
        );

        return [$secret, $url];
    }

    /**
     * Setup the 2FA for user, if he entered a valid code.
     * @return bool Returns false if the 2FA wasnt set up, true otherwise.
     */
    public function save2FA(): bool {
        if(!$this->validateRecaptcha($this->request->getPost('g-recaptcha-response'))) return false;

        $secret = $_SESSION["2fa_secret"];

        if (!$this->verifyKey($this->twoFA->verifyKey($secret, $this->request->getPost('code')))) return false;

        $this->authModel->setUp2FA($this->id, $secret);
        $_SESSION["2fa_passed"] = true;
        return true;
    }

    /**
     * Disable the 2FA for user.
     */
    public function disable2FA() {
        $this->authModel->disable2FA($this->id);
    }

    /**
     * Tries to register the user. Work with POST - email; username; password; accept
     * @return bool Returns true, if the user is registered, false otherwise.
     */
    public function register(): bool {
        if(!$this->validateRecaptcha($this->request->getPost('g-recaptcha-response'))) return false;

        if(!$this->isDataFilled()) return false;

        if(!$this->validateEmail($this->request->getPost('email'))) return false;

        if(!$this->validateName($this->request->getPost('username'))) return false;

        if(!$this->validatePassword($this->request->getPost('password'))) return false;

        if(!$this->validateCheckBox($this->request->getPost('accept'))) return false;
        
        if(!$this->checkName($this->request->getPost('username'))) return false;

        if(!$this->checkEmail($this->request->getPost('email'))) return false;

        $p = $this->authModel->register($this->request->getPost('email'), $this->request->getPost('username'), $this->request->getPost('password'));
        $_SESSION["username"] = strtolower($this->request->getPost('username'));
        $_SESSION["password"] = $p;
        return true;
    }

    /**
     * Tries to saves the new data of user.
     * @return bool Returns true if the data was saved, false otherwise (e.g. wrong password, email is already taken etc.)
     */
    public function edit(): bool {
        if(!$this->validateRecaptcha($this->request->getPost('g-recaptcha-response'))) return false;
        
        $mail = strtolower($this->request->getPost('email'));
        if($mail !== $this->email) {
            if(!$this->validateEmail($mail)) return false;
            if(!$this->checkEmail($mail)) return false;
        }

        $user = strtolower($this->request->getPost('username'));
        if($user !== $this->username) {
            if(!$this->validateName($user)) return false;
            if(!$this->checkName($user)) return false;
        }

        $password = $this->request->getPost('newpassword');
        if($password !== "") {
            if(!$this->validatePassword($password)) return false;
        } else $password = null;

        if(!$this->verifyPassword($this->request->getPost('password'))) return false;

        $p = $this->authModel->edit($this->id, $mail, $user, $password, ($this->request->getPost('email') !== $this->email));
        $this->username = $user;
        $this->email = $mail;
        if($p !== null) {
            $this->password = $p;
            $_SESSION["password"] = $p;
        }
        $_SESSION["username"] = $user;
        $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.profileUpdated", true);
        return true;
    }

    /**
     * @return string Returns error string or empty string.
     */
    public static function displayError(): string {
        if(!empty($_SESSION["AUTH_ERROR"])) {
            $e = $_SESSION["AUTH_ERROR"];
            $_SESSION["AUTH_ERROR"] = null;
            return $e;
        }
        return "";
    }

    /**
     * Logout user and redirect to logout page and exit() executing.
     */
    public function logout() {
        $_SESSION["username"] = null;
        $_SESSION["password"] = null;
        session_destroy();
        setcookie("PHPSESSID", "", -1, "/");
        setcookie("USERNAME", "", -1, "/");
        $t = null;
        if($this->request->getQuery("soft") == "true")
            $t = $_COOKIE["REMEMBER_TOKEN"] ?? null;
        setcookie("REMEMBER_TOKEN", "", -1, "/");
        $this->authModel->clearTokens($this->id, $t);
        PanxUtils::aliasredirect('logout');
        exit();
    }

    /**
     * Verify the user email by token.
     * @param string $token.
     * @return bool Returns true if the mail was verified, false otherwise.
     */
    public function verify(string $token): bool {
        return $this->authModel->verify($this->id, $token);
    }

    /**
     * Sends the email with reset link.
     * @return bool Returns true if the mail was sent, false otherwise.
     */
    public function forgot(): bool {
        if(!$this->validateRecaptcha($this->request->getPost('g-recaptcha-response'))) return false;

        $mail = strtolower($this->request->getPost('email'));
        
        if(!$this->validateEmail($mail)) return false;

        $this->authModel->forgot($mail);
        $_SESSION["AUTH_ERROR"] = PanxUtils::__("auth.resetPassword", true);
        return true;
    }

    /**
     * Saves the new password.
     * @return bool Returns true if the password was reset, false otherwise.
     */
    public function forgotSave(): bool {
        if(!$this->validateRecaptcha($this->request->getPost('g-recaptcha-response'))) return false;
        
        $password = $this->request->getPost('password');
        
        if(!$this->validatePassword($password)) return false;

        $mail = strtolower($this->request->getPost('email'));

        return $this->forgotSaveMessage($this->authModel->forgotSave($mail, $password, Route::getValue('TOKEN')));
    }

    /**
     * Returns the user specified data.
     * @param string $data The data column name, e.g. 'name', 'id', 'email', ...
     */
    public function user(string $data) {
        return $this->user->user($data);
    }

    /**
     * Check if user have the passed permission.
     * @param string $permission The permission name that will be checked.
     * @return bool Returns true if the user is permitted, false otherwise.
    */
    public function isUserPermittedTo(string $permission): bool {
        return (strpos($this->permissions, $permission) !== false);
    }

    /**
     * The captcha failed, inserts the row into `recaptcha_fails`, so the user needs to fill the recaptcha.
     */
    public function captchaFailed() {
        $this->authModel->captchaFailed($_SERVER['REMOTE_ADDR']);
    }

    /**
     * @return bool Returns true if recaptcha is needed (is collumn in `recaptcha_fails`), false otherwise.
     */
    public function isCaptchaNeeded(): bool {
        return $this->authModel->isCaptchaNeeded($_SERVER['REMOTE_ADDR']);
    }

    /**
     * The captcha passed, deletes the row from `recaptcha_fails`.
     */
    public function captchaPassed() {
        $this->authModel->captchaPassed($_SERVER['REMOTE_ADDR']);
    }

    public function loginUserFromToken($token) {
        $data = $this->authModel->loadDataFromLoginToken($token);
        if($data !== false) {
            $this->fillData($data);
        }
    }

    private function fillData(array $data) {
        $this->user->setData = $data;
    }

    public function __get(string $name) {
        if(isset($this->user->$name)) {
            return $this->user->$name;
        }
        return null;
    }

    public function __set(string $name, $value) {
        $this->user->$name = $value;
    }

}
