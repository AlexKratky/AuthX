<?php

declare (strict_types = 1);

namespace AlexKratky;

use AlexKratky\AuthModel;
use AlexKratky\db;

class User {

    private $data;
    private $authModel;

    public function __construct($id = null) {
        $this->authModel = new AuthModel();

        if($id !== null) {
            // find and load a user
            $user = $this->authModel->find($id);
            if($user !== false) {
                $this->setData($data);
            }
        }
    }

    public function __get(string $name) {
        if($name === "data" || $name === "password" || $name === "pass") return null;
        if(isset($this->data[$name])) {
            return $this->data[$name];
        }
        return null;
    }

    public function __set(string $name, $value) {
        $this->data[$name] = $value;
    }

    public function setData(array $data) {
        $data["role_name"] = $this->authModel->getRoleName($data["ROLE"]);
        $data["two_auth_enabled"] = $this->authModel->isEnabled2FA($data["ID"]);
        $data["VERIFIED"] = $data["VERIFIED"] === "0" ? false : true;

        array_change_key_case($data, CASE_LOWER);
        $this->data = $data;
    }

    public function user(string $name) {
        $name = strtolower($name);
        switch ($name) {
            case 'name':
                return $this->username;
                break;
            case 'mail':
                return $this->email;
                break;
            case '2fa':
                return $this->two_auth_enabled;
                break;
            default:
                return null;
        }
    }

    public function save() {
        $user = $this->authModel->find($this->id);
        if($user === false) return;
        $columns = array_keys($user);
        
        $cols = "";
        $values = array();
        for($i = 0; $i < count($columns); $i++) {
            $x = strtolower($columns[$i]);
            if($x == "password" || $x == "pass") continue;

            if($cols != "") $cols .= ", ";
            $cols .= "`{$columns[$i]}`" . '=?';
            array_push($values, $this->$x);
        }
        array_push($values, $this->id);

        db::query("UPDATE `users` SET {$cols} WHERE ID=?", $arr);
    }

}
