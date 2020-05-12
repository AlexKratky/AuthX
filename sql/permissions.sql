CREATE TABLE `permissions` (
	`ID` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	`PERMISSION_NAME` VARCHAR(50) NOT NULL DEFAULT '0' COLLATE 'utf8mb4_bin',
	PRIMARY KEY (`ID`)
)
COMMENT='The list of permissions for user'
COLLATE='utf8mb4_bin'
ENGINE=InnoDB
AUTO_INCREMENT=1
;