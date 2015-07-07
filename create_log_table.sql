/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;

-- Export database structur for vsftpd
CREATE DATABASE IF NOT EXISTS `vsftpd` /*!40100 DEFAULT CHARACTER SET utf8 */;
USE `vsftpd`;


-- Export table structur for vsftpd.log
CREATE TABLE IF NOT EXISTS `log` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `LOG_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `LOG_username` varchar(100) NOT NULL,
  `LOG_status` tinyint(4) NOT NULL COMMENT '0=OK,1=FAIL',
  `LOG_command` varchar(20) NOT NULL,
  `LOG_ip` varchar(41) NOT NULL,
  `LOG_anon-password` varchar(100) NOT NULL,
  `LOG_string` varchar(150) NOT NULL,
  `LOG_filesize` int(11) NOT NULL COMMENT 'filesize in bytes',
  `LOG_speed` int(11) NOT NULL COMMENT 'transferspeed in kbyte/sec',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='Table for vsftpd logs';

/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IF(@OLD_FOREIGN_KEY_CHECKS IS NULL, 1, @OLD_FOREIGN_KEY_CHECKS) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;

-- Create vsftp_logger USER

CREATE USER 'vsftpd_logger'@'localhost' IDENTIFIED BY 'very_secure_password123';
GRANT USAGE ON *.* TO 'vsftpd_logger'@'localhost';
GRANT INSERT  ON `vsftpd`.* TO 'vsftpd_logger'@'localhost';
FLUSH PRIVILEGES;