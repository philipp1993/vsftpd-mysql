/*
 * Part of Very Secure FTPd
 * Licence: GPL v2
 * Author: Philipp Koch
 * locales-de.h
 */

#define PERMISSION_DENIED "Permission denied."
#define FTP_TOO_MANY_USERS_LOG_LINE "Connection refused: too many sessions."
#define FTP_TOO_MANY_USERS_CMDIO_LINE "There are too many connected users, please try later."
#define DIE_CHROOT_TOP_WRITEABLE "vsftpd: refusing to run with writable root inside chroot()"
#define FTP_TOO_MANY_CONNECTIONS_LOG_LINE "Connection refused: too many sessions for this address."
#define FTP_TOO_MANY_CONNECTIONS_CMDIO_LINE "There are too many connections from your internet address."
#define FTP_TOO_TCP_WRAPPERS_LOG_LINE "Connection refused: tcp_wrappers denial."
#define FTP_TOO_TCP_WRAPPERS_CMDIO_LINE "Service not available."
#define FTP_GOODBYE_CMDIO_LINE "Goodbye."
#define FTP_LOGIN_ERROR_CMDIO_LINE "Please login with USER and PASS."
#define FTP_LOGIN_ERROR_NO_ROOT_CMDIO_LINE "root logins disabled!"
#define FTP_LOGIN_ERROR_ONLY_ANON_CMDIO_LINE "This FTP server is anonymous only."
#define FTP_NO_SSL_FOR_ANON "Anonymous sessions may not use encryption."
#define FTP_NO_SSL_LOCAL "Non-anonymous sessions must use encryption."
#define FTP_NO_SSL_ANON "Anonymous sessions must use encryption."
#define FTP_ASK_FOR_PASSWORD "Please specify the password."
#define FTP_ASK_FOR_USER "Login with USER first."
#define FTP_LOGIN_INVALID "Login incorrect."
#define FTP_LOGIN_VALID "Login successful."
#define FTP_NOTHING_TO_ABOR "No transfer to ABOR."
#define FTP_STRUOK_CMDIO_LINE "Structure set to F."
#define FTP_BAD_STRU_CMDIO_LINE "Bad STRU command."
#define FTP_MODE_OK_CMDIO_LINE "Mode set to S."
#define FTP_MODE_BAD_CMDIO_LINE "Bad MODE command."
#define FTP_ALLO_CMDIO_LINE "ALLO command ignored."
#define FTP_REIN_CMDIO_LINE "REIN not implemented."
#define FTP_ACCT_CMDIO_LINE "ACCT not implemented."
#define FTP_SMNT_CMDIO_LINE "SMNT not implemented."
#define FTP_BAD_COMMAND "Unknown command."
#define FTP_DATA_TIMEOUT_CMDIO_LINE "Data timeout. Reconnect. Sorry."
#define FTP_CHANGE_DIR_OK_CMDIO_LINE "Directory successfully changed."
#define FTP_CHANGE_DIR_FAIL_CMDIO_LINE "Failed to change directory."
#define FTP_BAD_EPS_CMDIO_LINE "EPSV ALL ok."
#define FTP_START_PASS_EX_CMDIO_LINE "Entering Extended Passive Mode (|||"
#define FTP_START_PASS_CMDIO_LINE "Entering Passive Mode ("
#define FTP_NO_ASCII_RETURN "No support for resume of ASCII transfer."
#define FTP_OPEN_FILE_FAIL_CMDIO_LINE "Failed to open file."
#define FTP_STRING_OPEN "Opening "
#define FTP_MODE_FOR_FILE_CMDIO_LINE " mode data connection for "
#define FTP_BAD_LOCAL_FILE_CMDIO_LINE "Failure reading local file."
#define FTP_BAD_NETWORK_WRITE_CMDIO_LINE "Failure writing network stream."
#define FTP_TRANSFER_OK_CMDIO_LINE "Transfer complete."
#define FTP_GIVE_STATUS_CMDIO_LINE "Status follows:"
#define FTP_END_STATUS_CMDIO_LINE "End of status"
#define FTP_DIRLISTING_ANNOUNCEMENT_CMDIO_LINE "Here comes the directory listing."
#define FTP_TRANSFER_OK_NO_DIR "Transfer done (but failed to open directory)."
#define FTP_DIRLISTING_OK "Directory send OK."
#define FTP_CHANGE_TO_BINARY "Switching to Binary mode."
#define FTP_CHANGE_TO_ASCII "Switching to ASCII mode."
#define FTP_UNKNOWN_TYPE "Unrecognised TYPE command."
#define FTP_PORT_FAIL_CMDIO_LINE "Illegal PORT command."
#define FTP_PORT_OK_PASV_INFO "PORT command successful. Consider using PASV."
#define FTP_UPLOAD_FAIL_NO_FILE_CREATE Could not create file."
#define FTP_FILE_CMDIO_LINE "FILE: "
#define FTP_READY_TO_SEND_CMDIO_LINE "Ok to send data."
#define FTP_BAD_LOCAL_FILE_WRITE_CMDIO_LINE "Failure writing to local file."
#define FTP_BAD_NETWORK_READ_CMDIO_LINE "Failure reading network stream."
#define FTP_TRANSFER_OK_CMDIO_LINE "Transfer complete."
#define FTP_BAD_MKDIR_CMDIO_LINE "Create directory operation failed."
#define FTP_CREATED_CMDIO_LINE "\" created"
#define FTP_BAD_RMDIR_CMDIO_LINE "Remove directory operation failed."
#define FTP_OK_RMDIR_CMDIO_LINE "Remove directory operation successful."
#define FTP_BAD_RM_CMDIO_LINE "Delete operation failed."
#define FTP_OK_RM_CMDIO_LINE "Delete operation successful."
#define FTP_RESTART_POS_OK_CMDIO_LINE "Restart position accepted ("
#define FTP_READY_FOR_RNTO_CMDIO_LINE "Ready for RNTO."
#define FTP_BAD_RNFR_CMDIO_LINE "RNFR command failed."
#define FTP_RNFR_FIRST_CMDIO_LINE "RNFR required first."
#define FTP_OK_RENAME_CMDIO_LINE "Rename successful."
#define FTP_FAIL_RENAME_CMDIO_LINE "Rename failed."
#define FTP_OK_ABOR_CMDIO_LINE "ABOR successful."
#define FTP_BAD_FILESTAT_CMDIO_LINE "Could not get file size."
#define FTP_SITE_HELP_CHMOD_UMASK "CHMOD UMASK HELP"
#define FTP_SITE_HELP_UMASK "UMASK HELP"
#define FTP_BAD_SITE_COMMAND_CMDIO_LINE "Unknown SITE command."
#define FTP_BAD_SITE_CHMOD_CMDIO_LINE "SITE CHMOD needs 2 arguments."
#define FTP_FAIL_SITE_CHMOD_CMDIO_LINE "SITE CHMOD command failed."
#define FTP_OK_SITE_CHMOD_CMDIO_LINE "SITE CHMOD command ok."
#define FTP_OK_UMASK_READ_CMDIO_LINE "Your current UMASK is "
#define FTP_OK_UMASK_WRITE_CMDIO_LINE "UMASK set to "
#define FTP_FAIL_SET_CTIME_CMDIO_LINE "Could not set file modification time."
#define FTP_OK_SET_CTIME_CMDIO_LINE "File modification time set."
#define FTP_FAIL_READ_CTIME_CMDIO_LINE "Could not get file modification time."
#define FTP_BAD_EPRT_CMDIO_LINE "Bad EPRT protocol."
#define FTP_BAD_EPRT_COMMAND_CMDIO_LINE "Illegal EPRT command."
#define FTP_OK_EPRT_COMMAND_CMDIO_LINE "EPRT command successful. Consider using EPSV."
#define FTP_HELP_HEADER_CMDIO_LINE "The following commands are recognized."
#define FTP_HELP_OK_CMDIO_LINE "Help OK."
#define FTP_SRV_STATUS_CMDIO_LINE "FTP server status:"
#define FTP_SRV_CONNECTED_CMDIO_LINE "     Connected to "
#define FTP_SRV_LOGGED_IN_AS_CMDIO_LINE "     Logged in as "
#define FTP_SRV_MODE_CMDIO_LINE "     Logged in as "
#define FTP_SHOW_SPEEDLIMIT_WITHOUT_CMDIO_LINE "     No session bandwidth limit\r\n"
#define FTP_SHOW_SPEEDLIMIT_LIMIT_CMDIO_LINE "     Session bandwidth limit in byte/s is "
#define FTP_SHOW_TIMEOUT_NO_CMDIO_LINE "     No session timeout\r\n"
#define FTP_SHOW_TIMEOUT_YES_CMDIO_LINE "     Session timeout in seconds is "
#define FTP_SHOW_COMMAND_IS_CRYPT  "     Control connection is encrypted\r\n"
#define FTP_SHOW_COMMAND_NO_CRYPT  "     Control connection is plain text\r\n"
#define FTP_SHOW_DATA_IS_CRYPT  "     Data connections will be encrypted\r\n"
#define FTP_SHOW_DATA_NO_CRYPT  "     Data connections will be plain text\r\n"
#define FTP_SHOW_DATA_NEED_CRYPT "Data connections must be encrypted."
#define FTP_SHOW_LOGGEND_ON_WHILE_LOGIN "     At session startup, client count was "
#define FTP_SHOW_LOGGEND_ON_WHILE_LOGIN2 "\r\n"
#define FTP_VSFTPD_TAIL " \r\n"
#define FTP_SHOW_END_OF_STATUS "End of status"
#define FTP_USE_FIRST_CMDIO_LINE "Use PORT or PASV first."
#define FTP_NO_CHANGE_FROM_GUEST "Can't change from guest user."
#define FTP_GIVE_ANY_PW "Any password will do."
#define FTP_COULD_NOT_CHANGE_USER "Can't change to another user."
#define FTP_ALREADY_LOGGED_IN "Already logged in."
#define FTP_BAD_CONNECTION_CMDIO_LINE "Failed to establish connection."
#define FTP_IP_IS_BLOCKED "Security: Bad IP connecting."
#define FTP_ALWAYS_UFT8_CMDIO_LINE "Always in UTF8 mode."
#define FTP_BAD_OPTION_CMDIO_LINE "Option not understood."
#define FTP_FEATURES_STRING_CMDIO_LINE "Features:"
#define FTP_SSL_HANDSHAKE_FAILED "Negotiation failed: "
#define FTP_SSL_CONTINUE "Proceed with negotiation."
#define FTP_UNKNOWN_AUTH_CMDIO_LINE "Unknown AUTH type."
#define FTP_SSL_PBSZ_REQUIRE "PBSZ needs a secure connection."
#define FTP_SSL_PBSZ_ZERO "PBSZ set to 0."
#define FTP_SSL_PROT_REQUIRE "PROT needs a secure connection."
#define FTP_SSL_PROT_FREE "PROT now Clear."
#define FTP_SSL_PROT_PRIVATE "PROT now Private."
#define FTP_SSL_PROT_NOT "PROT not supported."
#define FTP_SSL_PROT_UNKNOWN "PROT not recognized."
#define FTP_INPUT_LINE_LONG_CMDIO_LINE "Input line too long."
#define FTP_500_STRING "500 OOPS: "
#define FTP_500_SIZE 10 //the number of chars of the FTP_500_STRING
#define FTP_SSL_FAILED_1  "SSL connection failed"
#define FTP_SSL_FAILED_2 "; session reuse required"
#define FTP_SSL_FAILED_3 ": see require_ssl_reuse option in vsftpd.conf man page"
#define FTP_DATA_NAME "DATA"
#define FTP_CONTROL_NAME "Control"
#define FTP_SSL_CONNECTION_FAILED1 " connection terminated without SSL shutdown."
#define FTP_SSL_CONNECTION_FAILED2 " Buggy client! Integrity of upload cannot be asserted."
#define FTP_SECUTIL_LOCATE_USER "cannot locate user entry:"
#define FTP_SECUTIL_NOT_RUNNING_ROOT "vsf_secutil_change_credentials: not running as root"
#define FTP_SECUTIL_CANNOT_CHDIR "cannot change directory:"
#define FTP_PWD_TAIL "\" is the current directory"
