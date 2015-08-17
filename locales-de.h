/*
 * Part of Very Secure FTPd
 * Licence: GPL v2
 * Author: Philipp Koch
 * locales-de.h
 */

#define PERMISSION_DENIED "ZUGRIFF VERWEIGERT!"
#define FTP_TOO_MANY_USERS_LOG_LINE "Verbindung abgelehnt: Zu viele Verbindungen."
#define FTP_TOO_MANY_USERS_CMDIO_LINE "Es sind bereits zu viele Nutzer angemeldet. Bitte versuchen Sie es spaeter erneut."
#define DIE_CHROOT_TOP_WRITEABLE "chroot auf root-level beschreibar" 
#define FTP_TOO_MANY_CONNECTIONS_LOG_LINE "Verbindung abgelehnt: zu viele Verbindungen von ihrer IP."
#define FTP_TOO_MANY_CONNECTIONS_CMDIO_LINE "Es sind bereits zu viele Verbindungen von Ihrer IP Adresse aus aufgebaut."
#define FTP_TOO_TCP_WRAPPERS_LOG_LINE "Connection refused: tcp_wrappers denial."
#define FTP_TOO_TCP_WRAPPERS_CMDIO_LINE "Dienst nicht verfuegbar."
#define FTP_GOODBYE_CMDIO_LINE "Auf Wiedersehen."
#define FTP_LOGIN_ERROR_CMDIO_LINE "Bitte melden Sie sich mit USER und PASS an."
#define FTP_LOGIN_ERROR_NO_ROOT_CMDIO_LINE "KEIN ZUGRIFF FUER DEN ROOT ACCOUNT"
#define FTP_LOGIN_ERROR_ONLY_ANON_CMDIO_LINE "Dieser FTP Server ist nur anonym zu erreichen."
#define FTP_NO_SSL_FOR_ANON "Anonyme Sitzungen muessen unverschluesselt sein."
#define FTP_NO_SSL_LOCAL "Verbindungen muessen verschluesselt sein."
#define FTP_NO_SSL_ANON "Anonyme Sitzungen muessen verschluesselt sein."
#define FTP_ASK_FOR_PASSWORD "Bitte geben Sie ein Passwort an."
#define FTP_ASK_FOR_USER "Befehl USER zuerst benoetigt"
#define FTP_LOGIN_INVALID "Login ungueltig."
#define FTP_LOGIN_VALID "Login erfolgreich."
#define FTP_NOTHING_TO_ABOR "Keine Uebertragung zum Abrechen."
#define FTP_STRUOK_CMDIO_LINE "Struktur eingestellt auf F."
#define FTP_BAD_STRU_CMDIO_LINE "Falscher STRU Befehl."
#define FTP_MODE_OK_CMDIO_LINE "Modus eingestellt auf S."
#define FTP_MODE_BAD_CMDIO_LINE "Falscher MODE Befehl."
#define FTP_ALLO_CMDIO_LINE "ALLO Befehl ignoriert."
#define FTP_REIN_CMDIO_LINE "REIN nicht unterstuetzt."
#define FTP_ACCT_CMDIO_LINE "ACCT nicht unterstuetzt."
#define FTP_SMNT_CMDIO_LINE "SMNT nicht unterstuetzt."
#define FTP_BAD_COMMAND "Unbekannter Befehl."
#define FTP_DATA_TIMEOUT_CMDIO_LINE "Daten Timeout. Wiederverbinden. Sorry."
#define FTP_CHANGE_DIR_OK_CMDIO_LINE "Verzeichniswechsel erfolgreich."
#define FTP_CHANGE_DIR_FAIL_CMDIO_LINE "Verzeichniswechsel FEHLGESCHLAGEN ."
#define FTP_BAD_EPS_CMDIO_LINE "Falsches Netzwerkprotokoll."
#define FTP_START_PASS_EX_CMDIO_LINE "Starte erweiterten passiven Modus (|||"
#define FTP_START_PASS_CMDIO_LINE "Starte passiven Modus ("
#define FTP_NO_ASCII_RETURN "Kein Support fuer das Wiederaufnehmen von ASCII Uebertragungen."
#define FTP_OPEN_FILE_FAIL_CMDIO_LINE "Konnte Datei nicht oeffnen."
#define FTP_STRING_OPEN "Oeffne "
#define FTP_MODE_FOR_FILE_CMDIO_LINE " Modus Datenuebertragung fuer "
#define FTP_BAD_LOCAL_FILE_CMDIO_LINE "Fehler beim Lesen von lokaler Datei."
#define FTP_BAD_NETWORK_WRITE_CMDIO_LINE "Fehler beim Schreiben auf das Netzwerk."
#define FTP_TRANSFER_OK_CMDIO_LINE "Uebertragung komplett."
#define FTP_GIVE_STATUS_CMDIO_LINE "Status folgt:"
#define FTP_END_STATUS_CMDIO_LINE "Ende des Status"
#define FTP_DIRLISTING_ANNOUNCEMENT_CMDIO_LINE "Verzeichnisinhalt wird aufgelistet..."
#define FTP_TRANSFER_OK_NO_DIR "Uebertragung erfolgreich (aber konnte Verzeichnis nicht oeffnen)."
#define FTP_DIRLISTING_OK "Verzeichnisinhalt gesendet."
#define FTP_CHANGE_TO_BINARY "Dateiuebertragung im Binary Modus."
#define FTP_CHANGE_TO_ASCII "Dateiuebertragung im ASCII Modus."
#define FTP_UNKNOWN_TYPE "Unbekannter TYPE Befehl."
#define FTP_PORT_FAIL_CMDIO_LINE "Ungueltiger PORT Befehl."
#define FTP_PORT_OK_PASV_INFO "PORT Befehl erfolgreich, aber benutze besser PASV."
#define FTP_UPLOAD_FAIL_NO_FILE_CREATE "Konnte Datei nicht erstellen."
#define FTP_FILE_CMDIO_LINE "DATEI: "
#define FTP_READY_TO_SEND_CMDIO_LINE "Bereit zum Senden von Daten."
#define FTP_BAD_LOCAL_FILE_WRITE_CMDIO_LINE "Fehler beim Schreiben der lokalen Datei."
#define FTP_BAD_NETWORK_READ_CMDIO_LINE "Fehler beim Lesen vom Netzwerk."
#define FTP_TRANSFER_OK_CMDIO_LINE "Uebertragung komplett."
#define FTP_BAD_MKDIR_CMDIO_LINE "Verzeichnis erstellen fehlgeschlagen."
#define FTP_CREATED_CMDIO_LINE "\" erstellt"
#define FTP_BAD_RMDIR_CMDIO_LINE "Verzeichnis entfernen fehlgeschlagen."
#define FTP_OK_RMDIR_CMDIO_LINE "Verzeichnis entfernen erfolgreich."
#define FTP_BAD_RM_CMDIO_LINE "Entfernen fehlgeschlagen."
#define FTP_OK_RM_CMDIO_LINE "Entfernen erfolgreich."
#define FTP_RESTART_POS_OK_CMDIO_LINE "Neustart Position akzeptiert ("
#define FTP_READY_FOR_RNTO_CMDIO_LINE "Bereit fuer RNTO."
#define FTP_BAD_RNFR_CMDIO_LINE "RNFR Befehl fehlgeschlagen."
#define FTP_RNFR_FIRST_CMDIO_LINE "RNFR zuerst erforderlich."
#define FTP_OK_RENAME_CMDIO_LINE "Umbenennen erfolgreich."
#define FTP_FAIL_RENAME_CMDIO_LINE "Umbenennen fehlgeschlagen."
#define FTP_OK_ABOR_CMDIO_LINE "ABOR erfolgreich."
#define FTP_BAD_FILESTAT_CMDIO_LINE "Konnte Dateigroesse nicht bestimmen."
#define FTP_SITE_HELP_CHMOD_UMASK "CHMOD UMASK HILFE"
#define FTP_SITE_HELP_UMASK "UMASK HILFE"
#define FTP_BAD_SITE_COMMAND_CMDIO_LINE  "Unbekannter SITE Befehl."
#define FTP_BAD_SITE_CHMOD_CMDIO_LINE "SITE CHMOD benoetigt 2 Argumente."
#define FTP_FAIL_SITE_CHMOD_CMDIO_LINE "SITE CHMOD Befehl fehlgeschlagen."
#define FTP_OK_SITE_CHMOD_CMDIO_LINE "SITE CHMOD Befehl OK."
#define FTP_OK_UMASK_READ_CMDIO_LINE "Ihre aktuelle UMASK ist "
#define FTP_OK_UMASK_WRITE_CMDIO_LINE "UMASK gesetzt auf "
#define FTP_FAIL_SET_CTIME_CMDIO_LINE "Konnte Aenderungszeitpunkt der Datei nicht setzen."
#define FTP_OK_SET_CTIME_CMDIO_LINE "Aenderungszeitpunkt der Datei gesetzt."
#define FTP_FAIL_READ_CTIME_CMDIO_LINE "Konnte Aenderungszeitpunkt der Datei nicht lesen."
#define FTP_BAD_EPRT_CMDIO_LINE "Falsches EPRT Protokoll."
#define FTP_BAD_EPRT_COMMAND_CMDIO_LINE "Ungueltiger EPRT Befehl."
#define FTP_OK_EPRT_COMMAND_CMDIO_LINE "EPRT Befehl erfolgreich. Benutze besser EPSV."
#define FTP_HELP_HEADER_CMDIO_LINE "Die folgenden Befehle werde unterstuetzt."
#define FTP_HELP_OK_CMDIO_LINE "Hilfe OK."
#define FTP_SRV_STATUS_CMDIO_LINE "FTP Server Status:"
#define FTP_SRV_CONNECTED_CMDIO_LINE "     Verbunden von IP: "
#define FTP_SRV_LOGGED_IN_AS_CMDIO_LINE "     Angemeldet als: "
#define FTP_SRV_MODE_CMDIO_LINE "     Modus: "
#define FTP_SHOW_SPEEDLIMIT_WITHOUT_CMDIO_LINE "     Kein Geschwindigkeitslimit\r\n"
#define FTP_SHOW_SPEEDLIMIT_LIMIT_CMDIO_LINE "     Geschwindigkeitslimit in byte/s ist "
#define FTP_SHOW_TIMEOUT_NO_CMDIO_LINE "     Kein Timeout\r\n"
#define FTP_SHOW_TIMEOUT_YES_CMDIO_LINE "     Timeout in Sekunden ist "
#define FTP_SHOW_COMMAND_IS_CRYPT "     Befehle werden verschluesselt uebertragen\r\n"
#define FTP_SHOW_COMMAND_NO_CRYPT "     Befehle werden NICHT verschluesselt uebertragen\r\n"
#define FTP_SHOW_DATA_IS_CRYPT "     Dateien werden verschluesselt uebertragen\r\n"
#define FTP_SHOW_DATA_NO_CRYPT  "     Dateien werden NICHT verschluesselt uebertragen\r\n"
#define FTP_SHOW_DATA_NEED_CRYPT "Datenuebertragung muss verschluesselt sein"
#define FTP_SHOW_LOGGEND_ON_WHILE_LOGIN "     Beim Verbindungsaufbau waren "
#define FTP_SHOW_LOGGEND_ON_WHILE_LOGIN2 " Benutzer verbunden\r\n"
#define FTP_VSFTPD_TAIL " - 20150730\r\n"
#define FTP_SHOW_END_OF_STATUS "Ende des Status"
#define FTP_USE_FIRST_CMDIO_LINE "Benutze PORT oder PASV zuerst."
#define FTP_NO_CHANGE_FROM_GUEST "Kein Wechsel vom Gast Benutzer moeglich."
#define FTP_GIVE_ANY_PW "Jedes beliebige Passwort ist ok."
#define FTP_COULD_NOT_CHANGE_USER "Kann Benutzer nicht wechseln."
#define FTP_ALREADY_LOGGED_IN "Schon angemeldet."
#define FTP_BAD_CONNECTION_CMDIO_LINE "Konnte keine Verbindung aufbauen. Client Firewall?"
#define FTP_IP_IS_BLOCKED "Ihre IP Adresse wurde gesperrt."
#define FTP_ALWAYS_UFT8_CMDIO_LINE "Verbindung im UFT8 Modus."
#define FTP_BAD_OPTION_CMDIO_LINE "Option nicht verstanden."
#define FTP_FEATURES_STRING_CMDIO_LINE "Funktionen:"
#define FTP_SSL_HANDSHAKE_FAILED "Verbindungsaushandlung fehlgeschlagen: "
#define FTP_SSL_CONTINUE "Fortfahren mit Verbindungsaushandlung."
#define FTP_UNKNOWN_AUTH_CMDIO_LINE "Unbekannter AUTH Typ."
#define FTP_SSL_PBSZ_REQUIRE "PBSZ benoetigt eine sichere Verbindung."
#define FTP_SSL_PBSZ_ZERO "PBSZ auf 0 gesetzt."
#define FTP_SSL_PROT_REQUIRE "PROT benoetigt eine sichere Verbindung."
#define FTP_SSL_PROT_FREE "PROT jetzt Frei."
#define FTP_SSL_PROT_PRIVATE "PROT jetzt Privat."
#define FTP_SSL_PROT_NOT "PROT nicht unterstuetzt."
#define FTP_SSL_PROT_UNKNOWN "PROT nicht erkannt."
#define FTP_INPUT_LINE_LONG_CMDIO_LINE "Input line too long."
#define FTP_500_STRING "500 FEHLER: "
#define FTP_500_SIZE 12 //the number of chars of the FTP_500_STRING
#define FTP_SSL_FAILED_1 "SSL Verbindung fehlgeschlagen!"
#define FTP_SSL_FAILED_2 " Bitten verwenden Sie einen Client der SSL Session reuse beherrscht."
#define FTP_SSL_FAILED_3 " Siehe require_ssl_reuse Option in vsftpd.conf"
#define FTP_DATA_NAME "Daten"
#define FTP_CONTROL_NAME "Kontrol"
#define FTP_SSL_CONNECTION_FAILED1 " Verbindung ohne SSL Shutdown beendet."
#define FTP_SSL_CONNECTION_FAILED2 " Fehlerhafter Client! Integritaet der gesendeten Daten kann nicht sichergestellt werden."
#define FTP_SECUTIL_LOCATE_USER "Konnte Benutzer nicht finden:"
#define FTP_SECUTIL_NOT_RUNNING_ROOT "vsf_secutil_change_credentials: wurde nicht als root gestartet"
#define FTP_SECUTIL_CANNOT_CHDIR "Konnte Verzeichnis nicht wechseln:"
