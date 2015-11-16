/*
 * Part of Very Secure FTPd
 * Licence: GPL v2
 * Author: Chris Evans
 * postlogin.c
 */

#include "postlogin.h"
#include "session.h"
#include "oneprocess.h"
#include "twoprocess.h"
#include "ftpcodes.h"
#include "ftpcmdio.h"
#include "ftpdataio.h"
#include "utility.h"
#include "tunables.h"
#include "defs.h"
#include "str.h"
#include "sysstr.h"
#include "banner.h"
#include "sysutil.h"
#include "logging.h"
#include "sysdeputil.h"
#include "ipaddrparse.h"
#include "access.h"
#include "features.h"
#include "ssl.h"
#include "vsftpver.h"
#include "opts.h"
#include "locales.h"

/* Private local functions */
static void handle_pwd(struct vsf_session* p_sess);
static void handle_cwd(struct vsf_session* p_sess);
static void handle_pasv(struct vsf_session* p_sess, int is_epsv);
static void handle_retr(struct vsf_session* p_sess, int is_http);
static void handle_cdup(struct vsf_session* p_sess);
static void handle_list(struct vsf_session* p_sess);
static void handle_type(struct vsf_session* p_sess);
static void handle_port(struct vsf_session* p_sess);
static void handle_stor(struct vsf_session* p_sess);
static void handle_mkd(struct vsf_session* p_sess);
static void handle_rmd(struct vsf_session* p_sess);
static void handle_dele(struct vsf_session* p_sess);
static void handle_rest(struct vsf_session* p_sess);
static void handle_rnfr(struct vsf_session* p_sess);
static void handle_rnto(struct vsf_session* p_sess);
static void handle_nlst(struct vsf_session* p_sess);
static void handle_size(struct vsf_session* p_sess);
static void handle_site(struct vsf_session* p_sess);
static void handle_appe(struct vsf_session* p_sess);
static void handle_mdtm(struct vsf_session* p_sess);
static void handle_site_chmod(struct vsf_session* p_sess,
                              struct mystr* p_arg_str);
static void handle_site_umask(struct vsf_session* p_sess,
                              struct mystr* p_arg_str);
static void handle_eprt(struct vsf_session* p_sess);
static void handle_help(struct vsf_session* p_sess);
static void handle_stou(struct vsf_session* p_sess);
static void handle_stat(struct vsf_session* p_sess);
static void handle_stat_file(struct vsf_session* p_sess);
static void handle_logged_in_user(struct vsf_session* p_sess);
static void handle_logged_in_pass(struct vsf_session* p_sess);
static void handle_http(struct vsf_session* p_sess);

static int pasv_active(struct vsf_session* p_sess);
static int port_active(struct vsf_session* p_sess);
static void pasv_cleanup(struct vsf_session* p_sess);
static void port_cleanup(struct vsf_session* p_sess);
static void handle_dir_common(struct vsf_session* p_sess, int full_details,
                              int stat_cmd);
static void prepend_path_to_filename(struct mystr* p_str);
static int get_remote_transfer_fd(struct vsf_session* p_sess,
                                  const char* p_status_msg);
static void check_abor(struct vsf_session* p_sess);
static void handle_sigurg(void* p_private);
static void handle_upload_common(struct vsf_session* p_sess, int is_append,
                                 int is_unique);
static void get_unique_filename(struct mystr* p_outstr,
                                const struct mystr* p_base);
static int data_transfer_checks_ok(struct vsf_session* p_sess);
static void resolve_tilde(struct mystr* p_str, struct vsf_session* p_sess);

void
process_post_login(struct vsf_session* p_sess)
{
  str_getcwd(&p_sess->home_str);
  if (p_sess->is_anonymous)
  {
    vsf_sysutil_set_umask(tunable_anon_umask);
    p_sess->bw_rate_max = tunable_anon_max_rate;
  }
  else
  {
    vsf_sysutil_set_umask(tunable_local_umask);
    p_sess->bw_rate_max = tunable_local_max_rate;
  }
  if (p_sess->is_http)
  {
    handle_http(p_sess);
    bug("should not be reached");
  }

  /* Don't support async ABOR if we have an SSL channel. The spec says SHOULD
   * NOT, and I think there are synchronization issues between command and
   * data reads.
   */
  if (tunable_async_abor_enable && !p_sess->control_use_ssl)
  {
    vsf_sysutil_install_sighandler(kVSFSysUtilSigURG, handle_sigurg, p_sess, 0);
    vsf_sysutil_activate_sigurg(VSFTP_COMMAND_FD);
  }
  /* Handle any login message */
  vsf_banner_dir_changed(p_sess, FTP_LOGINOK);
  vsf_cmdio_write(p_sess, FTP_LOGINOK, FTP_LOGIN_VALID);

  while(1)
  {
    int cmd_ok = 1;
    if (tunable_setproctitle_enable)
    {
      vsf_sysutil_setproctitle("IDLE");
    }
    /* Blocks */
    vsf_cmdio_get_cmd_and_arg(p_sess, &p_sess->ftp_cmd_str,
                              &p_sess->ftp_arg_str, 1);
    if (tunable_setproctitle_enable)
    {
      struct mystr proctitle_str = INIT_MYSTR;
      str_copy(&proctitle_str, &p_sess->ftp_cmd_str);
      if (!str_isempty(&p_sess->ftp_arg_str))
      {
        str_append_char(&proctitle_str, ' ');
        str_append_str(&proctitle_str, &p_sess->ftp_arg_str);
      }
      /* Suggestion from Solar */
      str_replace_unprintable(&proctitle_str, '?');
      vsf_sysutil_setproctitle_str(&proctitle_str);
      str_free(&proctitle_str);
    }
    /* Test command against the allowed lists.. */
    if (tunable_cmds_allowed)
    {
      static struct mystr s_src_str;
      static struct mystr s_rhs_str;
      str_alloc_text(&s_src_str, tunable_cmds_allowed);
      while (1)
      {
        str_split_char(&s_src_str, &s_rhs_str, ',');
        if (str_isempty(&s_src_str))
        {
          cmd_ok = 0;
          break;
        }
        else if (str_equal(&s_src_str, &p_sess->ftp_cmd_str))
        {
          break;
        }
        str_copy(&s_src_str, &s_rhs_str);
      }
    }
    if (tunable_cmds_denied)
    {
      static struct mystr s_src_str;
      static struct mystr s_rhs_str;
      str_alloc_text(&s_src_str, tunable_cmds_denied);
      while (1)
      {
        str_split_char(&s_src_str, &s_rhs_str, ',');
        if (str_isempty(&s_src_str))
        {
          break;
        }
        else if (str_equal(&s_src_str, &p_sess->ftp_cmd_str))
        {
          cmd_ok = 0;
          break;
        }
        str_copy(&s_src_str, &s_rhs_str);
      }
    }
    if (!cmd_ok)
    {
      vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "QUIT"))
    {
      vsf_cmdio_write_exit(p_sess, FTP_GOODBYE, FTP_GOODBYE_CMDIO_LINE, 0);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "PWD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "XPWD"))
    {
      handle_pwd(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "CWD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "XCWD"))
    {
      handle_cwd(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "CDUP") ||
             str_equal_text(&p_sess->ftp_cmd_str, "XCUP"))
    {
      handle_cdup(p_sess);
    }
    else if (tunable_pasv_enable &&
             !p_sess->epsv_all &&
             (str_equal_text(&p_sess->ftp_cmd_str, "PASV") ||
              str_equal_text(&p_sess->ftp_cmd_str, "P@SW")))
    {
      handle_pasv(p_sess, 0);
    }
    else if (tunable_pasv_enable &&
             str_equal_text(&p_sess->ftp_cmd_str, "EPSV"))
    {
      handle_pasv(p_sess, 1);
    }
    else if (tunable_download_enable &&
             str_equal_text(&p_sess->ftp_cmd_str, "RETR"))
    {
      handle_retr(p_sess, 0);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "NOOP"))
    {
      vsf_cmdio_write(p_sess, FTP_NOOPOK, "NOOP ok.");
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "SYST"))
    {
      vsf_cmdio_write(p_sess, FTP_SYSTOK, "UNIX Type: L8");
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "HELP"))
    {
      handle_help(p_sess);
    }
    else if (tunable_dirlist_enable &&
             str_equal_text(&p_sess->ftp_cmd_str, "LIST"))
    {
      handle_list(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "TYPE"))
    {
      handle_type(p_sess);
    }
    else if (tunable_port_enable &&
             !p_sess->epsv_all &&
             str_equal_text(&p_sess->ftp_cmd_str, "PORT"))
    {
      handle_port(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_upload_enable || !p_sess->is_anonymous) &&
             str_equal_text(&p_sess->ftp_cmd_str, "STOR"))
    {
      handle_stor(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_mkdir_write_enable || !p_sess->is_anonymous) &&
             (str_equal_text(&p_sess->ftp_cmd_str, "MKD") ||
              str_equal_text(&p_sess->ftp_cmd_str, "XMKD")))
    {
      handle_mkd(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_other_write_enable || !p_sess->is_anonymous) &&
             (str_equal_text(&p_sess->ftp_cmd_str, "RMD") ||
              str_equal_text(&p_sess->ftp_cmd_str, "XRMD")))
    {
      handle_rmd(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_other_write_enable || !p_sess->is_anonymous) &&
             str_equal_text(&p_sess->ftp_cmd_str, "DELE"))
    {
      handle_dele(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "REST"))
    {
      handle_rest(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_other_write_enable || !p_sess->is_anonymous) &&
             str_equal_text(&p_sess->ftp_cmd_str, "RNFR"))
    {
      handle_rnfr(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_other_write_enable || !p_sess->is_anonymous) &&
             str_equal_text(&p_sess->ftp_cmd_str, "RNTO"))
    {
      handle_rnto(p_sess);
    }
    else if (tunable_dirlist_enable &&
             str_equal_text(&p_sess->ftp_cmd_str, "NLST"))
    {
      handle_nlst(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "SIZE"))
    {
      handle_size(p_sess);
    }
    else if (!p_sess->is_anonymous &&
             str_equal_text(&p_sess->ftp_cmd_str, "SITE"))
    {
      handle_site(p_sess);
    }
    /* Note - the weird ABOR string is checking for an async ABOR arriving
     * without a SIGURG condition.
     */
    else if (str_equal_text(&p_sess->ftp_cmd_str, "ABOR") ||
             str_equal_text(&p_sess->ftp_cmd_str, "\377\364\377\362ABOR"))
    {
      vsf_cmdio_write(p_sess, FTP_ABOR_NOCONN, FTP_NOTHING_TO_ABOR);
    }
    else if (tunable_write_enable &&
             (tunable_anon_other_write_enable || !p_sess->is_anonymous) &&
             str_equal_text(&p_sess->ftp_cmd_str, "APPE"))
    {
      handle_appe(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "MDTM"))
    {
      handle_mdtm(p_sess);
    }
    else if (tunable_port_enable &&
             str_equal_text(&p_sess->ftp_cmd_str, "EPRT"))
    {
      handle_eprt(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "STRU"))
    {
      str_upper(&p_sess->ftp_arg_str);
      if (str_equal_text(&p_sess->ftp_arg_str, "F"))
      {
        vsf_cmdio_write(p_sess, FTP_STRUOK, FTP_STRUOK_CMDIO_LINE);
      }
      else
      {
        vsf_cmdio_write(p_sess, FTP_BADSTRU, FTP_BAD_STRU_CMDIO_LINE);
      }
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "MODE"))
    {
      str_upper(&p_sess->ftp_arg_str);
      if (str_equal_text(&p_sess->ftp_arg_str, "S"))
      {
        vsf_cmdio_write(p_sess, FTP_MODEOK, FTP_MODE_OK_CMDIO_LINE);
      }
      else
      {
        vsf_cmdio_write(p_sess, FTP_BADMODE, FTP_MODE_BAD_CMDIO_LINE);
      }
    }
    else if (tunable_write_enable &&
             (tunable_anon_upload_enable || !p_sess->is_anonymous) &&
             str_equal_text(&p_sess->ftp_cmd_str, "STOU"))
    {
      handle_stou(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "ALLO"))
    {
      vsf_cmdio_write(p_sess, FTP_ALLOOK, FTP_ALLO_CMDIO_LINE);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "REIN"))
    {
      vsf_cmdio_write(p_sess, FTP_COMMANDNOTIMPL, FTP_REIN_CMDIO_LINE);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "ACCT"))
    {
      vsf_cmdio_write(p_sess, FTP_COMMANDNOTIMPL, FTP_ACCT_CMDIO_LINE);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "SMNT"))
    {
      vsf_cmdio_write(p_sess, FTP_COMMANDNOTIMPL, FTP_SMNT_CMDIO_LINE);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "FEAT"))
    {
      handle_feat(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "OPTS"))
    {
      handle_opts(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "STAT") &&
             str_isempty(&p_sess->ftp_arg_str))
    {
      handle_stat(p_sess);
    }
    else if (tunable_dirlist_enable &&
             str_equal_text(&p_sess->ftp_cmd_str, "STAT"))
    {
      handle_stat_file(p_sess);
    }
    else if (tunable_ssl_enable && str_equal_text(&p_sess->ftp_cmd_str, "PBSZ"))
    {
      handle_pbsz(p_sess);
    }
    else if (tunable_ssl_enable && str_equal_text(&p_sess->ftp_cmd_str, "PROT"))
    {
      handle_prot(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "USER"))
    {
      handle_logged_in_user(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "PASS"))
    {
      handle_logged_in_pass(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "PASV") ||
             str_equal_text(&p_sess->ftp_cmd_str, "PORT") ||
             str_equal_text(&p_sess->ftp_cmd_str, "STOR") ||
             str_equal_text(&p_sess->ftp_cmd_str, "MKD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "XMKD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "RMD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "XRMD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "DELE") ||
             str_equal_text(&p_sess->ftp_cmd_str, "RNFR") ||
             str_equal_text(&p_sess->ftp_cmd_str, "RNTO") ||
             str_equal_text(&p_sess->ftp_cmd_str, "SITE") ||
             str_equal_text(&p_sess->ftp_cmd_str, "APPE") ||
             str_equal_text(&p_sess->ftp_cmd_str, "EPSV") ||
             str_equal_text(&p_sess->ftp_cmd_str, "EPRT") ||
             str_equal_text(&p_sess->ftp_cmd_str, "RETR") ||
             str_equal_text(&p_sess->ftp_cmd_str, "LIST") ||
             str_equal_text(&p_sess->ftp_cmd_str, "NLST") ||
             str_equal_text(&p_sess->ftp_cmd_str, "STOU") ||
             str_equal_text(&p_sess->ftp_cmd_str, "ALLO") ||
             str_equal_text(&p_sess->ftp_cmd_str, "REIN") ||
             str_equal_text(&p_sess->ftp_cmd_str, "ACCT") ||
             str_equal_text(&p_sess->ftp_cmd_str, "SMNT") ||
             str_equal_text(&p_sess->ftp_cmd_str, "FEAT") ||
             str_equal_text(&p_sess->ftp_cmd_str, "OPTS") ||
             str_equal_text(&p_sess->ftp_cmd_str, "STAT") ||
             str_equal_text(&p_sess->ftp_cmd_str, "PBSZ") ||
             str_equal_text(&p_sess->ftp_cmd_str, "PROT"))
    {
      vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    }
    else if (str_isempty(&p_sess->ftp_cmd_str) &&
             str_isempty(&p_sess->ftp_arg_str))
    {
      /* Deliberately ignore to avoid NAT device bugs. ProFTPd does the same. */
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "GET") ||
             str_equal_text(&p_sess->ftp_cmd_str, "POST") ||
             str_equal_text(&p_sess->ftp_cmd_str, "HEAD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "OPTIONS") ||
             str_equal_text(&p_sess->ftp_cmd_str, "CONNECT"))
    {
      vsf_cmdio_write_exit(p_sess, FTP_BADCMD,
                           "HTTP protocol commands not allowed.", 1);
    }
    else
    {
      vsf_cmdio_write(p_sess, FTP_BADCMD, FTP_BAD_COMMAND);
    }
    if (vsf_log_entry_pending(p_sess))
    {
      vsf_log_do_log(p_sess, 0);
    }
    if (p_sess->data_timeout)
    {
      vsf_cmdio_write_exit(p_sess, FTP_DATA_TIMEOUT,
                           FTP_DATA_TIMEOUT_CMDIO_LINE, 1);
    }
  }
}

static void
handle_pwd(struct vsf_session* p_sess)
{
  static struct mystr s_cwd_buf_mangle_str;
  static struct mystr s_pwd_res_str;
  str_getcwd(&s_cwd_buf_mangle_str);
  /* Double up any double-quotes in the pathname! */
  str_replace_text(&s_cwd_buf_mangle_str, "\"", "\"\"");
  /* Enclose pathname in quotes */
  str_alloc_text(&s_pwd_res_str, "\"");
  str_append_str(&s_pwd_res_str, &s_cwd_buf_mangle_str);
  str_append_text(&s_pwd_res_str, FTP_PWD_TAIL);
  vsf_cmdio_write_str(p_sess, FTP_PWDOK, &s_pwd_res_str);
}

static void
handle_cwd(struct vsf_session* p_sess)
{
  int retval;
  resolve_tilde(&p_sess->ftp_arg_str, p_sess);
  if (!vsf_access_check_file(&p_sess->ftp_arg_str))
  {
    vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    return;
  }
  retval = str_chdir(&p_sess->ftp_arg_str);
  if (retval == 0)
  {
    /* Handle any messages */
    vsf_banner_dir_changed(p_sess, FTP_CWDOK);
    vsf_cmdio_write(p_sess, FTP_CWDOK, FTP_CHANGE_DIR_OK_CMDIO_LINE);
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, FTP_CHANGE_DIR_FAIL_CMDIO_LINE);
  }
}

static void
handle_cdup(struct vsf_session* p_sess)
{
  str_alloc_text(&p_sess->ftp_arg_str, "..");
  handle_cwd(p_sess);
}

static int
port_active(struct vsf_session* p_sess)
{
  int ret = 0;
  if (p_sess->p_port_sockaddr != 0)
  {
    ret = 1;
    if (pasv_active(p_sess))
    {
      bug("port and pasv both active");
    }
  }
  return ret;
}

static int
pasv_active(struct vsf_session* p_sess)
{
  int ret = 0;
  if (tunable_one_process_model)
  {
    ret = vsf_one_process_pasv_active(p_sess);
  }
  else
  {
    ret = vsf_two_process_pasv_active(p_sess);
  }
  if (ret)
  {
    if (port_active(p_sess))
    {
      bug("pasv and port both active");
    }
  }
  return ret;
}

static void
port_cleanup(struct vsf_session* p_sess)
{
  vsf_sysutil_sockaddr_clear(&p_sess->p_port_sockaddr);
}

static void
pasv_cleanup(struct vsf_session* p_sess)
{
  if (tunable_one_process_model)
  {
    vsf_one_process_pasv_cleanup(p_sess);
  }
  else
  {
    vsf_two_process_pasv_cleanup(p_sess);
  }
}

static void
handle_pasv(struct vsf_session* p_sess, int is_epsv)
{
  unsigned short the_port;
  static struct mystr s_pasv_res_str;
  static struct vsf_sysutil_sockaddr* s_p_sockaddr;
  int is_ipv6 = vsf_sysutil_sockaddr_is_ipv6(p_sess->p_local_addr);
  if (is_epsv && !str_isempty(&p_sess->ftp_arg_str))
  {
    int argval;
    str_upper(&p_sess->ftp_arg_str);
    if (str_equal_text(&p_sess->ftp_arg_str, "ALL"))
    {
      p_sess->epsv_all = 1;
      vsf_cmdio_write(p_sess, FTP_EPSVALLOK, "EPSV ALL ok.");
      return;
    }
    argval = vsf_sysutil_atoi(str_getbuf(&p_sess->ftp_arg_str));
    if (argval < 1 || argval > 2 || (!is_ipv6 && argval == 2))
    {
      vsf_cmdio_write(p_sess, FTP_EPSVBAD, FTP_BAD_EPS_CMDIO_LINE);
      return;
    }
  }
  pasv_cleanup(p_sess);
  port_cleanup(p_sess);
  if (tunable_one_process_model)
  {
    the_port = vsf_one_process_listen(p_sess);
  }
  else
  {
    the_port = vsf_two_process_listen(p_sess);
  }
  if (is_epsv)
  {
    str_alloc_text(&s_pasv_res_str, FTP_START_PASS_EX_CMDIO_LINE);
    str_append_ulong(&s_pasv_res_str, (unsigned long) the_port);
    str_append_text(&s_pasv_res_str, "|).");
    vsf_cmdio_write_str(p_sess, FTP_EPSVOK, &s_pasv_res_str);
    return;
  }
  if (tunable_pasv_address != 0)
  {
    vsf_sysutil_sockaddr_alloc_ipv4(&s_p_sockaddr);
    /* Report passive address as specified in configuration */
    if (vsf_sysutil_inet_aton(tunable_pasv_address, s_p_sockaddr) == 0)
    {
      die("invalid pasv_address");
    }
  }
  else
  {
    vsf_sysutil_sockaddr_clone(&s_p_sockaddr, p_sess->p_local_addr);
  }
  str_alloc_text(&s_pasv_res_str, FTP_START_PASS_CMDIO_LINE);
  if (!is_ipv6)
  {
    str_append_text(&s_pasv_res_str, vsf_sysutil_inet_ntop(s_p_sockaddr));
  }
  else
  {
    const void* p_v4addr = vsf_sysutil_sockaddr_ipv6_v4(s_p_sockaddr);
    if (p_v4addr)
    {
      str_append_text(&s_pasv_res_str, vsf_sysutil_inet_ntoa(p_v4addr));
    }
    else
    {
      str_append_text(&s_pasv_res_str, "0,0,0,0");
    }
  }
  str_replace_char(&s_pasv_res_str, '.', ',');
  str_append_text(&s_pasv_res_str, ",");
  str_append_ulong(&s_pasv_res_str, the_port >> 8);
  str_append_text(&s_pasv_res_str, ",");
  str_append_ulong(&s_pasv_res_str, the_port & 255);
  str_append_text(&s_pasv_res_str, ").");
  vsf_cmdio_write_str(p_sess, FTP_PASVOK, &s_pasv_res_str);
}

static void
handle_retr(struct vsf_session* p_sess, int is_http)
{
  static struct mystr s_mark_str;
  static struct vsf_sysutil_statbuf* s_p_statbuf;
  struct vsf_transfer_ret trans_ret;
  int remote_fd;
  int opened_file;
  int is_ascii = 0;
  filesize_t offset = p_sess->restart_pos;
  p_sess->restart_pos = 0;
  if (!is_http && !data_transfer_checks_ok(p_sess))
  {
    return;
  }
  if (p_sess->is_ascii && offset != 0)
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL,
                    FTP_NO_ASCII_RETURN);
    return;
  }
  resolve_tilde(&p_sess->ftp_arg_str, p_sess);
  vsf_log_start_entry(p_sess, kVSFLogEntryDownload);
  str_copy(&p_sess->log_str, &p_sess->ftp_arg_str);
  prepend_path_to_filename(&p_sess->log_str);
  if (!vsf_access_check_file(&p_sess->ftp_arg_str))
  {
    vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    return;
  }
  opened_file = str_open(&p_sess->ftp_arg_str, kVSFSysStrOpenReadOnly);
  if (vsf_sysutil_retval_is_error(opened_file))
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, FTP_OPEN_FILE_FAIL_CMDIO_LINE);
    return;
  }
  /* Lock file if required */
  if (tunable_lock_upload_files)
  {
    vsf_sysutil_lock_file_read(opened_file);
  }
  vsf_sysutil_fstat(opened_file, &s_p_statbuf);
  /* No games please */
  if (!vsf_sysutil_statbuf_is_regfile(s_p_statbuf))
  {
    /* Note - pretend open failed */
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, FTP_OPEN_FILE_FAIL_CMDIO_LINE);
    /* Irritating FireFox does RETR on directories, so avoid logging this
     * very common and noisy case.
     */
    if (vsf_sysutil_statbuf_is_dir(s_p_statbuf))
    {
      vsf_log_clear_entry(p_sess);
    }
    goto file_close_out;
  }
  /* Now deactive O_NONBLOCK, otherwise we have a problem on DMAPI filesystems
   * such as XFS DMAPI.
   */
  vsf_sysutil_deactivate_noblock(opened_file);
  /* Optionally, we'll be paranoid and only serve publicly readable stuff */
  if (p_sess->is_anonymous && tunable_anon_world_readable_only &&
      !vsf_sysutil_statbuf_is_readable_other(s_p_statbuf))
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, FTP_OPEN_FILE_FAIL_CMDIO_LINE);
    goto file_close_out;
  }
  /* Set the download offset (from REST) if any */
  if (offset != 0)
  {
    vsf_sysutil_lseek_to(opened_file, offset);
  }
  str_alloc_text(&s_mark_str, FTP_STRING_OPEN);
  if (tunable_ascii_download_enable && p_sess->is_ascii)
  {
    str_append_text(&s_mark_str, "ASCII");
    is_ascii = 1;
  }
  else
  {
    str_append_text(&s_mark_str, "BINARY");
  }
  str_append_text(&s_mark_str, FTP_MODE_FOR_FILE_CMDIO_LINE);
  str_append_str(&s_mark_str, &p_sess->ftp_arg_str);
  str_append_text(&s_mark_str, " (");
  str_append_filesize_t(&s_mark_str,
                        vsf_sysutil_statbuf_get_size(s_p_statbuf));
  str_append_text(&s_mark_str, " bytes).");
  if (is_http)
  {
    remote_fd = VSFTP_COMMAND_FD;
  }
  else
  {
    remote_fd = get_remote_transfer_fd(p_sess, str_getbuf(&s_mark_str));
    if (vsf_sysutil_retval_is_error(remote_fd))
    {
      goto port_pasv_cleanup_out;
    }
  }
  trans_ret = vsf_ftpdataio_transfer_file(p_sess, remote_fd,
                                          opened_file, 0, is_ascii);
  if (!is_http &&
      vsf_ftpdataio_dispose_transfer_fd(p_sess) != 1 &&
      trans_ret.retval == 0)
  {
    trans_ret.retval = -2;
  }
  p_sess->transfer_size = trans_ret.transferred;
  /* Log _after_ the blocking dispose call, so we get transfer times right */
  if (trans_ret.retval == 0)
  {
    vsf_log_do_log(p_sess, 1);
  }
  if (is_http)
  {
    goto file_close_out;
  }
  /* Emit status message _after_ blocking dispose call to avoid buggy FTP
   * clients truncating the transfer.
   */
  if (trans_ret.retval == -1)
  {
    vsf_cmdio_write(p_sess, FTP_BADSENDFILE, FTP_BAD_LOCAL_FILE_CMDIO_LINE);
  }
  else if (trans_ret.retval == -2)
  {
    if (!p_sess->data_timeout)
    {
      vsf_cmdio_write(p_sess, FTP_BADSENDNET,
                      FTP_BAD_NETWORK_WRITE_CMDIO_LINE);
    }
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_TRANSFEROK, FTP_TRANSFER_OK_CMDIO_LINE);
  }
  check_abor(p_sess);
port_pasv_cleanup_out:
  port_cleanup(p_sess);
  pasv_cleanup(p_sess);
file_close_out:
  vsf_sysutil_close(opened_file);
}

static void
handle_list(struct vsf_session* p_sess)
{
  handle_dir_common(p_sess, 1, 0);
}

static void
handle_dir_common(struct vsf_session* p_sess, int full_details, int stat_cmd)
{
  static struct mystr s_option_str;
  static struct mystr s_filter_str;
  static struct mystr s_dir_name_str;
  static struct vsf_sysutil_statbuf* s_p_dirstat;
  int dir_allow_read = 1;
  struct vsf_sysutil_dir* p_dir = 0;
  int retval = 0;
  int use_control = 0;
  str_empty(&s_option_str);
  str_empty(&s_filter_str);
  /* By default open the current directory */
  str_alloc_text(&s_dir_name_str, ".");
  if (!stat_cmd && !data_transfer_checks_ok(p_sess))
  {
    return;
  }
  /* Do we have an option? Going to be strict here - the option must come
   * first. e.g. "ls -a .." fine, "ls .. -a" not fine
   */
  if (!str_isempty(&p_sess->ftp_arg_str) &&
      str_get_char_at(&p_sess->ftp_arg_str, 0) == '-')
  {
    /* Chop off the '-' */
    str_mid_to_end(&p_sess->ftp_arg_str, &s_option_str, 1);
    /* A space will separate options from filter (if any) */
    str_split_char(&s_option_str, &s_filter_str, ' ');
  }
  else
  {
    /* The argument, if any, is just a filter */
    str_copy(&s_filter_str, &p_sess->ftp_arg_str);
  }
  if (!str_isempty(&s_filter_str))
  {
    resolve_tilde(&s_filter_str, p_sess);
    if (!vsf_access_check_file(&s_filter_str))
    {
      vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
      return;
    }
    /* First check - is it an outright directory, as in "ls /pub" */
    p_dir = str_opendir(&s_filter_str);
    if (p_dir != 0)
    {
      /* Listing a directory! */
      str_copy(&s_dir_name_str, &s_filter_str);
      str_free(&s_filter_str);
    }
    else
    {
      struct str_locate_result locate_result =
        str_locate_char(&s_filter_str, '/');
      if (locate_result.found)
      {
        /* Includes a path! Reverse scan for / in the arg, to get the
         * base directory and filter (if any)
         */
        str_copy(&s_dir_name_str, &s_filter_str);
        str_split_char_reverse(&s_dir_name_str, &s_filter_str, '/');
        /* If we have e.g. "ls /.message", we just ripped off the leading
         * slash because it is the only one!
         */
        if (str_isempty(&s_dir_name_str))
        {
          str_alloc_text(&s_dir_name_str, "/");
        }
      }
    }
  }
  if (p_dir == 0)
  {
    /* NOTE - failure check done below, it's not forgotten */
    p_dir = str_opendir(&s_dir_name_str);
  }
  /* Fine, do it */
  if (stat_cmd)
  {
    use_control = 1;
    str_append_char(&s_option_str, 'a');
    vsf_cmdio_write_hyphen(p_sess, FTP_STATFILE_OK, FTP_GIVE_STATUS_CMDIO_LINE);
  }
  else
  {
    int remote_fd = get_remote_transfer_fd(
      p_sess, FTP_DIRLISTING_ANNOUNCEMENT_CMDIO_LINE);
    if (vsf_sysutil_retval_is_error(remote_fd))
    {
      goto dir_close_out;
    }
  }
  if (p_sess->is_anonymous && p_dir && tunable_anon_world_readable_only)
  {
    vsf_sysutil_dir_stat(p_dir, &s_p_dirstat);
    if (!vsf_sysutil_statbuf_is_readable_other(s_p_dirstat))
    {
      dir_allow_read = 0;
    }
  }
  if (p_dir != 0 && dir_allow_read)
  {
    retval = vsf_ftpdataio_transfer_dir(p_sess, use_control, p_dir,
                                        &s_dir_name_str, &s_option_str,
                                        &s_filter_str, full_details);
  }
  if (!stat_cmd)
  {
    if (vsf_ftpdataio_dispose_transfer_fd(p_sess) != 1 && retval == 0)
    {
      retval = -1;
    }
  }
  if (stat_cmd)
  {
    vsf_cmdio_write(p_sess, FTP_STATFILE_OK, FTP_END_STATUS_CMDIO_LINE);
  }
  else if (retval != 0)
  {
    if (!p_sess->data_timeout)
    {
      vsf_cmdio_write(p_sess, FTP_BADSENDNET,
                      FTP_BAD_NETWORK_WRITE_CMDIO_LINE);
    }
  }
  else if (p_dir == 0 || !dir_allow_read)
  {
    vsf_cmdio_write(p_sess, FTP_TRANSFEROK,
                    FTP_TRANSFER_OK_NO_DIR);
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_TRANSFEROK, FTP_DIRLISTING_OK);
  }
  check_abor(p_sess);
dir_close_out:
  if (p_dir)
  {
    vsf_sysutil_closedir(p_dir);
  }
  if (!stat_cmd)
  {
    port_cleanup(p_sess);
    pasv_cleanup(p_sess);
  }
}

static void
handle_type(struct vsf_session* p_sess)
{
  str_upper(&p_sess->ftp_arg_str);
  if (str_equal_text(&p_sess->ftp_arg_str, "I") ||
      str_equal_text(&p_sess->ftp_arg_str, "L8") ||
      str_equal_text(&p_sess->ftp_arg_str, "L 8"))
  {
    p_sess->is_ascii = 0;
    vsf_cmdio_write(p_sess, FTP_TYPEOK, FTP_CHANGE_TO_BINARY);
  }
  else if (str_equal_text(&p_sess->ftp_arg_str, "A") ||
           str_equal_text(&p_sess->ftp_arg_str, "A N"))
  {
    p_sess->is_ascii = 1;
    vsf_cmdio_write(p_sess, FTP_TYPEOK, FTP_CHANGE_TO_ASCII);
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_BADCMD, FTP_UNKNOWN_TYPE);
  }
}

static void
handle_port(struct vsf_session* p_sess)
{
  unsigned short the_port;
  unsigned char vals[6];
  const unsigned char* p_raw;
  pasv_cleanup(p_sess);
  port_cleanup(p_sess);
  p_raw = vsf_sysutil_parse_uchar_string_sep(&p_sess->ftp_arg_str, ',', vals,
                                             sizeof(vals));
  if (p_raw == 0)
  {
    vsf_cmdio_write(p_sess, FTP_BADCMD, FTP_PORT_FAIL_CMDIO_LINE);
    return;
  }
  the_port = (unsigned short) ((vals[4] << 8) | vals[5]);
  vsf_sysutil_sockaddr_clone(&p_sess->p_port_sockaddr, p_sess->p_local_addr);
  vsf_sysutil_sockaddr_set_ipv4addr(p_sess->p_port_sockaddr, vals);
  vsf_sysutil_sockaddr_set_port(p_sess->p_port_sockaddr, the_port);
  /* SECURITY:
   * 1) Reject requests not connecting to the control socket IP
   * 2) Reject connects to privileged ports
   */
  if (!tunable_port_promiscuous)
  {
    if (!vsf_sysutil_sockaddr_addr_equal(p_sess->p_remote_addr,
                                         p_sess->p_port_sockaddr) ||
        vsf_sysutil_is_port_reserved(the_port))
    {
      vsf_cmdio_write(p_sess, FTP_BADCMD, FTP_PORT_FAIL_CMDIO_LINE);
      port_cleanup(p_sess);
      return;
    }
  }
  vsf_cmdio_write(p_sess, FTP_PORTOK,
                  FTP_PORT_OK_PASV_INFO);
}

static void
handle_stor(struct vsf_session* p_sess)
{
  handle_upload_common(p_sess, 0, 0);
}

static void
handle_upload_common(struct vsf_session* p_sess, int is_append, int is_unique)
{
  static struct vsf_sysutil_statbuf* s_p_statbuf;
  static struct mystr s_filename;
  struct mystr* p_filename;
  struct vsf_transfer_ret trans_ret;
  int new_file_fd;
  int remote_fd;
  int success = 0;
  int created = 0;
  int do_truncate = 0;
  filesize_t offset = p_sess->restart_pos;
  p_sess->restart_pos = 0;
  if (!data_transfer_checks_ok(p_sess))
  {
    return;
  }
  resolve_tilde(&p_sess->ftp_arg_str, p_sess);
  p_filename = &p_sess->ftp_arg_str;
  if (is_unique)
  {
    get_unique_filename(&s_filename, p_filename);
    p_filename = &s_filename;
  }
  vsf_log_start_entry(p_sess, kVSFLogEntryUpload);
  str_copy(&p_sess->log_str, &p_sess->ftp_arg_str);
  prepend_path_to_filename(&p_sess->log_str);
  if (!vsf_access_check_file(p_filename))
  {
    vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    return;
  }
  /* NOTE - actual file permissions will be governed by the tunable umask */
  /* XXX - do we care about race between create and chown() of anonymous
   * upload?
   */
  if (is_unique || (p_sess->is_anonymous && !tunable_anon_other_write_enable))
  {
    new_file_fd = str_create_exclusive(p_filename);
  }
  else
  {
    /* For non-anonymous, allow open() to overwrite or append existing files */
    new_file_fd = str_create(p_filename);
    if (!is_append && offset == 0)
    {
      do_truncate = 1;
    }
  }
  if (vsf_sysutil_retval_is_error(new_file_fd))
  {
    vsf_cmdio_write(p_sess, FTP_UPLOADFAIL, FTP_UPLOAD_FAIL_NO_FILE_CREATE);
    return;
  }
  created = 1;
  vsf_sysutil_fstat(new_file_fd, &s_p_statbuf);
  if (vsf_sysutil_statbuf_is_regfile(s_p_statbuf))
  {
    /* Now deactive O_NONBLOCK, otherwise we have a problem on DMAPI filesystems
     * such as XFS DMAPI.
     */
    vsf_sysutil_deactivate_noblock(new_file_fd);
  }
  /* Are we required to chown() this file for security? */
  if (p_sess->is_anonymous && tunable_chown_uploads)
  {
    vsf_sysutil_fchmod(new_file_fd, tunable_chown_upload_mode);
    if (tunable_one_process_model)
    {
      vsf_one_process_chown_upload(p_sess, new_file_fd);
    }
    else
    {
      vsf_two_process_chown_upload(p_sess, new_file_fd);
    }
  }
  /* Are we required to lock this file? */
  if (tunable_lock_upload_files)
  {
    vsf_sysutil_lock_file_write(new_file_fd);
  }
  /* Must truncate the file AFTER locking it! */
  if (do_truncate)
  {
    vsf_sysutil_ftruncate(new_file_fd);
    vsf_sysutil_lseek_to(new_file_fd, 0);
  }
  if (!is_append && offset != 0)
  {
    /* XXX - warning, allows seek past end of file! Check for seek > size? */
    vsf_sysutil_lseek_to(new_file_fd, offset);
  }
  else if (is_append)
  {
    vsf_sysutil_lseek_end(new_file_fd);
  }
  if (is_unique)
  {
    struct mystr resp_str = INIT_MYSTR;
    str_alloc_text(&resp_str, FTP_FILE_CMDIO_LINE);
    str_append_str(&resp_str, p_filename);
    remote_fd = get_remote_transfer_fd(p_sess, str_getbuf(&resp_str));
    str_free(&resp_str);
  }
  else
  {
    remote_fd = get_remote_transfer_fd(p_sess, FTP_READY_TO_SEND_CMDIO_LINE);
  }
  if (vsf_sysutil_retval_is_error(remote_fd))
  {
    goto port_pasv_cleanup_out;
  }
  if (tunable_ascii_upload_enable && p_sess->is_ascii)
  {
    trans_ret = vsf_ftpdataio_transfer_file(p_sess, remote_fd,
                                            new_file_fd, 1, 1);
  }
  else
  {
    trans_ret = vsf_ftpdataio_transfer_file(p_sess, remote_fd,
                                            new_file_fd, 1, 0);
  }
  if (vsf_ftpdataio_dispose_transfer_fd(p_sess) != 1 && trans_ret.retval == 0)
  {
    trans_ret.retval = -2;
  }
  p_sess->transfer_size = trans_ret.transferred;
  if (trans_ret.retval == 0)
  {
    success = 1;
    vsf_log_do_log(p_sess, 1);
  }
  if (trans_ret.retval == -1)
  {
    vsf_cmdio_write(p_sess, FTP_BADSENDFILE, FTP_BAD_LOCAL_FILE_WRITE_CMDIO_LINE);
  }
  else if (trans_ret.retval == -2)
  {
    if (!p_sess->data_timeout)
    {
      vsf_cmdio_write(p_sess, FTP_BADSENDNET,
                      FTP_BAD_NETWORK_READ_CMDIO_LINE);
    }
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_TRANSFEROK, FTP_TRANSFER_OK_CMDIO_LINE);
  }
  check_abor(p_sess);
port_pasv_cleanup_out:
  port_cleanup(p_sess);
  pasv_cleanup(p_sess);
  if (tunable_delete_failed_uploads && created && !success)
  {
    str_unlink(p_filename);
  }
  vsf_sysutil_close(new_file_fd);
}

static void
handle_mkd(struct vsf_session* p_sess)
{
  int retval;
  resolve_tilde(&p_sess->ftp_arg_str, p_sess);
  vsf_log_start_entry(p_sess, kVSFLogEntryMkdir);
  str_copy(&p_sess->log_str, &p_sess->ftp_arg_str);
  prepend_path_to_filename(&p_sess->log_str);
  if (!vsf_access_check_file(&p_sess->ftp_arg_str))
  {
    vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    return;
  }
  /* NOTE! Actual permissions will be governed by the tunable umask */
  retval = str_mkdir(&p_sess->ftp_arg_str, 0777);
  if (retval != 0)
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL,
                    FTP_BAD_MKDIR_CMDIO_LINE);
    return;
  }
  vsf_log_do_log(p_sess, 1);
  {
    static struct mystr s_mkd_res;
    static struct mystr s_tmp_str;
    str_copy(&s_tmp_str, &p_sess->ftp_arg_str);
    prepend_path_to_filename(&s_tmp_str);
    /* Double up double quotes */
    str_replace_text(&s_tmp_str, "\"", "\"\"");
    /* Build result string */
    str_alloc_text(&s_mkd_res, "\"");
    str_append_str(&s_mkd_res, &s_tmp_str);
    str_append_text(&s_mkd_res, FTP_CREATED_CMDIO_LINE);
    vsf_cmdio_write_str(p_sess, FTP_MKDIROK, &s_mkd_res);
  }
}

static void
handle_rmd(struct vsf_session* p_sess)
{
  int retval;
  resolve_tilde(&p_sess->ftp_arg_str, p_sess);
  vsf_log_start_entry(p_sess, kVSFLogEntryRmdir);
  str_copy(&p_sess->log_str, &p_sess->ftp_arg_str);
  prepend_path_to_filename(&p_sess->log_str);
  if (!vsf_access_check_file(&p_sess->ftp_arg_str))
  {
    vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    return;
  }
  retval = str_rmdir(&p_sess->ftp_arg_str);
  if (retval != 0)
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL,
                   FTP_BAD_RMDIR_CMDIO_LINE );
  }
  else
  {
    vsf_log_do_log(p_sess, 1);
    vsf_cmdio_write(p_sess, FTP_RMDIROK,
                    FTP_OK_RMDIR_CMDIO_LINE);
  }
}

static void
handle_dele(struct vsf_session* p_sess)
{
  int retval;
  resolve_tilde(&p_sess->ftp_arg_str, p_sess);
  vsf_log_start_entry(p_sess, kVSFLogEntryDelete);
  str_copy(&p_sess->log_str, &p_sess->ftp_arg_str);
  prepend_path_to_filename(&p_sess->log_str);
  if (!vsf_access_check_file(&p_sess->ftp_arg_str))
  {
    vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    return;
  }
  retval = str_unlink(&p_sess->ftp_arg_str);
  if (retval != 0)
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, FTP_BAD_RM_CMDIO_LINE);
  }
  else
  {
    vsf_log_do_log(p_sess, 1);
    vsf_cmdio_write(p_sess, FTP_DELEOK, FTP_OK_RM_CMDIO_LINE);
  }
}

static void
handle_rest(struct vsf_session* p_sess)
{
  static struct mystr s_rest_str;
  filesize_t val = str_a_to_filesize_t(&p_sess->ftp_arg_str);
  if (val < 0)
  {
    val = 0;
  }
  p_sess->restart_pos = val;
  str_alloc_text(&s_rest_str, FTP_RESTART_POS_OK_CMDIO_LINE);
  str_append_filesize_t(&s_rest_str, val);
  str_append_text(&s_rest_str, ").");
  vsf_cmdio_write_str(p_sess, FTP_RESTOK, &s_rest_str);
}

static void
handle_rnfr(struct vsf_session* p_sess)
{
  static struct vsf_sysutil_statbuf* p_statbuf;
  int retval;
  /* Clear old value */
  str_free(&p_sess->rnfr_filename_str);
  resolve_tilde(&p_sess->ftp_arg_str, p_sess);
  if (!vsf_access_check_file(&p_sess->ftp_arg_str))
  {
    vsf_log_start_entry(p_sess, kVSFLogEntryRename);
    str_copy(&p_sess->log_str, &p_sess->ftp_arg_str);
    prepend_path_to_filename(&p_sess->log_str);
    vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    return;
  }
  /* Does it exist? */
  retval = str_stat(&p_sess->ftp_arg_str, &p_statbuf);
  if (retval == 0)
  {
    /* Yes */
    str_copy(&p_sess->rnfr_filename_str, &p_sess->ftp_arg_str);
    vsf_cmdio_write(p_sess, FTP_RNFROK, FTP_READY_FOR_RNTO_CMDIO_LINE);
  }
  else
  {
    vsf_log_start_entry(p_sess, kVSFLogEntryRename);
    str_copy(&p_sess->log_str, &p_sess->ftp_arg_str);
    prepend_path_to_filename(&p_sess->log_str);
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, FTP_BAD_RNFR_CMDIO_LINE);
  }
}

static void
handle_rnto(struct vsf_session* p_sess)
{
  static struct mystr s_tmp_str;
  int retval;
  /* If we didn't get a RNFR, throw a wobbly */
  if (str_isempty(&p_sess->rnfr_filename_str))
  {
    vsf_cmdio_write(p_sess, FTP_NEEDRNFR,
                    FTP_RNFR_FIRST_CMDIO_LINE);
    return;
  }
  resolve_tilde(&p_sess->ftp_arg_str, p_sess);
  vsf_log_start_entry(p_sess, kVSFLogEntryRename);
  str_copy(&p_sess->log_str, &p_sess->rnfr_filename_str);
  prepend_path_to_filename(&p_sess->log_str);
  str_append_char(&p_sess->log_str, ' ');
  str_copy(&s_tmp_str, &p_sess->ftp_arg_str);
  prepend_path_to_filename(&s_tmp_str);
  str_append_str(&p_sess->log_str, &s_tmp_str);
  if (!vsf_access_check_file(&p_sess->ftp_arg_str))
  {
    vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    return;
  }
  /* NOTE - might overwrite destination file. Not a concern because the same
   * could be accomplished with DELE.
   */
  retval = str_rename(&p_sess->rnfr_filename_str, &p_sess->ftp_arg_str);
  /* Clear the RNFR filename; start the two stage process again! */
  str_free(&p_sess->rnfr_filename_str);
  if (retval == 0)
  {
    vsf_log_do_log(p_sess, 1);
    vsf_cmdio_write(p_sess, FTP_RENAMEOK, FTP_OK_RENAME_CMDIO_LINE);
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, FTP_FAIL_RENAME_CMDIO_LINE);
  }
}

static void
handle_nlst(struct vsf_session* p_sess)
{
  handle_dir_common(p_sess, 0, 0);
}

static void
prepend_path_to_filename(struct mystr* p_str)
{
  static struct mystr s_tmp_str;
  /* Only prepend current working directory if the incoming filename is
   * relative
   */
  str_empty(&s_tmp_str);
  if (str_isempty(p_str) || str_get_char_at(p_str, 0) != '/')
  {
    str_getcwd(&s_tmp_str);
    /* Careful to not emit // if we are in directory / (common with chroot) */
    if (str_isempty(&s_tmp_str) ||
        str_get_char_at(&s_tmp_str, str_getlen(&s_tmp_str) - 1) != '/')
    {
      str_append_char(&s_tmp_str, '/');
    }
  }
  str_append_str(&s_tmp_str, p_str);
  str_copy(p_str, &s_tmp_str);
}


static void
handle_sigurg(void* p_private)
{
  struct mystr async_cmd_str = INIT_MYSTR;
  struct mystr async_arg_str = INIT_MYSTR;
  struct mystr real_cmd_str = INIT_MYSTR;
  unsigned int len;
  struct vsf_session* p_sess = (struct vsf_session*) p_private;
  /* Did stupid client sent something OOB without a data connection? */
  if (p_sess->data_fd == -1)
  {
    return;
  }
  /* Get the async command - blocks (use data timeout alarm) */
  vsf_cmdio_get_cmd_and_arg(p_sess, &async_cmd_str, &async_arg_str, 0);
  /* Chop off first four characters; they are telnet characters. The client
   * should have sent the first two normally and the second two as urgent
   * data.
   */
  len = str_getlen(&async_cmd_str);
  if (len >= 4)
  {
    str_right(&async_cmd_str, &real_cmd_str, len - 4);
  }
  if (str_equal_text(&real_cmd_str, "ABOR"))
  {
    p_sess->abor_received = 1;
    /* This is failok because of a small race condition; the SIGURG might
     * be raised after the data socket is closed, but before data_fd is
     * set to -1.
     */
    vsf_sysutil_shutdown_failok(p_sess->data_fd);
  }
  else
  {
    /* Sorry! */
    vsf_cmdio_write(p_sess, FTP_BADCMD, FTP_BAD_COMMAND);
  }
  str_free(&async_cmd_str);
  str_free(&async_arg_str);
  str_free(&real_cmd_str);
}

static int
get_remote_transfer_fd(struct vsf_session* p_sess, const char* p_status_msg)
{
  int remote_fd;
  if (!pasv_active(p_sess) && !port_active(p_sess))
  {
    bug("neither PORT nor PASV active in get_remote_transfer_fd");
  }
  p_sess->abor_received = 0;
  if (pasv_active(p_sess))
  {
    remote_fd = vsf_ftpdataio_get_pasv_fd(p_sess);
  }
  else
  {
    remote_fd = vsf_ftpdataio_get_port_fd(p_sess);
  }
  if (vsf_sysutil_retval_is_error(remote_fd))
  {
    return remote_fd;
  }
  vsf_cmdio_write(p_sess, FTP_DATACONN, p_status_msg);
  if (vsf_ftpdataio_post_mark_connect(p_sess) != 1)
  {
    vsf_ftpdataio_dispose_transfer_fd(p_sess);
    return -1;
  }
  return remote_fd;
}

static void
check_abor(struct vsf_session* p_sess)
{
  /* If the client sent ABOR, respond to it here */
  if (p_sess->abor_received)
  {
    p_sess->abor_received = 0;
    vsf_cmdio_write(p_sess, FTP_ABOROK, FTP_OK_ABOR_CMDIO_LINE);
  }
}

static void
handle_size(struct vsf_session* p_sess)
{
  /* Note - in ASCII mode, are supposed to return the size after taking into
   * account ASCII linefeed conversions. At least this is what wu-ftpd does in
   * version 2.6.1. Proftpd-1.2.0pre fails to do this.
   * I will not do it because it is a potential I/O DoS.
   */
  static struct vsf_sysutil_statbuf* s_p_statbuf;
  int retval;
  resolve_tilde(&p_sess->ftp_arg_str, p_sess);
  if (!vsf_access_check_file(&p_sess->ftp_arg_str))
  {
    vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    return;
  }
  retval = str_stat(&p_sess->ftp_arg_str, &s_p_statbuf);
  if (retval != 0 || !vsf_sysutil_statbuf_is_regfile(s_p_statbuf))
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, FTP_BAD_FILESTAT_CMDIO_LINE);
  }
  else
  {
    static struct mystr s_size_res_str;
    str_alloc_filesize_t(&s_size_res_str,
                         vsf_sysutil_statbuf_get_size(s_p_statbuf));
    vsf_cmdio_write_str(p_sess, FTP_SIZEOK, &s_size_res_str);
  }
}

static void
handle_site(struct vsf_session* p_sess)
{
  static struct mystr s_site_args_str;
  /* What SITE sub-command is it? */
  str_split_char(&p_sess->ftp_arg_str, &s_site_args_str, ' ');
  str_upper(&p_sess->ftp_arg_str);
  if (tunable_write_enable &&
      tunable_chmod_enable &&
      str_equal_text(&p_sess->ftp_arg_str, "CHMOD"))
  {
    handle_site_chmod(p_sess, &s_site_args_str);
  }
  else if (str_equal_text(&p_sess->ftp_arg_str, "UMASK"))
  {
    handle_site_umask(p_sess, &s_site_args_str);
  }
  else if (str_equal_text(&p_sess->ftp_arg_str, "HELP"))
  {
    if (tunable_write_enable &&
        tunable_chmod_enable)
    {
      vsf_cmdio_write(p_sess, FTP_SITEHELP, FTP_SITE_HELP_CHMOD_UMASK);
    }
    else
    {
      vsf_cmdio_write(p_sess, FTP_SITEHELP, FTP_SITE_HELP_UMASK);
    }
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_BADCMD, FTP_BAD_SITE_COMMAND_CMDIO_LINE);
  }
}

static void
handle_site_chmod(struct vsf_session* p_sess, struct mystr* p_arg_str)
{
  static struct mystr s_chmod_file_str;
  unsigned int perms;
  int retval;
  if (str_isempty(p_arg_str))
  {
    vsf_cmdio_write(p_sess, FTP_BADCMD, FTP_BAD_SITE_CHMOD_CMDIO_LINE);
    return;
  }
  str_split_char(p_arg_str, &s_chmod_file_str, ' ');
  if (str_isempty(&s_chmod_file_str))
  {
    vsf_cmdio_write(p_sess, FTP_BADCMD, FTP_BAD_SITE_CHMOD_CMDIO_LINE);
    return;
  }
  resolve_tilde(&s_chmod_file_str, p_sess);
  vsf_log_start_entry(p_sess, kVSFLogEntryChmod);
  str_copy(&p_sess->log_str, &s_chmod_file_str);
  prepend_path_to_filename(&p_sess->log_str);
  str_append_char(&p_sess->log_str, ' ');
  str_append_str(&p_sess->log_str, p_arg_str);
  if (!vsf_access_check_file(&s_chmod_file_str))
  {
    vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    return;
  }
  /* Don't worry - our chmod() implementation only allows 0 - 0777 */
  perms = str_octal_to_uint(p_arg_str);
  retval = str_chmod(&s_chmod_file_str, perms);
  if (vsf_sysutil_retval_is_error(retval))
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, FTP_FAIL_SITE_CHMOD_CMDIO_LINE);
  }
  else
  {
    vsf_log_do_log(p_sess, 1);
    vsf_cmdio_write(p_sess, FTP_CHMODOK, FTP_OK_SITE_CHMOD_CMDIO_LINE);
  }
}

static void
handle_site_umask(struct vsf_session* p_sess, struct mystr* p_arg_str)
{
  static struct mystr s_umask_resp_str;
  if (str_isempty(p_arg_str))
  {
    /* Empty arg => report current umask */
    str_alloc_text(&s_umask_resp_str, FTP_OK_UMASK_READ_CMDIO_LINE);
    str_append_text(&s_umask_resp_str,
                    vsf_sysutil_uint_to_octal(vsf_sysutil_get_umask()));
  }
  else
  {
    /* Set current umask */
    unsigned int new_umask = str_octal_to_uint(p_arg_str);
    vsf_sysutil_set_umask(new_umask);
    str_alloc_text(&s_umask_resp_str, FTP_OK_UMASK_WRITE_CMDIO_LINE);
    str_append_text(&s_umask_resp_str,
                    vsf_sysutil_uint_to_octal(vsf_sysutil_get_umask()));
  }
  vsf_cmdio_write_str(p_sess, FTP_UMASKOK, &s_umask_resp_str);
}

static void
handle_appe(struct vsf_session* p_sess)
{
  handle_upload_common(p_sess, 1, 0);
}

static void
handle_mdtm(struct vsf_session* p_sess)
{
  static struct mystr s_filename_str;
  static struct vsf_sysutil_statbuf* s_p_statbuf;
  int do_write = 0;
  long modtime = 0;
  struct str_locate_result loc = str_locate_char(&p_sess->ftp_arg_str, ' ');
  int retval = str_stat(&p_sess->ftp_arg_str, &s_p_statbuf);
  if (tunable_mdtm_write && retval != 0 && loc.found &&
      vsf_sysutil_isdigit(str_get_char_at(&p_sess->ftp_arg_str, 0)))
  {
    if (loc.index == 8 || loc.index == 14 ||
        (loc.index > 15 && str_get_char_at(&p_sess->ftp_arg_str, 14) == '.'))
    {
      do_write = 1;
    }
  }
  if (do_write != 0)
  {
    str_split_char(&p_sess->ftp_arg_str, &s_filename_str, ' ');
    modtime = vsf_sysutil_parse_time(str_getbuf(&p_sess->ftp_arg_str));
    str_copy(&p_sess->ftp_arg_str, &s_filename_str);
  }
  resolve_tilde(&p_sess->ftp_arg_str, p_sess);
  if (!vsf_access_check_file(&p_sess->ftp_arg_str))
  {
    vsf_cmdio_write(p_sess, FTP_NOPERM, PERMISSION_DENIED);
    return;
  }
  if (do_write && tunable_write_enable &&
      (tunable_anon_other_write_enable || !p_sess->is_anonymous))
  {
    retval = str_stat(&p_sess->ftp_arg_str, &s_p_statbuf);
    if (retval != 0 || !vsf_sysutil_statbuf_is_regfile(s_p_statbuf))
    {
      vsf_cmdio_write(p_sess, FTP_FILEFAIL,
                      FTP_FAIL_SET_CTIME_CMDIO_LINE);
    }
    else
    {
      retval = vsf_sysutil_setmodtime(
        str_getbuf(&p_sess->ftp_arg_str), modtime, tunable_use_localtime);
      if (retval != 0)
      {
        vsf_cmdio_write(p_sess, FTP_FILEFAIL,
                        FTP_FAIL_SET_CTIME_CMDIO_LINE);
      }
      else
      {
        vsf_cmdio_write(p_sess, FTP_MDTMOK,
                        FTP_OK_SET_CTIME_CMDIO_LINE);
      }
    }
  }
  else
  {
    if (retval != 0 || !vsf_sysutil_statbuf_is_regfile(s_p_statbuf))
    {
      vsf_cmdio_write(p_sess, FTP_FILEFAIL,
                      FTP_FAIL_READ_CTIME_CMDIO_LINE);
    }
    else
    {
      static struct mystr s_mdtm_res_str;
      str_alloc_text(&s_mdtm_res_str,
                     vsf_sysutil_statbuf_get_numeric_date(
                       s_p_statbuf, tunable_use_localtime));
      vsf_cmdio_write_str(p_sess, FTP_MDTMOK, &s_mdtm_res_str);
    }
  }
}

static void
handle_eprt(struct vsf_session* p_sess)
{
  static struct mystr s_part1_str;
  static struct mystr s_part2_str;
  static struct mystr s_scopeid_str;
  int proto;
  int port;
  const unsigned char* p_raw_addr;
  int is_ipv6 = vsf_sysutil_sockaddr_is_ipv6(p_sess->p_local_addr);
  port_cleanup(p_sess);
  pasv_cleanup(p_sess);
  str_copy(&s_part1_str, &p_sess->ftp_arg_str);
  str_split_char(&s_part1_str, &s_part2_str, '|');
  if (!str_isempty(&s_part1_str))
  {
    goto bad_eprt;
  }
  /* Split out the protocol and check it */
  str_split_char(&s_part2_str, &s_part1_str, '|');
  proto = str_atoi(&s_part2_str);
  if (proto < 1 || proto > 2 || (!is_ipv6 && proto == 2))
  {
    vsf_cmdio_write(p_sess, FTP_BADCMD, FTP_BAD_EPRT_CMDIO_LINE);
    return;
  }
  /* Split out address and parse it */
  str_split_char(&s_part1_str, &s_part2_str, '|');
  if (proto == 2)
  {
    str_split_char(&s_part1_str, &s_scopeid_str, '%');
    p_raw_addr = vsf_sysutil_parse_ipv6(&s_part1_str);
  }
  else
  {
    p_raw_addr = vsf_sysutil_parse_ipv4(&s_part1_str);
  }
  if (!p_raw_addr)
  {
    goto bad_eprt;
  }
  /* Split out port and parse it */
  str_split_char(&s_part2_str, &s_part1_str, '|');
  if (!str_isempty(&s_part1_str) || str_isempty(&s_part2_str))
  {
    goto bad_eprt;
  }
  port = str_atoi(&s_part2_str);
  if (port < 0 || port > 65535)
  {
    goto bad_eprt;
  }
  vsf_sysutil_sockaddr_clone(&p_sess->p_port_sockaddr, p_sess->p_local_addr);
  if (proto == 2)
  {
    vsf_sysutil_sockaddr_set_ipv6addr(p_sess->p_port_sockaddr, p_raw_addr);
  }
  else
  {
    vsf_sysutil_sockaddr_set_ipv4addr(p_sess->p_port_sockaddr, p_raw_addr);
  }
  vsf_sysutil_sockaddr_set_port(p_sess->p_port_sockaddr, (unsigned short) port);
  /* SECURITY:
   * 1) Reject requests not connecting to the control socket IP
   * 2) Reject connects to privileged ports
   */
  if (!tunable_port_promiscuous)
  {
    if (!vsf_sysutil_sockaddr_addr_equal(p_sess->p_remote_addr,
                                         p_sess->p_port_sockaddr) ||
        vsf_sysutil_is_port_reserved((unsigned short) port))
    {
      vsf_cmdio_write(p_sess, FTP_BADCMD, FTP_BAD_EPRT_COMMAND_CMDIO_LINE);
      port_cleanup(p_sess);
      return;
    }
  }
  vsf_cmdio_write(p_sess, FTP_EPRTOK,
                  FTP_OK_EPRT_COMMAND_CMDIO_LINE);
  return;
bad_eprt:
  vsf_cmdio_write(p_sess, FTP_BADCMD, FTP_BAD_EPRT_COMMAND_CMDIO_LINE);
}

/* XXX - add AUTH etc. */
static void
handle_help(struct vsf_session* p_sess)
{
  vsf_cmdio_write_hyphen(p_sess, FTP_HELP,
                         FTP_HELP_HEADER_CMDIO_LINE);
  vsf_cmdio_write_raw(p_sess,
" ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n");
  vsf_cmdio_write_raw(p_sess,
" MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n");
  vsf_cmdio_write_raw(p_sess,
" RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n");
  vsf_cmdio_write_raw(p_sess,
" XPWD XRMD\r\n");
  vsf_cmdio_write(p_sess, FTP_HELP, FTP_HELP_OK_CMDIO_LINE);
}

static void
handle_stou(struct vsf_session* p_sess)
{
  handle_upload_common(p_sess, 0, 1);
}

static void
get_unique_filename(struct mystr* p_outstr, const struct mystr* p_base_str)
{
  /* Use silly wu-ftpd algorithm for compatibility. It has races of course, if
   * two sessions are using the same file prefix at the same time.
   */
  static struct vsf_sysutil_statbuf* s_p_statbuf;
  static struct mystr s_stou_str;
  unsigned int suffix = 1;
  const struct mystr* p_real_base_str = p_base_str;
  int retval;
  if (str_isempty(p_real_base_str))
  {
    str_alloc_text(&s_stou_str, "STOU");
    p_real_base_str = &s_stou_str;
  }
  else
  {
    /* Do not add any suffix at all if the name is not taken. */
    retval = str_stat(p_real_base_str, &s_p_statbuf);
    if (vsf_sysutil_retval_is_error(retval))
    {
       str_copy(p_outstr, p_real_base_str);
       return;
    }
  }
  while (1)
  {
    str_copy(p_outstr, p_real_base_str);
    str_append_char(p_outstr, '.');
    str_append_ulong(p_outstr, suffix);
    retval = str_stat(p_outstr, &s_p_statbuf);
    if (vsf_sysutil_retval_is_error(retval))
    {
      return;
    }
    ++suffix;
  }
}

static void
handle_stat(struct vsf_session* p_sess)
{
  vsf_cmdio_write_hyphen(p_sess, FTP_STATOK, FTP_SRV_STATUS_CMDIO_LINE);
  vsf_cmdio_write_raw(p_sess, FTP_SRV_CONNECTED_CMDIO_LINE);
  vsf_cmdio_write_raw(p_sess, str_getbuf(&p_sess->remote_ip_str));
  vsf_cmdio_write_raw(p_sess, "\r\n");
  vsf_cmdio_write_raw(p_sess, FTP_SRV_LOGGED_IN_AS_CMDIO_LINE);
  vsf_cmdio_write_raw(p_sess, str_getbuf(&p_sess->user_str));
  vsf_cmdio_write_raw(p_sess, "\r\n");
  vsf_cmdio_write_raw(p_sess, FTP_SRV_MODE_CMDIO_LINE);
  if (p_sess->is_ascii)
  {
    vsf_cmdio_write_raw(p_sess, "ASCII\r\n");
  }
  else
  {
    vsf_cmdio_write_raw(p_sess, "BINARY\r\n");
  }
  if (p_sess->bw_rate_max == 0)
  {
    vsf_cmdio_write_raw(p_sess, FTP_SHOW_SPEEDLIMIT_WITHOUT_CMDIO_LINE);
  }
  else
  {
    vsf_cmdio_write_raw(p_sess, FTP_SHOW_SPEEDLIMIT_LIMIT_CMDIO_LINE);
    vsf_cmdio_write_raw(p_sess, vsf_sysutil_ulong_to_str(p_sess->bw_rate_max));
    vsf_cmdio_write_raw(p_sess, "\r\n");
  }
  if (tunable_idle_session_timeout == 0)
  {
    vsf_cmdio_write_raw(p_sess, FTP_SHOW_TIMEOUT_NO_CMDIO_LINE);
  }
  else
  {
    vsf_cmdio_write_raw(p_sess, FTP_SHOW_TIMEOUT_YES_CMDIO_LINE);
    vsf_cmdio_write_raw(p_sess,
      vsf_sysutil_ulong_to_str(tunable_idle_session_timeout));
    vsf_cmdio_write_raw(p_sess, "\r\n");
  }
  if (p_sess->control_use_ssl)
  {
    vsf_cmdio_write_raw(p_sess, FTP_SHOW_COMMAND_IS_CRYPT); 
  }
  else
  {
    vsf_cmdio_write_raw(p_sess, FTP_SHOW_COMMAND_NO_CRYPT); 
  }
  if (p_sess->data_use_ssl)
  {
    vsf_cmdio_write_raw(p_sess, FTP_SHOW_DATA_IS_CRYPT); 
  }
  else
  {
    vsf_cmdio_write_raw(p_sess, FTP_SHOW_DATA_NO_CRYPT);
  }
  if (p_sess->num_clients > 0)
  {
    vsf_cmdio_write_raw(p_sess, FTP_SHOW_LOGGEND_ON_WHILE_LOGIN);
    vsf_cmdio_write_raw(p_sess, vsf_sysutil_ulong_to_str(p_sess->num_clients));
    vsf_cmdio_write_raw(p_sess, FTP_SHOW_LOGGEND_ON_WHILE_LOGIN2);
  }
  vsf_cmdio_write_raw(p_sess,
    "     vsFTPd " VSF_VERSION FTP_VSFTPD_TAIL);
  vsf_cmdio_write(p_sess, FTP_STATOK, FTP_SHOW_END_OF_STATUS);
}

static void
handle_stat_file(struct vsf_session* p_sess)
{
  handle_dir_common(p_sess, 1, 1);
}

static int
data_transfer_checks_ok(struct vsf_session* p_sess)
{
  if (!pasv_active(p_sess) && !port_active(p_sess))
  {
    vsf_cmdio_write(p_sess, FTP_BADSENDCONN, FTP_USE_FIRST_CMDIO_LINE);
    return 0;
  }
  if (tunable_ssl_enable && !p_sess->data_use_ssl &&
      ((tunable_force_local_data_ssl && !p_sess->is_anonymous) ||
       (tunable_force_anon_data_ssl && p_sess->is_anonymous)))
  {
	if (!tunable_ssl_nonforce_file_enable || (tunable_ssl_nonforce_file_enable && !p_sess->non_force_ssl))
	{
			vsf_cmdio_write(
              p_sess, FTP_NEEDENCRYPT, FTP_SHOW_DATA_NEED_CRYPT);
			  return 0;
	}
  }
  return 1;
}

static void
resolve_tilde(struct mystr* p_str, struct vsf_session* p_sess)
{
  unsigned int len = str_getlen(p_str);
  if (len > 0 && str_get_char_at(p_str, 0) == '~')
  {
    static struct mystr s_rhs_str;
    if (len == 1 || str_get_char_at(p_str, 1) == '/')
    {
      str_split_char(p_str, &s_rhs_str, '~');
      str_copy(p_str, &p_sess->home_str);
      str_append_str(p_str, &s_rhs_str);
    }
    else if (tunable_tilde_user_enable && len > 1)
    {
      static struct mystr s_user_str;
      struct vsf_sysutil_user* p_user;
      str_copy(&s_rhs_str, p_str);
      str_split_char(&s_rhs_str, &s_user_str, '~');
      str_split_char(&s_user_str, &s_rhs_str, '/');
      p_user = str_getpwnam(&s_user_str);
      if (p_user != 0)
      {
        str_alloc_text(p_str, vsf_sysutil_user_get_homedir(p_user));
        if (!str_isempty(&s_rhs_str))
        {
          str_append_char(p_str, '/');
          str_append_str(p_str, &s_rhs_str);
        }
      }
    }
  }
}

static void handle_logged_in_user(struct vsf_session* p_sess)
{
  if (p_sess->is_anonymous)
  {
    vsf_cmdio_write(p_sess, FTP_LOGINERR, FTP_NO_CHANGE_FROM_GUEST);
  }
  else if (str_equal(&p_sess->user_str, &p_sess->ftp_arg_str))
  {
    vsf_cmdio_write(p_sess, FTP_GIVEPWORD, FTP_GIVE_ANY_PW);
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_LOGINERR, FTP_COULD_NOT_CHANGE_USER);
  }
}

static void handle_logged_in_pass(struct vsf_session* p_sess)
{
  vsf_cmdio_write(p_sess, FTP_LOGINOK, FTP_ALREADY_LOGGED_IN);
}

static void
handle_http(struct vsf_session* p_sess)
{
  /* Warning: Doesn't respect cmds_allowed etc. because there is currently only
   * one command (GET)!
   * HTTP likely doesn't respect other important FTP options. I don't think
   * logging works.
   */
  if (!tunable_download_enable)
  {
    bug("HTTP needs download - fix your config");
  }
  /* Eat the HTTP headers, which we don't care about. */
  do
  {
    vsf_cmdio_get_cmd_and_arg(p_sess, &p_sess->ftp_cmd_str,
                              &p_sess->ftp_arg_str, 1);
  }
  while (!str_isempty(&p_sess->ftp_cmd_str) ||
         !str_isempty(&p_sess->ftp_arg_str));
  vsf_cmdio_write_raw(p_sess, "HTTP/1.1 200 OK\r\n");
  vsf_cmdio_write_raw(p_sess, "Server: vsftpd\r\n");
  vsf_cmdio_write_raw(p_sess, "Connection: close\r\n");
  vsf_cmdio_write_raw(p_sess, "X-Frame-Options: SAMEORIGIN\r\n");
  vsf_cmdio_write_raw(p_sess, "X-Content-Type-Options: nosniff\r\n");
  /* Split the path from the HTTP/1.x */
  str_split_char(&p_sess->http_get_arg, &p_sess->ftp_arg_str, ' ');
  str_copy(&p_sess->ftp_arg_str, &p_sess->http_get_arg);
  str_split_char(&p_sess->http_get_arg, &p_sess->ftp_cmd_str, '.');
  str_upper(&p_sess->ftp_cmd_str);
  if (str_equal_text(&p_sess->ftp_cmd_str, "HTML") ||
      str_equal_text(&p_sess->ftp_cmd_str, "HTM"))
  {
    vsf_cmdio_write_raw(p_sess, "Content-Type: text/html\r\n");
  }
  else
  {
    vsf_cmdio_write_raw(p_sess, "Content-Type: dunno\r\n");
  }
  vsf_cmdio_write_raw(p_sess, "\r\n");
  p_sess->is_ascii = 0;
  p_sess->restart_pos = 0;
  handle_retr(p_sess, 1);
  if (vsf_log_entry_pending(p_sess))
  {
    vsf_log_do_log(p_sess, 0);
  }
  vsf_sysutil_exit(0);
}
