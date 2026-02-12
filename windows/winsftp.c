/*
 * winsftp.c — Windows GUI wrapper for PSFTP (winsftp.exe).
 *
 * Provides a simple window with:
 *   - a read-only multiline EDIT for output
 *   - a single-line EDIT + "Send" button for input
 *   - a STATIC status bar showing file transfer progress
 *
 * Replaces windows/console.c (win_console.obj) and the platform-
 * specific portions of windows/sftp.c for this target.
 *
 * psftp.c is compiled with -DWINSFTP_BUILD=1
 * -Dprintf=winsftp_printf -Dfprintf=winsftp_fprintf
 * so all its printf/fprintf calls route here.
 *
 * windows/sftp.c is compiled with -DWINSFTP_BUILD=1 (win_sftp_fileio.obj)
 * which strips out the event-loop and main function, keeping only the
 * file I/O helpers (RFile/WFile/DirHandle/WildcardMatcher etc.).
 */

#include <winsock.h>
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define NEED_DECLARATION_OF_SELECT
#include "putty.h"
#include "psftp.h"
#include "ssh.h"
#include "console.h"
#include "storage.h"
#include "security-api.h"
#include "putty-rc.h"
#include "version.h"

/* ----------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------- */
static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
static void winsftp_append(const char *text);
static void do_layout(HWND hwnd);

/* ----------------------------------------------------------------
 * Global GUI state
 * ---------------------------------------------------------------- */
HINSTANCE hinst;

static HWND g_hwnd;     /* main window */
static HWND g_output;   /* read-only multiline EDIT */
static HWND g_input;    /* single-line command EDIT */
static HWND g_status;   /* STATIC for progress/status text */
static HWND g_send;     /* "Send" push button */

static WNDPROC g_input_orig_proc; /* for subclassing g_input */

#define IDC_OUTPUT  100
#define IDC_INPUT   101
#define IDC_STATUS  102
/* IDC_SEND == IDOK == 1 so IsDialogMessage routes Enter to it */

/* ----------------------------------------------------------------
 * Command-line input synchronisation
 * (set by WndProc when user presses Send/Enter)
 * ---------------------------------------------------------------- */
static char  *g_cmd_line      = NULL;
static bool   g_cmd_ready     = false;
static bool   g_running       = true;
static bool   g_suppress_echo = false; /* true during credential prompts */

/* ----------------------------------------------------------------
 * Progress state
 * ---------------------------------------------------------------- */
static uint64_t g_progress_total = 0;
static char     g_progress_fname[256];

/* ================================================================
 * Output helpers
 * ================================================================ */

static void winsftp_append(const char *text)
{
    int len;
    const char *p;
    char *buf, *q;
    if (!g_output)
        return;

    /* Convert lone \n → \r\n for the EDIT control */
    buf = snewn(2 * strlen(text) + 1, char);
    for (p = text, q = buf; *p; p++) {
        if (*p == '\n' && (p == text || p[-1] != '\r'))
            *q++ = '\r';
        *q++ = *p;
    }
    *q = '\0';
    text = buf;

    len = GetWindowTextLength(g_output);

    /* Trim the output buffer if it gets too large (EDIT limit ~30 KB).
     * Snap the cut point to the start of the next line so we never
     * leave a half-wiped line at the top of the backlog. */
    if (len > 28000) {
        int cut = 14000;
        int line = (int)SendMessage(g_output, EM_LINEFROMCHAR, cut, 0);
        int next = (int)SendMessage(g_output, EM_LINEINDEX, line + 1, 0);
        if (next > cut) cut = next; /* advance to line boundary */
        SendMessage(g_output, EM_SETSEL, 0, cut);
        SendMessage(g_output, EM_REPLACESEL, FALSE, (LPARAM)"");
        len = GetWindowTextLength(g_output);
    }

    /* Append at end */
    SendMessage(g_output, EM_SETSEL, len, len);
    SendMessage(g_output, EM_REPLACESEL, FALSE, (LPARAM)text);
    sfree(buf);
}

/* These are called as printf/fprintf by psftp.c via -D macros */
int winsftp_printf(const char *fmt, ...)
{
    char buf[4096];
    int r;
    va_list ap;
    va_start(ap, fmt);
    r = vsprintf(buf, fmt, ap);
    va_end(ap);
    if (r > 0) winsftp_append(buf);
    return r;
}

int winsftp_fprintf(FILE *f, const char *fmt, ...)
{
    char buf[4096];
    int r;
    va_list ap;
    va_start(ap, fmt);
    r = vsprintf(buf, fmt, ap);
    va_end(ap);
    if (r > 0) winsftp_append(buf);
    return r;
}

/* ================================================================
 * Progress callbacks
 * (called from psftp.c under #ifdef WINSFTP_BUILD)
 * ================================================================ */

void sftp_progress_init(const char *fname, uint64_t total)
{
    char buf[300];
    int n;
    g_progress_total = total;
    /* Truncate filename for display */
    n = (int)strlen(fname);
    if (n > 40) fname += n - 40;
    strncpy(g_progress_fname, fname, sizeof(g_progress_fname) - 1);
    g_progress_fname[sizeof(g_progress_fname) - 1] = '\0';
    if (total > 0)
        sprintf(buf, "%s  [0 / %lu KB]", g_progress_fname,
                (unsigned long)(total / 1024));
    else
        sprintf(buf, "%s  [transferring...]", g_progress_fname);
    if (g_status) SetWindowText(g_status, buf);
}

void sftp_progress_update(uint64_t done)
{
    char buf[300];
    if (!g_status) return;
    if (g_progress_total > 0) {
        unsigned pct = (unsigned)((done * 100) / g_progress_total);
        sprintf(buf, "%s  [%lu / %lu KB  %u%%]",
                g_progress_fname,
                (unsigned long)(done / 1024),
                (unsigned long)(g_progress_total / 1024),
                pct);
    } else {
        sprintf(buf, "%s  [%lu KB]",
                g_progress_fname,
                (unsigned long)(done / 1024));
    }
    SetWindowText(g_status, buf);
    /* Pump one message so the status updates visually */
    {
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { g_running = false; break; }
            if (!IsDialogMessage(g_hwnd, &msg)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    }
}

/* ================================================================
 * Platform helpers (replacing windows/sftp.c under WINSFTP_BUILD)
 * ================================================================ */

void platform_get_x11_auth(struct X11Display *display, Conf *conf)
{
    /* No X11 auth on Windows */
}
const bool platform_uses_x11_unix_by_default = true;

extern Conf *conf; /* psftp.c */

void platform_psftp_pre_conn_setup(LogPolicy *lp)
{
    char buf[256];
    const char *host = conf_get_str(conf, CONF_host);
    bool user_utf8;
    const char *user = conf_get_str_ambi(conf, CONF_username, &user_utf8);
    int port = conf_get_int(conf, CONF_port);

    if (user && user[0])
        sprintf(buf, "Connecting to %s@%s port %d...\r\n", user, host, port);
    else
        sprintf(buf, "Connecting to %s port %d...\r\n", host, port);
    winsftp_append(buf);
    if (g_status) SetWindowText(g_status, "Connecting...");

    if (restricted_acl())
        lp_eventlog(lp, "Running with restricted process ACL");
}

SeatPromptResult filexfer_get_userpass_input(Seat *seat, prompts_t *p)
{
    size_t i;
    MSG msg;

    /* First try to satisfy from the command line (-pw flag etc.) */
    {
        static cmdline_get_passwd_input_state st =
            CMDLINE_GET_PASSWD_INPUT_STATE_INIT;
        SeatPromptResult spr = cmdline_get_passwd_input(p, &st, false);
        if (spr.kind != SPRK_INCOMPLETE)
            return spr;
    }

    /* Interactively prompt each field through the GUI text entry */
    for (i = 0; i < p->n_prompts; i++) {
        prompt_t *pr = p->prompts[i];
        char *line;

        /* Show the prompt text in the output area */
        winsftp_append(pr->prompt);

        /* For non-echo prompts (passwords), mask the input */
        if (!pr->echo && g_input)
            SendMessage(g_input, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);

        /* Clear status */
        if (g_status) SetWindowText(g_status, "Enter credential");

        g_suppress_echo = true;
        g_cmd_ready = false;
        g_cmd_line  = NULL;

        /* Modal loop: wait for user to press Enter */
        while (!g_cmd_ready) {
            if (!GetMessage(&msg, NULL, 0, 0)) {
                g_running = false;
                /* Restore input field */
                if (g_input)
                    SendMessage(g_input, EM_SETPASSWORDCHAR, 0, 0);
                return SPR_USER_ABORT;
            }
            if (!IsDialogMessage(g_hwnd, &msg)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            run_toplevel_callbacks();
        }

        /* Restore normal (unmasked) input */
        g_suppress_echo = false;
        if (g_input)
            SendMessage(g_input, EM_SETPASSWORDCHAR, 0, 0);

        line = g_cmd_line;
        g_cmd_line = NULL;

        if (line) {
            prompt_set_result(pr, line);
            sfree(line);
        } else {
            return SPR_USER_ABORT;
        }

        /* Echo a newline after hidden input */
        if (!pr->echo)
            winsftp_append("\r\n");
    }

    return SPR_OK;
}

/* ================================================================
 * Console interface (replacing windows/console.c / win_console.obj)
 * ================================================================ */

void cleanup_exit(int code)
{
    sk_cleanup();
    random_save_seed();
    exit(code);
}

void console_print_error_msg(const char *prefix, const char *msg)
{
    char buf[1024];
    sprintf(buf, "%s: %s\r\n", prefix, msg);
    winsftp_append(buf);
    MessageBox(g_hwnd, msg, prefix, MB_OK | MB_ICONERROR);
}

void console_print_error_msg_fmt_v(
    const char *prefix, const char *fmt, va_list ap)
{
    char *msg = dupvprintf(fmt, ap);
    console_print_error_msg(prefix, msg);
    sfree(msg);
}

void console_print_error_msg_fmt(const char *prefix, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    console_print_error_msg_fmt_v(prefix, fmt, ap);
    va_end(ap);
}

void modalfatalbox(const char *fmt, ...)
{
    va_list ap;
    char *msg;
    va_start(ap, fmt);
    msg = dupvprintf(fmt, ap);
    va_end(ap);
    /* Don't exit — show in the output area and let psftp_main unwind
     * cleanly so WinMain can restart the session. */
    winsftp_append("Connection error: ");
    winsftp_append(msg);
    winsftp_append("\r\n");
    sfree(msg);
}

void nonfatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    console_print_error_msg_fmt_v("ERROR", fmt, ap);
    va_end(ap);
}

bool console_batch_mode = false;

bool console_set_batch_mode(bool newvalue)
{
    console_batch_mode = newvalue;
    return true;
}

void timer_change_notify(unsigned long next)
{
    /* GUI app pumps messages in the event loop; no extra action needed */
}

/* Build a readable message string from a SeatDialogText */
static char *sdt_to_string(SeatDialogText *text)
{
    strbuf *sb = strbuf_new();
    size_t i;
    for (i = 0; i < text->nitems; i++) {
        SeatDialogTextItem *item = &text->items[i];
        switch (item->type) {
          case SDT_PARA:
          case SDT_SCARY_HEADING:
          case SDT_DISPLAY:
          case SDT_TITLE:
            put_dataz(sb, item->text);
            put_dataz(sb, "\n\n");
            break;
          case SDT_MORE_INFO_KEY:
            put_dataz(sb, item->text);
            put_dataz(sb, ": ");
            break;
          case SDT_MORE_INFO_VALUE_SHORT:
            put_dataz(sb, item->text);
            put_dataz(sb, "\n");
            break;
          case SDT_MORE_INFO_VALUE_BLOB:
            put_dataz(sb, item->text);
            put_dataz(sb, "\n");
            break;
          default:
            break;
        }
    }
    return strbuf_to_str(sb);
}

SeatPromptResult console_confirm_ssh_host_key(
    Seat *seat, const char *host, int port, const char *keytype,
    char *keystr, SeatDialogText *text, HelpCtx helpctx,
    void (*callback)(void *ctx, SeatPromptResult result), void *ctx)
{
    char *msg = sdt_to_string(text);
    int r = MessageBox(g_hwnd, msg, "Host Key Verification",
                       MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    sfree(msg);
    if (r == IDYES) {
        store_host_key(seat, host, port, keytype, keystr);
        return SPR_OK;
    }
    return SPR_USER_ABORT;
}

SeatPromptResult console_confirm_weak_crypto_primitive(
    Seat *seat, SeatDialogText *text,
    void (*callback)(void *ctx, SeatPromptResult result), void *ctx)
{
    char *msg = sdt_to_string(text);
    int r = MessageBox(g_hwnd, msg, "Weak Cryptography Warning",
                       MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    sfree(msg);
    return (r == IDYES) ? SPR_OK : SPR_USER_ABORT;
}

SeatPromptResult console_confirm_weak_cached_hostkey(
    Seat *seat, SeatDialogText *text,
    void (*callback)(void *ctx, SeatPromptResult result), void *ctx)
{
    char *msg = sdt_to_string(text);
    int r = MessageBox(g_hwnd, msg, "Cached Host Key Warning",
                       MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    sfree(msg);
    return (r == IDYES) ? SPR_OK : SPR_USER_ABORT;
}

const SeatDialogPromptDescriptions *console_prompt_descriptions(Seat *seat)
{
    static const SeatDialogPromptDescriptions descs = {
        .hk_accept_action = "click Yes",
        .hk_connect_once_action = "click No",
        .hk_cancel_action = "click No",
        .hk_cancel_action_Participle = "Clicking No",
        .weak_accept_action = "click Yes",
        .weak_cancel_action = "click No",
    };
    return &descs;
}

void console_connection_fatal(Seat *seat, const char *msg)
{
    /* Don't exit — let psftp_main unwind cleanly and WinMain restart
     * the session, just like after a normal disconnection. */
    winsftp_append("Connection error: ");
    winsftp_append(msg);
    winsftp_append("\r\n");
}

void console_nonfatal(Seat *seat, const char *msg)
{
    console_print_error_msg("ERROR", msg);
}

void console_set_trust_status(Seat *seat, bool trusted) { }
bool console_can_set_trust_status(Seat *seat) { return false; }
bool console_has_mixed_input_stream(Seat *seat) { return false; }

int console_askappend(LogPolicy *lp, Filename *filename,
                      void (*callback)(void *ctx, int result), void *ctx)
{
    char buf[512];
    sprintf(buf, "Log file \"%s\" already exists.\n"
            "Append to it?", filename_to_str(filename));
    int r = MessageBox(g_hwnd, buf, "WinSFTP",
                       MB_YESNOCANCEL | MB_ICONQUESTION);
    if (r == IDYES)   return 1;  /* append */
    if (r == IDNO)    return 2;  /* overwrite */
    return 0;                    /* cancel logging */
}

void console_logging_error(LogPolicy *lp, const char *msg)
{
    char buf[512];
    sprintf(buf, "Log error: %s\r\n", msg);
    winsftp_append(buf);
}

void console_eventlog(LogPolicy *lp, const char *msg)
{
    /* Suppress: event log goes to output area only if verbose */
}

StripCtrlChars *console_stripctrl_new(
    Seat *seat, BinarySink *bs_out, SeatInteractionContext sic)
{
    return stripctrl_new(bs_out, false, L'\0');
}

bool console_set_stdio_prompts(bool newvalue) { return true; }
bool set_legacy_charset_handling(bool newvalue) { return true; }

void old_keyfile_warning(void)
{
    MessageBox(g_hwnd,
        "You are loading an SSH-2 private key in an old file format.\n"
        "The key is not fully tamperproof. Consider re-saving it with\n"
        "PuTTYgen to convert it to the new format.",
        "Old key file format", MB_OK | MB_ICONWARNING);
}

void pgp_fingerprints(void)
{
    message_box(g_hwnd,
        "These are the fingerprints of the PuTTY PGP Master Keys. They can\n"
        "be used to establish a trust path from this executable to another\n"
        "one. See the manual for more information.\n"
        "(Note: these fingerprints have nothing to do with SSH!)\n\n"
        "PuTTY Master Key as of " PGP_MASTER_KEY_YEAR
        " (" PGP_MASTER_KEY_DETAILS "):\n"
        "  " PGP_MASTER_KEY_FP "\n\n"
        "Previous Master Key (" PGP_PREV_MASTER_KEY_YEAR
        ", " PGP_PREV_MASTER_KEY_DETAILS "):\n"
        "  " PGP_PREV_MASTER_KEY_FP,
        "PGP fingerprints", MB_ICONINFORMATION | MB_OK,
        false, HELPCTXID(pgp_fingerprints));
}

/* LogPolicy for this app (equivalent of clicons.c's console_cli_logpolicy) */
static const LogPolicyVtable winsftp_logpolicy_vt = {
    .eventlog       = console_eventlog,
    .askappend      = console_askappend,
    .logging_error  = console_logging_error,
    .verbose        = cmdline_lp_verbose,
};
LogPolicy console_cli_logpolicy[1] = {{ &winsftp_logpolicy_vt }};

/* ================================================================
 * Event loop (replaces windows/sftp.c ssh_sftp_loop_iteration and
 * ssh_sftp_get_cmdline)
 * ================================================================ */

/* Pump Windows messages; return false if WM_QUIT received */
static bool pump_messages(void)
{
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        if (msg.message == WM_QUIT) {
            g_running = false;
            return false;
        }
        if (!IsDialogMessage(g_hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    run_toplevel_callbacks();
    return true;
}

int ssh_sftp_loop_iteration(void)
{
    /* winsftp.exe targets Win32s (WinSock 1): always use select() */
    fd_set readfds;
    int ret;
    unsigned long now = GETTICKCOUNT(), then;
    SOCKET skt = winselcli_unique_socket();

    if (skt == INVALID_SOCKET)
        return -1;

    if (!pump_messages())
        return -1;

    /*
     * Drain all pending callbacks before blocking in select().  If any
     * are pending, return 0 immediately so the caller can consume
     * freshly-delivered application data (e.g. FXP_VERSION in
     * received_data) before we block again.  Without this, the
     * following deadlock occurs:
     *   1. select() returns with data (e.g. SSH_MSG_CHANNEL_DATA)
     *   2. select_result+run_toplevel_callbacks queues ic_process_queue
     *   3. we return 0; caller loops and calls us again
     *   4. ic_process_queue fires, fills received_data with FXP_VERSION
     *   5. but then we fall into select() blocking forever while
     *      received_data already has the data the caller needs
     */
    if (toplevel_callback_pending()) {
        while (toplevel_callback_pending())
            run_toplevel_callbacks();
        return 0;
    }

    if (socket_writable(skt))
        select_result((WPARAM)skt, (LPARAM)FD_WRITE);

    do {
        unsigned long next;
        long ticks;
        struct timeval tv;

        if (run_timers(now, &next)) {
            then = now;
            now = GETTICKCOUNT();
            if (now - then > next - then)
                ticks = 0;
            else
                ticks = next - now;
            /* Cap at 100 ms to keep UI responsive */
            if (ticks > 100) ticks = 100;
            tv.tv_sec  = ticks / 1000;
            tv.tv_usec = (ticks % 1000) * 1000;
        } else {
            tv.tv_sec  = 0;
            tv.tv_usec = 100000; /* 100 ms */
        }

        FD_ZERO(&readfds);
        FD_SET(skt, &readfds);
        ret = p_select(1, &readfds, NULL, NULL, &tv);

        if (ret < 0)
            return -1;

        if (ret == 0) {
            now = GETTICKCOUNT();
            /* Pump messages while waiting */
            if (!pump_messages())
                return -1;
        } else {
            now = GETTICKCOUNT();
        }

    } while (ret == 0);

    select_result((WPARAM)skt, (LPARAM)FD_READ);
    return 0;
}

char *ssh_sftp_get_cmdline(const char *prompt, bool no_fds_ok)
{
    MSG msg;
    char *ret;

    /* Clear progress status */
    if (g_status) SetWindowText(g_status, "Ready");

    g_cmd_ready = false;
    g_cmd_line  = NULL;

    /* Modal message loop: block until user presses Enter */
    while (!g_cmd_ready) {
        if (!GetMessage(&msg, NULL, 0, 0)) {
            /* WM_QUIT */
            g_running = false;
            return NULL;
        }
        if (!IsDialogMessage(g_hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        run_toplevel_callbacks();
    }

    ret = g_cmd_line;
    g_cmd_line = NULL;

    /* Handle /cls locally: clear the output area and prompt again */
    if (ret && strcmp(ret, "/cls") == 0) {
        sfree(ret);
        if (g_output) SetWindowText(g_output, "");
        return ssh_sftp_get_cmdline(prompt, no_fds_ok);
    }

    /* Handle /quit locally: close the window and exit */
    if (ret && strcmp(ret, "/quit") == 0) {
        sfree(ret);
        g_running = false;
        if (g_hwnd) DestroyWindow(g_hwnd);
        return NULL;
    }

    return ret; /* caller frees */
}

/* ================================================================
 * Tab completion
 * ================================================================ */

/*
 * Split a path token at the last separator into dir+prefix.
 * dir will include the trailing backslash if present.
 * Both strings must be freed by the caller.
 */
static void split_path(const char *token,
                        char **dir_out, char **prefix_out)
{
    const char *p = token + strlen(token);
    while (p > token && p[-1] != '\\' && p[-1] != '/')
        p--;
    if (p == token) {
        *dir_out    = dupstr("");
        *prefix_out = dupstr(token);
    } else {
        int dir_len = (int)(p - token);
        *dir_out    = snewn(dir_len + 1, char);
        memcpy(*dir_out, token, dir_len);
        (*dir_out)[dir_len] = '\0';
        *prefix_out = dupstr(p);
    }
}

/*
 * Tab completion: enumerate local filesystem entries matching the
 * last token in the input field.  Absolute paths (C:\...) and
 * relative paths (resolved against the current local directory set
 * by the 'lcd' command) are both supported.
 */
static void tab_complete(void)
{
    char input_buf[1024];
    int input_len, token_offset, i;
    const char *token_start;
    char *token, *dir_part, *prefix_part;
    char search_pat[MAX_PATH + 4];
    HANDLE hFind;
    WIN32_FIND_DATA fd;
    char **matches = NULL;
    int n_matches = 0, max_matches = 0;
    char common[MAX_PATH];
    int common_len;

    if (!g_input) return;

    input_len = GetWindowText(g_input, input_buf, (int)sizeof(input_buf) - 1);
    input_buf[input_len] = '\0';

    /* The token to complete is everything after the last space */
    {
        char *sp = strrchr(input_buf, ' ');
        token_start = sp ? sp + 1 : input_buf;
    }
    token_offset = (int)(token_start - input_buf);
    token = dupstr(token_start);

    split_path(token, &dir_part, &prefix_part);

    /* FindFirstFile search pattern: dir\prefix* */
    if ((int)(strlen(dir_part) + strlen(prefix_part)) + 2 > MAX_PATH)
        goto cleanup;
    sprintf(search_pat, "%s%s*", dir_part, prefix_part);

    /* Enumerate matching entries */
    hFind = FindFirstFile(search_pat, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            const char *name = fd.cFileName;
            bool is_dir = !!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
            char *entry;
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
                continue;
            if (n_matches >= max_matches) {
                max_matches = max_matches ? max_matches * 2 : 16;
                matches = sresize(matches, max_matches, char *);
            }
            /* Completion stores the dir_part prefix so the token is
             * reconstructed correctly for both relative and absolute paths. */
            if (is_dir)
                entry = dupcat(dir_part, name, "\\");
            else
                entry = dupcat(dir_part, name);
            matches[n_matches++] = entry;
        } while (FindNextFile(hFind, &fd));
        FindClose(hFind);
    }

    if (n_matches == 0) {
        MessageBeep((UINT)-1);
        goto cleanup;
    }

    if (n_matches == 1) {
        /* Single match: fill it in; append a space unless it's a dir */
        const char *m = matches[0];
        int mlen = (int)strlen(m);
        bool add_space = (mlen == 0 || m[mlen - 1] != '\\');
        char *new_text = snewn(token_offset + mlen + 2, char);
        memcpy(new_text, input_buf, token_offset);
        memcpy(new_text + token_offset, m, mlen);
        if (add_space) {
            new_text[token_offset + mlen]     = ' ';
            new_text[token_offset + mlen + 1] = '\0';
        } else {
            new_text[token_offset + mlen] = '\0';
        }
        SetWindowText(g_input, new_text);
        {
            int newlen = (int)strlen(new_text);
            SendMessage(g_input, EM_SETSEL, newlen, newlen);
        }
        sfree(new_text);
        goto cleanup;
    }

    /* Multiple matches: show list, then extend to longest common prefix */
    winsftp_append("Completions:\r\n");
    for (i = 0; i < n_matches; i++) {
        winsftp_append("  ");
        winsftp_append(matches[i]);
        winsftp_append("\r\n");
    }

    /* Compute longest common prefix of the name portions */
    {
        int dir_len = (int)strlen(dir_part);
        const char *first = matches[0] + dir_len;
        common_len = (int)strlen(first);
        if (common_len >= MAX_PATH) common_len = MAX_PATH - 1;
        strncpy(common, first, common_len);
        common[common_len] = '\0';
        for (i = 1; i < n_matches; i++) {
            const char *name = matches[i] + dir_len;
            int j;
            for (j = 0; j < common_len && name[j]; j++) {
                if (tolower((unsigned char)common[j]) !=
                    tolower((unsigned char)name[j]))
                    break;
            }
            common_len = j;
        }
        common[common_len] = '\0';
    }

    /* Extend the input field if the common prefix is longer than what
     * was already typed */
    if (common_len > (int)strlen(prefix_part)) {
        char *completed = dupcat(dir_part, common);
        int clen = (int)strlen(completed);
        char *new_text = snewn(token_offset + clen + 1, char);
        memcpy(new_text, input_buf, token_offset);
        memcpy(new_text + token_offset, completed, clen);
        new_text[token_offset + clen] = '\0';
        SetWindowText(g_input, new_text);
        {
            int newlen = (int)strlen(new_text);
            SendMessage(g_input, EM_SETSEL, newlen, newlen);
        }
        sfree(completed);
        sfree(new_text);
    }

  cleanup:
    for (i = 0; i < n_matches; i++)
        sfree(matches[i]);
    sfree(matches);
    sfree(token);
    sfree(dir_part);
    sfree(prefix_part);
}

/*
 * Subclass procedure for g_input: intercepts Tab for completion.
 * WM_GETDLGCODE returns DLGC_WANTTAB so IsDialogMessage doesn't
 * consume Tab before the window sees it.
 */
static LRESULT CALLBACK InputSubclassProc(HWND hwnd, UINT umsg,
                                           WPARAM wParam, LPARAM lParam)
{
    if (umsg == WM_GETDLGCODE)
        return CallWindowProc(g_input_orig_proc, hwnd, umsg, wParam, lParam)
               | DLGC_WANTTAB;
    if (umsg == WM_KEYDOWN && wParam == VK_TAB) {
        tab_complete();
        return 0;
    }
    if (umsg == WM_CHAR && wParam == '\t')
        return 0; /* eat the translated Tab character */
    return CallWindowProc(g_input_orig_proc, hwnd, umsg, wParam, lParam);
}

/* ================================================================
 * GUI: window procedure and layout
 * ================================================================ */

#define STATUS_H  20
#define INPUT_H   24
#define MARGIN     4
#define BTN_W     50

static void do_layout(HWND hwnd)
{
    RECT rc;
    int w, h, output_h, input_y, status_y;

    GetClientRect(hwnd, &rc);
    w = rc.right  - rc.left;
    h = rc.bottom - rc.top;

    status_y  = h - STATUS_H;
    input_y   = status_y - INPUT_H - MARGIN;
    output_h  = input_y - MARGIN;

    if (output_h < 1) output_h = 1;

    if (g_output)
        MoveWindow(g_output, 0, 0, w, output_h, TRUE);
    if (g_input)
        MoveWindow(g_input, 0, input_y, w - BTN_W - MARGIN, INPUT_H, TRUE);
    if (g_send)
        MoveWindow(g_send, w - BTN_W, input_y, BTN_W, INPUT_H, TRUE);
    if (g_status)
        MoveWindow(g_status, 0, status_y, w, STATUS_H, TRUE);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg,
                                 WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
      case WM_CREATE:
        /* Output area */
        g_output = CreateWindow("EDIT", "",
                                WS_CHILD | WS_VISIBLE | WS_BORDER |
                                WS_VSCROLL | ES_MULTILINE |
                                ES_READONLY | ES_AUTOVSCROLL,
                                0, 0, 0, 0,
                                hwnd, (HMENU)IDC_OUTPUT, hinst, NULL);
        /* Input field */
        g_input  = CreateWindow("EDIT", "",
                                WS_CHILD | WS_VISIBLE | WS_BORDER |
                                ES_AUTOHSCROLL,
                                0, 0, 0, 0,
                                hwnd, (HMENU)IDC_INPUT, hinst, NULL);
        /* Subclass input EDIT to intercept Tab for completion */
        g_input_orig_proc = (WNDPROC)SetWindowLong(
            g_input, GWL_WNDPROC, (LONG)InputSubclassProc);
        /* Send button — ID = IDOK so IsDialogMessage routes Enter here */
        g_send   = CreateWindow("BUTTON", "Send",
                                WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                0, 0, 0, 0,
                                hwnd, (HMENU)IDOK, hinst, NULL);
        /* Status bar */
        g_status = CreateWindow("STATIC", "Ready",
                                WS_CHILD | WS_VISIBLE | SS_SUNKEN,
                                0, 0, 0, 0,
                                hwnd, (HMENU)IDC_STATUS, hinst, NULL);

        /* Set a fixed-width font for the output area */
        {
            HFONT hf = (HFONT)GetStockObject(SYSTEM_FIXED_FONT);
            SendMessage(g_output, WM_SETFONT, (WPARAM)hf, FALSE);
            SendMessage(g_input,  WM_SETFONT, (WPARAM)hf, FALSE);
            SendMessage(g_status, WM_SETFONT, (WPARAM)hf, FALSE);
        }

        do_layout(hwnd);
        return 0;

      case WM_SIZE:
        do_layout(hwnd);
        return 0;

      case WM_SETFOCUS:
        if (g_input) SetFocus(g_input);
        return 0;

      case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            /* User pressed Enter or clicked Send */
            int len = GetWindowTextLength(g_input);
            if (len > 0) {
                g_cmd_line = snewn(len + 2, char);
                GetWindowText(g_input, g_cmd_line, len + 1);
                SetWindowText(g_input, "");
                if (!g_suppress_echo) {
                    winsftp_append("> ");
                    winsftp_append(g_cmd_line);
                    winsftp_append("\r\n");
                }
                g_cmd_ready = true;
            } else {
                /* Empty Enter: submit empty line (exits batch/interactive) */
                g_cmd_line  = dupstr("");
                g_cmd_ready = true;
            }
        }
        return 0;

      case WM_CLOSE:
        g_running = false;
        DestroyWindow(hwnd);
        return 0;

      case WM_DESTROY:
        g_hwnd   = NULL;
        g_output = NULL;
        g_input  = NULL;
        g_send   = NULL;
        g_status = NULL;
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

/* ================================================================
 * WinMain
 * ================================================================ */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR cmdline, int nShow)
{
    WNDCLASS wc;
    int ret;

    hinst = hInst;

    dll_hijacking_protection();
    enable_dit();

    /* Register window class (skip if a previous instance already did it) */
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "WinSFTP";
    wc.hIcon         = LoadIcon(hInst, MAKEINTRESOURCE(IDI_MAINICON));
    if (!hPrev)
        RegisterClass(&wc);

    /* Create main window */
    g_hwnd = CreateWindow(
        "WinSFTP", "WinSFTP",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        640, 480,
        NULL, NULL, hInst, NULL);

    if (!g_hwnd) {
        MessageBox(NULL, "Failed to create window", "WinSFTP", MB_OK);
        return 1;
    }

    ShowWindow(g_hwnd, nShow);
    UpdateWindow(g_hwnd);

    /* Session loop: restart after each session ends */
    ret = 0;
    while (g_hwnd && g_running) {
        winsftp_append("WinSFTP " TEXTVER " type \"open [user@]host [port]\" to connect\r\n\r\n");

        ret = psftp_main(NULL);

        if (g_hwnd && g_running) {
            winsftp_append("\r\nSession ended.\r\n\r\n");
            if (g_status) SetWindowText(g_status, "Ready");
        }
    }

    /* psftp_main already calls sk_cleanup() and random_save_seed().
     * wc.hIcon is a shared resource (LoadIcon) — do NOT DestroyIcon it.
     * Only the window class needs unregistering here. */
    if (!hPrev)
        UnregisterClass("WinSFTP", hInst);

    return ret;
}
