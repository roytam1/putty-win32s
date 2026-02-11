/*
 * storage.c: Windows-specific implementation of the interface
 * defined in storage.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>
#include "putty.h"
#include "storage.h"

#ifdef WIN32S_COMPAT
/* ================================================================
 * Win32s file-based storage implementation.
 * Sessions stored as flat files under $PUTTYDIR or $HOME\putty\.
 * ================================================================ */

#include <direct.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include "tree234.h"

/* Index values for make_filename() */
enum {
    INDEX_DIR,        /* base putty directory */
    INDEX_SESSIONDIR, /* sessions subdirectory */
    INDEX_SESSION,    /* individual session file */
    INDEX_HOSTKEYS,   /* host keys file */
    INDEX_RANDSEED,   /* random seed file */
};

static void make_dir_path(const char *path)
{
    char *p, *buf = dupstr(path);
    for (p = buf; *p; p++) {
        if (*p == '\\' || *p == '/') {
            char old = *p;
            *p = '\0';
            _mkdir(buf);
            *p = old;
        }
    }
    _mkdir(buf);
    sfree(buf);
}

/*
 * Convert a session name to an 8.3-compliant filename for FAT/Win32s.
 * Other names: uppercase, keep only alphanumerics and underscore,
 * truncate to 8 characters.
 */
static char *make_session_filename(const char *in)
{
    if (!strcmp(in, DEFAULT_SESSION_NAME))
        return dupstr(DEFAULT_SESSION_NAME);

    strbuf *sb = strbuf_new();
    const char *p;
    int count = 0;
    for (p = in; *p && count < 8; p++) {
        unsigned char c = (unsigned char)*p;
        if (c >= 'a' && c <= 'z') {
            put_byte(sb, c - 'a' + 'A');
            count++;
        } else if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            put_byte(sb, c);
            count++;
        } else if (c == ' ' || c == '-' || c == '.') {
            put_byte(sb, '_');
            count++;
        }
        /* other characters are skipped */
    }
    if (sb->len == 0)
        put_datapl(sb, PTRLEN_LITERAL("_SESS"));
    return strbuf_to_str(sb);
}

/*
 * Decode an 8.3 session filename back to a session name.
 * The filename IS the session name on Win32s.
 */
static char *decode_session_filename(const char *in)
{
    return dupstr(in);
}

/*
 * Construct a full pathname from a given index and optional subname.
 */
static char *make_filename(int index, const char *subname)
{
    char *env, *base;
    char *ret;

    env = getenv("PUTTYDIR");
    if (env && *env) {
        base = dupstr(env);
    } else {
        env = getenv("HOME");
        if (!env || !*env)
            env = getenv("HOMEDRIVE");
        if (!env || !*env)
            env = "C:";
        base = dupcat(env, "\\putty");
    }

    switch (index) {
      case INDEX_DIR:
        ret = base;
        break;
      case INDEX_SESSIONDIR:
        ret = dupcat(base, "\\sessions");
        sfree(base);
        break;
      case INDEX_SESSION: {
        char *enc = make_session_filename(subname);
        ret = dupcat(base, "\\sessions\\", enc);
        sfree(enc);
        sfree(base);
        break;
      }
      case INDEX_HOSTKEYS:
        ret = dupcat(base, "\\HOSTKEYS");
        sfree(base);
        break;
      case INDEX_RANDSEED:
        ret = dupcat(base, "\\RNDSEED");
        sfree(base);
        break;
      default:
        sfree(base);
        ret = NULL;
        break;
    }

    return ret;
}

/* ---- settings_w (file-based) ---- */

struct settings_w {
    FILE *fp;
};

settings_w *open_settings_w(const char *sessionname, char **errmsg)
{
    char *dir, *filename;
    FILE *fp;

    *errmsg = NULL;

    if (!sessionname || !*sessionname)
        sessionname = DEFAULT_SESSION_NAME;

    dir = make_filename(INDEX_SESSIONDIR, NULL);
    make_dir_path(dir);
    sfree(dir);

    filename = make_filename(INDEX_SESSION, sessionname);
    fp = fopen(filename, "w");
    if (!fp) {
        *errmsg = dupprintf("Unable to create session file\n%s", filename);
        sfree(filename);
        return NULL;
    }
    sfree(filename);

    settings_w *handle = snew(settings_w);
    handle->fp = fp;
    return handle;
}

void write_setting_s(settings_w *handle, const char *key, const char *value)
{
    if (handle)
        fprintf(handle->fp, "%s=%s\n", key, value);
}

void write_setting_i(settings_w *handle, const char *key, int value)
{
    if (handle)
        fprintf(handle->fp, "%s=%d\n", key, value);
}

void close_settings_w(settings_w *handle)
{
    fclose(handle->fp);
    sfree(handle);
}

/* ---- settings_r (file-based, tree234 lookup) ---- */

struct skv {
    char *key;
    char *value;
};

static int skvcmp(void *av, void *bv)
{
    const struct skv *a = (const struct skv *)av;
    const struct skv *b = (const struct skv *)bv;
    return strcmp(a->key, b->key);
}

struct settings_r {
    tree234 *t;
};

settings_r *open_settings_r(const char *sessionname)
{
    char *filename;
    FILE *fp;
    char *line;

    if (!sessionname || !*sessionname)
        sessionname = DEFAULT_SESSION_NAME;

    filename = make_filename(INDEX_SESSION, sessionname);
    fp = fopen(filename, "r");
    sfree(filename);
    if (!fp)
        return NULL;

    settings_r *handle = snew(settings_r);
    handle->t = newtree234(skvcmp);

    while ((line = fgetline(fp)) != NULL) {
        char *eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            struct skv *kv = snew(struct skv);
            kv->key = dupstr(line);
            /* strip trailing newline from value */
            char *val = eq + 1;
            int len = strlen(val);
            if (len > 0 && val[len-1] == '\n')
                val[len-1] = '\0';
            kv->value = dupstr(val);
            struct skv *old = add234(handle->t, kv);
            if (old != kv) {
                /* duplicate key - replace */
                sfree(old->value);
                old->value = kv->value;
                sfree(kv->key);
                sfree(kv);
            }
        }
        sfree(line);
    }
    fclose(fp);

    return handle;
}

char *read_setting_s(settings_r *handle, const char *key)
{
    struct skv tmp, *found;
    if (!handle)
        return NULL;
    tmp.key = (char *)key;
    found = find234(handle->t, &tmp, NULL);
    if (found)
        return dupstr(found->value);
    return NULL;
}

int read_setting_i(settings_r *handle, const char *key, int defvalue)
{
    struct skv tmp, *found;
    if (!handle)
        return defvalue;
    tmp.key = (char *)key;
    found = find234(handle->t, &tmp, NULL);
    if (found)
        return atoi(found->value);
    return defvalue;
}

FontSpec *read_setting_fontspec(settings_r *handle, const char *name)
{
    char *settingname;
    char *fontname;
    FontSpec *ret;
    int isbold, height, charset;

    fontname = read_setting_s(handle, name);
    if (!fontname)
        return NULL;

    settingname = dupcat(name, "IsBold");
    isbold = read_setting_i(handle, settingname, -1);
    sfree(settingname);
    if (isbold == -1) {
        sfree(fontname);
        return NULL;
    }

    settingname = dupcat(name, "CharSet");
    charset = read_setting_i(handle, settingname, -1);
    sfree(settingname);
    if (charset == -1) {
        sfree(fontname);
        return NULL;
    }

    settingname = dupcat(name, "Height");
    height = read_setting_i(handle, settingname, INT_MIN);
    sfree(settingname);
    if (height == INT_MIN) {
        sfree(fontname);
        return NULL;
    }

    ret = fontspec_new(fontname, isbold, height, charset);
    sfree(fontname);
    return ret;
}

void write_setting_fontspec(settings_w *handle,
                            const char *name, FontSpec *font)
{
    char *settingname;

    write_setting_s(handle, name, font->name);
    settingname = dupcat(name, "IsBold");
    write_setting_i(handle, settingname, font->isbold);
    sfree(settingname);
    settingname = dupcat(name, "CharSet");
    write_setting_i(handle, settingname, font->charset);
    sfree(settingname);
    settingname = dupcat(name, "Height");
    write_setting_i(handle, settingname, font->height);
    sfree(settingname);
}

Filename *read_setting_filename(settings_r *handle, const char *name)
{
    char *tmp = read_setting_s(handle, name);
    if (tmp) {
        Filename *ret = filename_from_str(tmp);
        sfree(tmp);
        return ret;
    } else
        return NULL;
}

void write_setting_filename(settings_w *handle,
                            const char *name, Filename *result)
{
    write_setting_s(handle, name, result->cpath);
}

void close_settings_r(settings_r *handle)
{
    struct skv *kv;
    if (handle) {
        while ((kv = delpos234(handle->t, 0)) != NULL) {
            sfree(kv->key);
            sfree(kv->value);
            sfree(kv);
        }
        freetree234(handle->t);
        sfree(handle);
    }
}

void del_settings(const char *sessionname)
{
    char *filename = make_filename(INDEX_SESSION, sessionname);
    remove(filename);
    sfree(filename);
}

/* ---- settings_e (session enumeration) ---- */

struct settings_e {
    HANDLE hFind;
    WIN32_FIND_DATA fd;
    bool first;
};

settings_e *enum_settings_start(void)
{
    char *dir = make_filename(INDEX_SESSIONDIR, NULL);
    char *wildcard = dupcat(dir, "\\*");
    sfree(dir);

    settings_e *e = snew(settings_e);
    e->hFind = FindFirstFile(wildcard, &e->fd);
    sfree(wildcard);

    if (e->hFind == INVALID_HANDLE_VALUE) {
        sfree(e);
        return NULL;
    }
    e->first = true;
    return e;
}

bool enum_settings_next(settings_e *e, strbuf *sb)
{
    while (1) {
        if (!e->first) {
            if (!FindNextFile(e->hFind, &e->fd))
                return false;
        }
        e->first = false;

        /* Skip . and .. and directories */
        if (e->fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        char *name = decode_session_filename(e->fd.cFileName);
        put_datapl(sb, ptrlen_from_asciz(name));
        sfree(name);
        return true;
    }
}

void enum_settings_finish(settings_e *e)
{
    FindClose(e->hFind);
    sfree(e);
}

/* ---- Host key storage (flat file) ---- */

static void hostkey_regname(strbuf *sb, const char *hostname,
                            int port, const char *keytype)
{
    put_fmt(sb, "%s@%d:%s", keytype, port, hostname);
}

int check_stored_host_key(const char *hostname, int port,
                          const char *keytype, const char *key)
{
    char *filename = make_filename(INDEX_HOSTKEYS, NULL);
    FILE *fp = fopen(filename, "r");
    sfree(filename);

    if (!fp)
        return 1; /* key does not exist */

    strbuf *expected = strbuf_new();
    hostkey_regname(expected, hostname, port, keytype);

    char *line;
    int ret = 1; /* not found */
    while ((line = fgetline(fp)) != NULL) {
        int len = strlen(line);
        if (len > 0 && line[len-1] == '\n')
            line[--len] = '\0';

        /* Each line is: type@port:hostname keydata */
        char *space = strchr(line, ' ');
        if (space) {
            *space = '\0';
            if (!strcmp(line, expected->s)) {
                /* Found the entry */
                if (!strcmp(space + 1, key))
                    ret = 0; /* key matches */
                else
                    ret = 2; /* key is different */
                sfree(line);
                break;
            }
        }
        sfree(line);
    }

    fclose(fp);
    strbuf_free(expected);
    return ret;
}

bool have_ssh_host_key(const char *hostname, int port,
                       const char *keytype)
{
    return check_stored_host_key(hostname, port, keytype, "") != 1;
}

void store_host_key(Seat *seat, const char *hostname, int port,
                    const char *keytype, const char *key)
{
    char *filename = make_filename(INDEX_HOSTKEYS, NULL);
    char *tmpfilename = dupcat(filename, ".tmp");

    /*
     * Read existing host keys, replacing any existing entry for
     * this host+keytype, then write back.
     */
    strbuf *expected = strbuf_new();
    hostkey_regname(expected, hostname, port, keytype);

    FILE *rfp = fopen(filename, "r");
    FILE *wfp = fopen(tmpfilename, "w");
    if (!wfp) {
        /* Ensure directory exists */
        char *dir = make_filename(INDEX_DIR, NULL);
        make_dir_path(dir);
        sfree(dir);
        wfp = fopen(tmpfilename, "w");
    }

    if (wfp) {
        if (rfp) {
            char *line;
            while ((line = fgetline(rfp)) != NULL) {
                char *space = strchr(line, ' ');
                if (space) {
                    /* Check if this line is for the same host key */
                    char saved = *space;
                    *space = '\0';
                    if (strcmp(line, expected->s) != 0) {
                        *space = saved;
                        fputs(line, wfp);
                    }
                    /* else skip - we'll write the new one below */
                } else {
                    fputs(line, wfp);
                }
                sfree(line);
            }
        }
        fprintf(wfp, "%s %s\n", expected->s, key);
        fclose(wfp);

        /* Atomic-ish replace */
        remove(filename);
        rename(tmpfilename, filename);
    }

    if (rfp)
        fclose(rfp);
    strbuf_free(expected);
    sfree(tmpfilename);
    sfree(filename);
}

/* ---- Host CA stubs (not supported on Win32s) ---- */

struct host_ca_enum {
    int dummy;
};

host_ca_enum *enum_host_ca_start(void) { return NULL; }
bool enum_host_ca_next(host_ca_enum *e, strbuf *sb) { return false; }
void enum_host_ca_finish(host_ca_enum *e) { }
host_ca *host_ca_load(const char *name) { return NULL; }
char *host_ca_save(host_ca *hca) {
    return dupstr("Host CA storage not supported on Win32s");
}
char *host_ca_delete(const char *name) { return NULL; }

/* ---- Random seed (file-based) ---- */

void read_random_seed(noise_consumer_t consumer)
{
    char *fname = make_filename(INDEX_RANDSEED, NULL);
    FILE *fp = fopen(fname, "rb");
    sfree(fname);

    if (fp) {
        char buf[1024];
        size_t len;
        while ((len = fread(buf, 1, sizeof(buf), fp)) > 0)
            consumer(buf, len);
        fclose(fp);
    }
}

void write_random_seed(void *data, int len)
{
    char *dir = make_filename(INDEX_DIR, NULL);
    make_dir_path(dir);
    sfree(dir);

    char *fname = make_filename(INDEX_RANDSEED, NULL);
    FILE *fp = fopen(fname, "wb");
    sfree(fname);

    if (fp) {
        fwrite(data, 1, len, fp);
        fclose(fp);
    }
}

/* ---- Jump list stubs ---- */

static int transform_jumplist_registry(
    const char *add, const char *rem, char **out)
{
    if (out) {
        *out = snewn(2, char);
        (*out)[0] = '\0';
        (*out)[1] = '\0';
    }
    return JUMPLISTREG_OK;
}

int add_to_jumplist_registry(const char *item) { return JUMPLISTREG_OK; }
int remove_from_jumplist_registry(const char *item) { return JUMPLISTREG_OK; }

char *get_jumplist_registry_entries(void)
{
    char *list = snewn(2, char);
    list[0] = '\0';
    list[1] = '\0';
    return list;
}

/* ---- Cleanup (no-op for file-based storage) ---- */

void cleanup_all(void) { }

#else /* !WIN32S_COMPAT */
/* ================================================================
 * Standard registry-based storage implementation.
 * ================================================================ */

#include <shlobj.h>
#ifndef CSIDL_APPDATA
#define CSIDL_APPDATA 0x001a
#endif
#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA 0x001c
#endif

static const char *const reg_jumplist_key = PUTTY_REG_POS "\\Jumplist";
static const char *const reg_jumplist_value = "Recent sessions";
static const char *const puttystr = PUTTY_REG_POS "\\Sessions";
static const char *const host_ca_key = PUTTY_REG_POS "\\SshHostCAs";

static bool tried_shgetfolderpath = false;
static HMODULE shell32_module = NULL;
DECL_WINDOWS_FUNCTION(static, HRESULT, SHGetFolderPathA,
                      (HWND, int, HANDLE, DWORD, LPSTR));

struct settings_w {
    HKEY sesskey;
};

settings_w *open_settings_w(const char *sessionname, char **errmsg)
{
    *errmsg = NULL;

    if (!sessionname || !*sessionname)
        sessionname = "Default Settings";

    strbuf *sb = strbuf_new();
    escape_registry_key(sessionname, sb);

    HKEY sesskey = create_regkey(HKEY_CURRENT_USER, puttystr, sb->s);
    if (!sesskey) {
        *errmsg = dupprintf("Unable to create registry key\n"
                            "HKEY_CURRENT_USER\\%s\\%s", puttystr, sb->s);
        strbuf_free(sb);
        return NULL;
    }
    strbuf_free(sb);

    settings_w *handle = snew(settings_w);
    handle->sesskey = sesskey;
    return handle;
}

void write_setting_s(settings_w *handle, const char *key, const char *value)
{
    if (handle)
        put_reg_sz(handle->sesskey, key, value);
}

void write_setting_i(settings_w *handle, const char *key, int value)
{
    if (handle)
        put_reg_dword(handle->sesskey, key, value);
}

void close_settings_w(settings_w *handle)
{
    close_regkey(handle->sesskey);
    sfree(handle);
}

struct settings_r {
    HKEY sesskey;
};

settings_r *open_settings_r(const char *sessionname)
{
    if (!sessionname || !*sessionname)
        sessionname = "Default Settings";

    strbuf *sb = strbuf_new();
    escape_registry_key(sessionname, sb);
    HKEY sesskey = open_regkey_ro(HKEY_CURRENT_USER, puttystr, sb->s);
    strbuf_free(sb);

    if (!sesskey)
        return NULL;

    settings_r *handle = snew(settings_r);
    handle->sesskey = sesskey;
    return handle;
}

char *read_setting_s(settings_r *handle, const char *key)
{
    if (!handle)
        return NULL;
    return get_reg_sz(handle->sesskey, key);
}

int read_setting_i(settings_r *handle, const char *key, int defvalue)
{
    DWORD val;
    if (!handle || !get_reg_dword(handle->sesskey, key, &val))
        return defvalue;
    else
        return val;
}

FontSpec *read_setting_fontspec(settings_r *handle, const char *name)
{
    char *settingname;
    char *fontname;
    FontSpec *ret;
    int isbold, height, charset;

    fontname = read_setting_s(handle, name);
    if (!fontname)
        return NULL;

    settingname = dupcat(name, "IsBold");
    isbold = read_setting_i(handle, settingname, -1);
    sfree(settingname);
    if (isbold == -1) {
        sfree(fontname);
        return NULL;
    }

    settingname = dupcat(name, "CharSet");
    charset = read_setting_i(handle, settingname, -1);
    sfree(settingname);
    if (charset == -1) {
        sfree(fontname);
        return NULL;
    }

    settingname = dupcat(name, "Height");
    height = read_setting_i(handle, settingname, INT_MIN);
    sfree(settingname);
    if (height == INT_MIN) {
        sfree(fontname);
        return NULL;
    }

    ret = fontspec_new(fontname, isbold, height, charset);
    sfree(fontname);
    return ret;
}

void write_setting_fontspec(settings_w *handle,
                            const char *name, FontSpec *font)
{
    char *settingname;

    write_setting_s(handle, name, font->name);
    settingname = dupcat(name, "IsBold");
    write_setting_i(handle, settingname, font->isbold);
    sfree(settingname);
    settingname = dupcat(name, "CharSet");
    write_setting_i(handle, settingname, font->charset);
    sfree(settingname);
    settingname = dupcat(name, "Height");
    write_setting_i(handle, settingname, font->height);
    sfree(settingname);
}

Filename *read_setting_filename(settings_r *handle, const char *name)
{
    char *tmp = read_setting_s(handle, name);
    if (tmp) {
        Filename *ret = filename_from_str(tmp);
        sfree(tmp);
        return ret;
    } else
        return NULL;
}

void write_setting_filename(settings_w *handle,
                            const char *name, Filename *result)
{
    /*
     * When saving a session involving a Filename, we use the 'cpath'
     * member of the Filename structure, because otherwise we break
     * backwards compatibility with existing saved sessions.
     *
     * This means that 'exotic' filenames - those including Unicode
     * characters outside the host system's CP_ACP default code page -
     * cannot be represented faithfully, and saving and reloading a
     * Conf including one will break it.
     *
     * This can't be fixed without breaking backwards compatibility,
     * and if we're going to break compatibility then we should break
     * it good and hard (the Nanny Ogg principle), and devise a
     * completely fresh storage representation that fixes as many
     * other legacy problems as possible at the same time.
     */
    write_setting_s(handle, name, result->cpath); /* FIXME */
}

void close_settings_r(settings_r *handle)
{
    if (handle) {
        close_regkey(handle->sesskey);
        sfree(handle);
    }
}

void del_settings(const char *sessionname)
{
    HKEY rkey = open_regkey_rw(HKEY_CURRENT_USER, puttystr);
    if (!rkey)
        return;

    strbuf *sb = strbuf_new();
    escape_registry_key(sessionname, sb);
    del_regkey(rkey, sb->s);
    strbuf_free(sb);

    close_regkey(rkey);

    remove_session_from_jumplist(sessionname);
}

struct settings_e {
    HKEY key;
    int i;
};

settings_e *enum_settings_start(void)
{
    HKEY key = open_regkey_ro(HKEY_CURRENT_USER, puttystr);
    if (!key)
        return NULL;

    settings_e *e = snew(settings_e);
    if (e) {
        e->key = key;
        e->i = 0;
    }

    return e;
}

bool enum_settings_next(settings_e *e, strbuf *sb)
{
    char *name = enum_regkey(e->key, e->i);
    if (!name)
        return false;

    unescape_registry_key(name, sb);
    sfree(name);
    e->i++;
    return true;
}

void enum_settings_finish(settings_e *e)
{
    close_regkey(e->key);
    sfree(e);
}

static void hostkey_regname(strbuf *sb, const char *hostname,
                            int port, const char *keytype)
{
    put_fmt(sb, "%s@%d:", keytype, port);
    escape_registry_key(hostname, sb);
}

int check_stored_host_key(const char *hostname, int port,
                          const char *keytype, const char *key)
{
    /*
     * Read a saved key in from the registry and see what it says.
     */
    strbuf *regname = strbuf_new();
    hostkey_regname(regname, hostname, port, keytype);

    HKEY rkey = open_regkey_ro(HKEY_CURRENT_USER,
                               PUTTY_REG_POS "\\SshHostKeys");
    if (!rkey) {
        strbuf_free(regname);
        return 1;                      /* key does not exist in registry */
    }

    char *otherstr = get_reg_sz(rkey, regname->s);
    if (!otherstr && !strcmp(keytype, "rsa")) {
        /*
         * Key didn't exist. If the key type is RSA, we'll try
         * another trick, which is to look up the _old_ key format
         * under just the hostname and translate that.
         */
        char *justhost = regname->s + 1 + strcspn(regname->s, ":");
        char *oldstyle = get_reg_sz(rkey, justhost);

        if (oldstyle) {
            /*
             * The old format is two old-style bignums separated by
             * a slash. An old-style bignum is made of groups of
             * four hex digits: digits are ordered in sensible
             * (most to least significant) order within each group,
             * but groups are ordered in silly (least to most)
             * order within the bignum. The new format is two
             * ordinary C-format hex numbers (0xABCDEFG...XYZ, with
             * A nonzero except in the special case 0x0, which
             * doesn't appear anyway in RSA keys) separated by a
             * comma. All hex digits are lowercase in both formats.
             */
            strbuf *new = strbuf_new();
            const char *q = oldstyle;
            int i, j;

            for (i = 0; i < 2; i++) {
                int ndigits, nwords;
                put_datapl(new, PTRLEN_LITERAL("0x"));
                ndigits = strcspn(q, "/");      /* find / or end of string */
                nwords = ndigits / 4;
                /* now trim ndigits to remove leading zeros */
                while (q[(ndigits - 1) ^ 3] == '0' && ndigits > 1)
                    ndigits--;
                /* now move digits over to new string */
                for (j = ndigits; j-- > 0 ;)
                    put_byte(new, q[j ^ 3]);
                q += nwords * 4;
                if (*q) {
                    q++;                 /* eat the slash */
                    put_byte(new, ',');  /* add a comma */
                }
            }

            /*
             * Now _if_ this key matches, we'll enter it in the new
             * format. If not, we'll assume something odd went
             * wrong, and hyper-cautiously do nothing.
             */
            if (!strcmp(new->s, key)) {
                put_reg_sz(rkey, regname->s, new->s);
                otherstr = strbuf_to_str(new);
            } else {
                strbuf_free(new);
            }
        }

        sfree(oldstyle);
    }

    close_regkey(rkey);

    int compare = otherstr ? strcmp(otherstr, key) : -1;

    sfree(otherstr);
    strbuf_free(regname);

    if (!otherstr)
        return 1;                      /* key does not exist in registry */
    else if (compare)
        return 2;                      /* key is different in registry */
    else
        return 0;                      /* key matched OK in registry */
}

bool have_ssh_host_key(const char *hostname, int port,
                       const char *keytype)
{
    /*
     * If we have a host key, check_stored_host_key will return 0 or 2.
     * If we don't have one, it'll return 1.
     */
    return check_stored_host_key(hostname, port, keytype, "") != 1;
}

void store_host_key(Seat *seat, const char *hostname, int port,
                    const char *keytype, const char *key)
{
    strbuf *regname = strbuf_new();
    hostkey_regname(regname, hostname, port, keytype);

    HKEY rkey = create_regkey(HKEY_CURRENT_USER,
                              PUTTY_REG_POS "\\SshHostKeys");
    if (rkey) {
        put_reg_sz(rkey, regname->s, key);
        close_regkey(rkey);
    } /* else key does not exist in registry */

    strbuf_free(regname);
}

struct host_ca_enum {
    HKEY key;
    int i;
};

host_ca_enum *enum_host_ca_start(void)
{
    host_ca_enum *e;
    HKEY key;

    if (!(key = open_regkey_ro(HKEY_CURRENT_USER, host_ca_key)))
        return NULL;

    e = snew(host_ca_enum);
    e->key = key;
    e->i = 0;

    return e;
}

bool enum_host_ca_next(host_ca_enum *e, strbuf *sb)
{
    char *regbuf = enum_regkey(e->key, e->i);
    if (!regbuf)
        return false;

    unescape_registry_key(regbuf, sb);
    sfree(regbuf);
    e->i++;
    return true;
}

void enum_host_ca_finish(host_ca_enum *e)
{
    close_regkey(e->key);
    sfree(e);
}

host_ca *host_ca_load(const char *name)
{
    strbuf *sb;
    const char *s;

    sb = strbuf_new();
    escape_registry_key(name, sb);
    HKEY rkey = open_regkey_ro(HKEY_CURRENT_USER, host_ca_key, sb->s);
    strbuf_free(sb);

    if (!rkey)
        return NULL;

    host_ca *hca = host_ca_new();
    hca->name = dupstr(name);

    DWORD val;

    if ((s = get_reg_sz(rkey, "PublicKey")) != NULL)
        hca->ca_public_key = base64_decode_sb(ptrlen_from_asciz(s));

    if ((s = get_reg_sz(rkey, "Validity")) != NULL) {
        hca->validity_expression = strbuf_to_str(
            percent_decode_sb(ptrlen_from_asciz(s)));
    } else if ((sb = get_reg_multi_sz(rkey, "MatchHosts")) != NULL) {
        BinarySource src[1];
        BinarySource_BARE_INIT_PL(src, ptrlen_from_strbuf(sb));
        CertExprBuilder *eb = cert_expr_builder_new();

        const char *wc;
        while (wc = get_asciz(src), !get_err(src))
            cert_expr_builder_add(eb, wc);

        hca->validity_expression = cert_expr_expression(eb);
        cert_expr_builder_free(eb);
    }

    if (get_reg_dword(rkey, "PermitRSASHA1", &val))
        hca->opts.permit_rsa_sha1 = val;
    if (get_reg_dword(rkey, "PermitRSASHA256", &val))
        hca->opts.permit_rsa_sha256 = val;
    if (get_reg_dword(rkey, "PermitRSASHA512", &val))
        hca->opts.permit_rsa_sha512 = val;

    close_regkey(rkey);
    return hca;
}

char *host_ca_save(host_ca *hca)
{
    if (!*hca->name)
        return dupstr("CA record must have a name");

    strbuf *sb = strbuf_new();
    escape_registry_key(hca->name, sb);
    HKEY rkey = create_regkey(HKEY_CURRENT_USER, host_ca_key, sb->s);
    if (!rkey) {
        char *err = dupprintf("Unable to create registry key\n"
                              "HKEY_CURRENT_USER\\%s\\%s", host_ca_key, sb->s);
        strbuf_free(sb);
        return err;
    }
    strbuf_free(sb);

    strbuf *base64_pubkey = base64_encode_sb(
        ptrlen_from_strbuf(hca->ca_public_key), 0);
    put_reg_sz(rkey, "PublicKey", base64_pubkey->s);
    strbuf_free(base64_pubkey);

    strbuf *validity = percent_encode_sb(
        ptrlen_from_asciz(hca->validity_expression), NULL);
    put_reg_sz(rkey, "Validity", validity->s);
    strbuf_free(validity);

    put_reg_dword(rkey, "PermitRSASHA1", hca->opts.permit_rsa_sha1);
    put_reg_dword(rkey, "PermitRSASHA256", hca->opts.permit_rsa_sha256);
    put_reg_dword(rkey, "PermitRSASHA512", hca->opts.permit_rsa_sha512);

    close_regkey(rkey);
    return NULL;
}

char *host_ca_delete(const char *name)
{
    HKEY rkey = open_regkey_rw(HKEY_CURRENT_USER, host_ca_key);
    if (!rkey)
        return NULL;

    strbuf *sb = strbuf_new();
    escape_registry_key(name, sb);
    del_regkey(rkey, sb->s);
    strbuf_free(sb);

    return NULL;
}

/*
 * Open (or delete) the random seed file.
 */
enum { DEL, OPEN_R, OPEN_W };
static bool try_random_seed(char const *path, int action, HANDLE *ret)
{
    if (action == DEL) {
        if (!DeleteFile(path) && GetLastError() != ERROR_FILE_NOT_FOUND) {
            nonfatal("Unable to delete '%s': %s", path,
                     win_strerror(GetLastError()));
        }
        *ret = INVALID_HANDLE_VALUE;
        return false;                  /* so we'll do the next ones too */
    }

    *ret = CreateFile(path,
                      action == OPEN_W ? GENERIC_WRITE : GENERIC_READ,
                      action == OPEN_W ? 0 : (FILE_SHARE_READ |
                                              FILE_SHARE_WRITE),
                      NULL,
                      action == OPEN_W ? CREATE_ALWAYS : OPEN_EXISTING,
                      action == OPEN_W ? FILE_ATTRIBUTE_NORMAL : 0,
                      NULL);

    return (*ret != INVALID_HANDLE_VALUE);
}

static bool try_random_seed_and_free(char *path, int action, HANDLE *hout)
{
    bool retd = try_random_seed(path, action, hout);
    sfree(path);
    return retd;
}

static HANDLE access_random_seed(int action)
{
    HANDLE rethandle;

    /*
     * Iterate over a selection of possible random seed paths until
     * we find one that works.
     *
     * We do this iteration separately for reading and writing,
     * meaning that we will automatically migrate random seed files
     * if a better location becomes available (by reading from the
     * best location in which we actually find one, and then
     * writing to the best location in which we can _create_ one).
     */

    /*
     * First, try the location specified by the user in the
     * Registry, if any.
     */
    {
        HKEY rkey = open_regkey_ro(HKEY_CURRENT_USER, PUTTY_REG_POS);
        if (rkey) {
            char *regpath = get_reg_sz(rkey, "RandSeedFile");
            close_regkey(rkey);
            if (regpath) {
                bool success = try_random_seed(regpath, action, &rethandle);
                sfree(regpath);
                if (success)
                    return rethandle;
            }
        }
    }

    /*
     * Next, try the user's local Application Data directory,
     * followed by their non-local one. This is found using the
     * SHGetFolderPath function, which won't be present on all
     * versions of Windows.
     */
    if (!tried_shgetfolderpath) {
        /* This is likely only to bear fruit on systems with IE5+
         * installed, or WinMe/2K+. There is some faffing with
         * SHFOLDER.DLL we could do to try to find an equivalent
         * on older versions of Windows if we cared enough.
         * However, the invocation below requires IE5+ anyway,
         * so stuff that. */
        shell32_module = load_system32_dll("shell32.dll");
        GET_WINDOWS_FUNCTION(shell32_module, SHGetFolderPathA);
        tried_shgetfolderpath = true;
    }
    if (p_SHGetFolderPathA) {
        char profile[MAX_PATH + 1];
        if (SUCCEEDED(p_SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA,
                                         NULL, SHGFP_TYPE_CURRENT, profile)) &&
            try_random_seed_and_free(dupcat(profile, "\\PUTTY.RND"),
                                     action, &rethandle))
            return rethandle;

        if (SUCCEEDED(p_SHGetFolderPathA(NULL, CSIDL_APPDATA,
                                         NULL, SHGFP_TYPE_CURRENT, profile)) &&
            try_random_seed_and_free(dupcat(profile, "\\PUTTY.RND"),
                                     action, &rethandle))
            return rethandle;
    }

    /*
     * Failing that, try %HOMEDRIVE%%HOMEPATH% as a guess at the
     * user's home directory.
     */
    {
        char drv[MAX_PATH], path[MAX_PATH];

        DWORD drvlen = GetEnvironmentVariable("HOMEDRIVE", drv, sizeof(drv));
        DWORD pathlen = GetEnvironmentVariable("HOMEPATH", path, sizeof(path));

        /* We permit %HOMEDRIVE% to expand to an empty string, but if
         * %HOMEPATH% does that, we abort the attempt. Same if either
         * variable overflows its buffer. */
        if (drvlen == 0)
            drv[0] = '\0';

        if (drvlen < lenof(drv) && pathlen < lenof(path) && pathlen > 0 &&
            try_random_seed_and_free(
                dupcat(drv, path, "\\PUTTY.RND"), action, &rethandle))
            return rethandle;
    }

    /*
     * And finally, fall back to C:\WINDOWS.
     */
    {
        char windir[MAX_PATH];
        DWORD len = GetWindowsDirectory(windir, sizeof(windir));
        if (len < lenof(windir) &&
            try_random_seed_and_free(
                dupcat(windir, "\\PUTTY.RND"), action, &rethandle))
            return rethandle;
    }

    /*
     * If even that failed, give up.
     */
    return INVALID_HANDLE_VALUE;
}

void read_random_seed(noise_consumer_t consumer)
{
    HANDLE seedf = access_random_seed(OPEN_R);

    if (seedf != INVALID_HANDLE_VALUE) {
        while (1) {
            char buf[1024];
            DWORD len;

            if (ReadFile(seedf, buf, sizeof(buf), &len, NULL) && len)
                consumer(buf, len);
            else
                break;
        }
        CloseHandle(seedf);
    }
}

void write_random_seed(void *data, int len)
{
    HANDLE seedf = access_random_seed(OPEN_W);

    if (seedf != INVALID_HANDLE_VALUE) {
        DWORD lenwritten;

        WriteFile(seedf, data, len, &lenwritten, NULL);
        CloseHandle(seedf);
    }
}

/*
 * Internal function supporting the jump list registry code. All the
 * functions to add, remove and read the list have substantially
 * similar content, so this is a generalisation of all of them which
 * transforms the list in the registry by prepending 'add' (if
 * non-null), removing 'rem' from what's left (if non-null), and
 * returning the resulting concatenated list of strings in 'out' (if
 * non-null).
 */
static int transform_jumplist_registry(
    const char *add, const char *rem, char **out)
{
    HKEY rkey = create_regkey(HKEY_CURRENT_USER, reg_jumplist_key);
    if (!rkey)
        return JUMPLISTREG_ERROR_KEYOPENCREATE_FAILURE;

    /* Get current list of saved sessions in the registry. */
    strbuf *oldlist = get_reg_multi_sz(rkey, reg_jumplist_value);
    if (!oldlist) {
        /* Start again with the empty list. */
        oldlist = strbuf_new();
        put_data(oldlist, "\0\0", 2);
    }

    /*
     * Modify the list, if we're modifying.
     */
    bool write_failure = false;
    if (add || rem) {
        BinarySource src[1];
        BinarySource_BARE_INIT_PL(src, ptrlen_from_strbuf(oldlist));
        strbuf *newlist = strbuf_new();

        /* First add the new item to the beginning of the list. */
        if (add)
            put_asciz(newlist, add);

        /* Now add the existing list, taking care to leave out the removed
         * item, if it was already in the existing list. */
        while (true) {
            const char *olditem = get_asciz(src);
            if (get_err(src))
                break;

            if (!rem || strcmp(olditem, rem) != 0) {
                /* Check if this is a valid session, otherwise don't add. */
                settings_r *psettings_tmp = open_settings_r(olditem);
                if (psettings_tmp != NULL) {
                    close_settings_r(psettings_tmp);
                    put_asciz(newlist, olditem);
                }
            }
        }

        /* Save the new list to the registry. */
        write_failure = !put_reg_multi_sz(rkey, reg_jumplist_value, newlist);

        strbuf_free(oldlist);
        oldlist = newlist;
    }

    close_regkey(rkey);

    if (out && !write_failure)
        *out = strbuf_to_str(oldlist);
    else
        strbuf_free(oldlist);

    if (write_failure)
        return JUMPLISTREG_ERROR_VALUEWRITE_FAILURE;
    else
        return JUMPLISTREG_OK;
}

/* Adds a new entry to the jumplist entries in the registry. */
int add_to_jumplist_registry(const char *item)
{
    return transform_jumplist_registry(item, item, NULL);
}

/* Removes an item from the jumplist entries in the registry. */
int remove_from_jumplist_registry(const char *item)
{
    return transform_jumplist_registry(NULL, item, NULL);
}

/* Returns the jumplist entries from the registry. Caller must free
 * the returned pointer. */
char *get_jumplist_registry_entries (void)
{
    char *list_value;

    if (transform_jumplist_registry(NULL,NULL,&list_value) != JUMPLISTREG_OK) {
        list_value = snewn(2, char);
        *list_value = '\0';
        *(list_value + 1) = '\0';
    }
    return list_value;
}

/*
 * Recursively delete a registry key and everything under it.
 */
static void registry_recursive_remove(HKEY key)
{
    char *name;

    DWORD i = 0;
    while ((name = enum_regkey(key, i)) != NULL) {
        HKEY subkey = open_regkey_rw(key, name);
        if (subkey) {
            registry_recursive_remove(subkey);
            close_regkey(subkey);
        }
        del_regkey(key, name);
        sfree(name);
    }
}

void cleanup_all(void)
{
    /* ------------------------------------------------------------
     * Wipe out the random seed file, in all of its possible
     * locations.
     */
    access_random_seed(DEL);

    /* ------------------------------------------------------------
     * Ask Windows to delete any jump list information associated
     * with this installation of PuTTY.
     */
    clear_jumplist();

    /* ------------------------------------------------------------
     * Destroy all registry information associated with PuTTY.
     */

    /*
     * Open the main PuTTY registry key and remove everything in it.
     */
    HKEY key = open_regkey_rw(HKEY_CURRENT_USER, PUTTY_REG_POS);
    if (key) {
        registry_recursive_remove(key);
        close_regkey(key);
    }
    /*
     * Now open the parent key and remove the PuTTY main key. Once
     * we've done that, see if the parent key has any other
     * children.
     */
    if ((key = open_regkey_rw(HKEY_CURRENT_USER, PUTTY_REG_PARENT)) != NULL) {
        del_regkey(key, PUTTY_REG_PARENT_CHILD);
        char *name = enum_regkey(key, 0);
        close_regkey(key);

        /*
         * If the parent key had no other children, we must delete
         * it in its turn. That means opening the _grandparent_
         * key.
         */
        if (name) {
            sfree(name);
        } else {
            if ((key = open_regkey_rw(HKEY_CURRENT_USER,
                                      PUTTY_REG_GPARENT)) != NULL) {
                del_regkey(key, PUTTY_REG_GPARENT_CHILD);
                close_regkey(key);
            }
        }
    }
    /*
     * Now we're done.
     */
}

#endif /* WIN32S_COMPAT */
