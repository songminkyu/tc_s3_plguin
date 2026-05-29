/*
 * plugin.c  -  Total Commander WFX Plugin for Amazon S3
 *
 * Language: C  (compiled as 64-bit DLL with MinGW-w64 or MSVC)
 * WFX SDK : www.ghisler.com/plugins.htm
 *
 * Directory structure inside TC:
 *   \                       <- root: shows all profiles
 *   \<profile>\             <- profile: shows all buckets
 *   \<profile>\<bucket>\    <- bucket contents
 *   \<profile>\<bucket>\<key>
 *
 * AWS credentials read from: %USERPROFILE%\.aws\credentials
 */
#define _CRT_SECURE_NO_WARNINGS
#include "wfxtypes.h"
#include "aws_s3.h"

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ════════════════════════════════════════════════
   State
   ════════════════════════════════════════════════ */

static int               g_plugin_nr  = 0;
static tProgressProcW    g_progress   = NULL;
static tLogProcW         g_log        = NULL;
static tRequestProcW     g_request    = NULL;
static tCryptProcW       g_crypt      = NULL;
static int               g_crypt_nr   = 0;

static S3Profile**       g_profiles   = NULL;
static int               g_profile_cnt= 0;
static S3Context*        g_s3         = NULL;   /* current S3 context */
static char              g_cur_profile[AWS_MAX_PROFILE_LEN] = "";

/* Simple abort flag */
static volatile int g_abort = 0;

/* ════════════════════════════════════════════════
   Helper: path parsing
   \<profile>\<bucket>\[key...]
   ════════════════════════════════════════════════ */

typedef struct {
    char profile[AWS_MAX_PROFILE_LEN];
    char bucket [AWS_MAX_BUCKET_LEN];
    char key    [AWS_MAX_PATH_LEN];
    int  depth; /* 0=root, 1=profile, 2=bucket, 3=key */
} TcPath;

static void parse_tc_path(const wchar_t* remote, TcPath* out) {
    memset(out, 0, sizeof(*out));
    /* Convert to narrow */
    char narrow[AWS_MAX_PATH_LEN*2];
    WideCharToMultiByte(CP_UTF8,0,remote,-1,narrow,sizeof(narrow),NULL,NULL);

    /* Skip leading backslash */
    char* p = narrow;
    while (*p == '\\') p++;
    if (!*p) { out->depth = 0; return; }

    /* profile */
    char* slash = strchr(p, '\\');
    if (!slash) {
        strncpy(out->profile, p, AWS_MAX_PROFILE_LEN-1);
        out->depth = 1;
        return;
    }
    size_t n = (size_t)(slash - p);
    strncpy(out->profile, p, n < AWS_MAX_PROFILE_LEN ? n : AWS_MAX_PROFILE_LEN-1);
    p = slash + 1;
    while (*p == '\\') p++;
    if (!*p) { out->depth = 1; return; }

    /* bucket */
    slash = strchr(p, '\\');
    if (!slash) {
        strncpy(out->bucket, p, AWS_MAX_BUCKET_LEN-1);
        out->depth = 2;
        return;
    }
    n = (size_t)(slash - p);
    strncpy(out->bucket, p, n < AWS_MAX_BUCKET_LEN ? n : AWS_MAX_BUCKET_LEN-1);
    p = slash + 1;
    while (*p == '\\') p++;
    if (!*p) { out->depth = 2; return; }

    /* key: replace backslash with forward slash */
    strncpy(out->key, p, AWS_MAX_PATH_LEN-1);
    for (char* c = out->key; *c; c++) if (*c=='\\') *c='/';
    out->depth = 3;
}

/* Connect to S3 using the named profile.
   Returns 1 on success, 0 if profile not found */
static int connect_profile(const char* profile_name) {
    if (g_s3) { s3_destroy(g_s3); g_s3 = NULL; }
    for (int i = 0; i < g_profile_cnt; i++) {
        S3Profile* p = g_profiles[i];
        if (_stricmp(p->name, profile_name) == 0) {
            g_s3 = s3_create(p->access_key_id, p->secret_access_key, p->region);
            strncpy(g_cur_profile, profile_name, AWS_MAX_PROFILE_LEN-1);
            return g_s3 != NULL;
        }
    }
    return 0;
}

/* Ensure g_s3 is connected to the profile mentioned in path.
   Reconnects lazily. */
static void ensure_connected(const TcPath* tp) {
    if (tp->depth >= 1 && tp->profile[0]) {
        if (!g_s3 || _stricmp(g_cur_profile, tp->profile) != 0) {
            connect_profile(tp->profile);
        }
    }
}

/* ════════════════════════════════════════════════
   FindFirst enumeration state
   We store a linked-list of "virtual" entries returned per-path.
   Only one enumeration active at a time (TC is single-threaded per plugin).
   ════════════════════════════════════════════════ */

typedef struct VEntry {
    wchar_t      name[MAX_PATH];
    int          is_dir;
    __int64      size;
    FILETIME     ft;
    struct VEntry* next;
} VEntry;

static VEntry* g_enum_head  = NULL;
static VEntry* g_enum_cur   = NULL;

static void free_ventry_list(void) {
    while (g_enum_head) {
        VEntry* n = g_enum_head->next;
        free(g_enum_head);
        g_enum_head = n;
    }
    g_enum_cur = NULL;
}

/* Convert ISO-8601 string to FILETIME */
static FILETIME iso8601_to_filetime(const char* s) {
    FILETIME ft = {0,0};
    SYSTEMTIME st = {0};
    /* "2023-01-15T12:34:56.000Z" */
    if (strlen(s) >= 19) {
        sscanf(s, "%4hd-%2hd-%2hdT%2hd:%2hd:%2hd",
               &st.wYear, &st.wMonth, &st.wDay,
               &st.wHour, &st.wMinute, &st.wSecond);
    }
    FILETIME local_ft;
    SystemTimeToFileTime(&st, &local_ft);
    LocalFileTimeToFileTime(&local_ft, &ft);
    return ft;
}

static VEntry* alloc_ventry(const char* name_utf8, int is_dir, __int64 size, FILETIME ft) {
    VEntry* e = (VEntry*)calloc(1, sizeof(VEntry));
    MultiByteToWideChar(CP_UTF8, 0, name_utf8, -1, e->name, MAX_PATH);
    e->is_dir = is_dir;
    e->size   = size;
    e->ft     = ft;
    return e;
}

static void append_ventry(VEntry** head, VEntry* e) {
    e->next = NULL;
    if (!*head) { *head = e; return; }
    VEntry* t = *head;
    while (t->next) t = t->next;
    t->next = e;
}

static void fill_find_data(WIN32_FIND_DATAW* fd, const VEntry* e) {
    memset(fd, 0, sizeof(*fd));
    wcsncpy(fd->cFileName, e->name, MAX_PATH-1);
    fd->dwFileAttributes = e->is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    fd->ftCreationTime   = e->ft;
    fd->ftLastWriteTime  = e->ft;
    fd->ftLastAccessTime = e->ft;
    if (!e->is_dir) {
        fd->nFileSizeLow  = (DWORD)(e->size & 0xFFFFFFFF);
        fd->nFileSizeHigh = (DWORD)(e->size >> 32);
    }
}

/* ════════════════════════════════════════════════
   DLL entry point
   ════════════════════════════════════════════════ */

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)hInst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_s3) { s3_destroy(g_s3); g_s3 = NULL; }
        s3_free_profiles(g_profiles, g_profile_cnt);
        free_ventry_list();
    }
    return TRUE;
}

/* ════════════════════════════════════════════════
   WFX Exports
   ════════════════════════════════════════════════ */

/* FsInitW - called once when plugin is loaded */
__declspec(dllexport)
int __stdcall FsInitW(int PluginNr,
                       tProgressProcW pProgressProc,
                       tLogProcW pLogProc,
                       tRequestProcW pRequestProc) {
    g_plugin_nr = PluginNr;
    g_progress  = pProgressProc;
    g_log       = pLogProc;
    g_request   = pRequestProc;

    /* Load AWS profiles */
    s3_free_profiles(g_profiles, g_profile_cnt);
    g_profiles    = s3_load_profiles(&g_profile_cnt);
    g_cur_profile[0] = '\0';

    /* Auto-connect to "default" profile if available */
    if (g_profile_cnt > 0) {
        connect_profile(g_profiles[0]->name);
    }

    return 0;
}

/* FsGetDefRootName - shown in TC network neighbourhood */
__declspec(dllexport)
void __stdcall FsGetDefRootName(char* DefRootName, int MaxLen) {
    strncpy(DefRootName, "S3", (size_t)MaxLen - 1);
}

/* FsFindFirstW - start directory listing */
__declspec(dllexport)
HANDLE __stdcall FsFindFirstW(const wchar_t* Path, WIN32_FIND_DATAW* FindData) {
    free_ventry_list();
    g_abort = 0;

    TcPath tp;
    parse_tc_path(Path, &tp);

    VEntry* head = NULL;

    if (tp.depth == 0) {
        /* Root: list profiles */
        if (g_profile_cnt == 0) {
            SetLastError(ERROR_NO_MORE_FILES);
            return INVALID_HANDLE_VALUE;
        }
        for (int i = 0; i < g_profile_cnt; i++) {
            FILETIME ft = {0,0};
            VEntry* e = alloc_ventry(g_profiles[i]->name, 1, 0, ft);
            append_ventry(&head, e);
        }
    } else if (tp.depth == 1) {
        /* Profile dir: list buckets */
        ensure_connected(&tp);
        if (!g_s3) { SetLastError(ERROR_NO_MORE_FILES); return INVALID_HANDLE_VALUE; }
        S3BucketEntry* buckets = s3_list_buckets(g_s3);
        if (!buckets) { SetLastError(ERROR_NO_MORE_FILES); return INVALID_HANDLE_VALUE; }
        for (S3BucketEntry* b = buckets; b; b = b->next) {
            FILETIME ft = iso8601_to_filetime(b->creation_date);
            VEntry* e = alloc_ventry(b->name, 1, 0, ft);
            append_ventry(&head, e);
        }
        s3_free_buckets(buckets);
    } else if (tp.depth >= 2) {
        /* Bucket or sub-folder: list objects */
        ensure_connected(&tp);
        if (!g_s3) { SetLastError(ERROR_NO_MORE_FILES); return INVALID_HANDLE_VALUE; }

        const char* prefix = (tp.depth == 3) ? tp.key : "";
        /* Ensure prefix ends with / if non-empty */
        char prefix_with_slash[AWS_MAX_PATH_LEN] = "";
        if (prefix && *prefix) {
            strncpy(prefix_with_slash, prefix, sizeof(prefix_with_slash)-2);
            size_t plen = strlen(prefix_with_slash);
            if (plen > 0 && prefix_with_slash[plen-1] != '/')
                prefix_with_slash[plen] = '/';
        }

        S3Object* objs = s3_list_objects(g_s3, tp.bucket,
                                          prefix_with_slash[0] ? prefix_with_slash : NULL, '/');
        if (!objs) { SetLastError(ERROR_NO_MORE_FILES); return INVALID_HANDLE_VALUE; }

        for (S3Object* o = objs; o; o = o->next) {
            /* Compute display name: strip prefix, strip trailing / */
            const char* display = o->key;
            size_t plen = prefix_with_slash[0] ? strlen(prefix_with_slash) : 0;
            if (plen && strncmp(display, prefix_with_slash, plen) == 0)
                display += plen;
            if (!*display) continue; /* skip the prefix entry itself */

            /* Remove trailing slash for display */
            char disp_buf[AWS_MAX_PATH_LEN];
            strncpy(disp_buf, display, sizeof(disp_buf)-1);
            size_t dl = strlen(disp_buf);
            if (dl > 0 && disp_buf[dl-1] == '/') disp_buf[dl-1] = '\0';
            if (!disp_buf[0]) continue;

            FILETIME ft = o->is_prefix ? (FILETIME){0,0} : iso8601_to_filetime(o->last_modified);
            VEntry* e = alloc_ventry(disp_buf, o->is_prefix || o->key[strlen(o->key)-1]=='/', o->size, ft);
            append_ventry(&head, e);
        }
        s3_free_objects(objs);
    }

    if (!head) {
        SetLastError(ERROR_NO_MORE_FILES);
        return INVALID_HANDLE_VALUE;
    }

    g_enum_head = head;
    g_enum_cur  = head;
    fill_find_data(FindData, g_enum_cur);
    g_enum_cur = g_enum_cur->next;

    return (HANDLE)1; /* non-zero handle */
}

/* FsFindNextW */
__declspec(dllexport)
BOOL __stdcall FsFindNextW(HANDLE Hdl, WIN32_FIND_DATAW* FindData) {
    (void)Hdl;
    if (!g_enum_cur) return FALSE;
    fill_find_data(FindData, g_enum_cur);
    g_enum_cur = g_enum_cur->next;
    return TRUE;
}

/* FsFindClose */
__declspec(dllexport)
int __stdcall FsFindClose(HANDLE Hdl) {
    (void)Hdl;
    free_ventry_list();
    return 0;
}

/* FsGetFileW - download file from S3 to local */
__declspec(dllexport)
int __stdcall FsGetFileW(const wchar_t* RemoteName, wchar_t* LocalName,
                          int CopyFlags, RemoteInfoStruct* RemoteInfo) {
    (void)CopyFlags; (void)RemoteInfo;
    TcPath tp;
    parse_tc_path(RemoteName, &tp);
    if (tp.depth < 3 || !tp.key[0]) return FS_FILE_NOTSUPPORTED;

    ensure_connected(&tp);
    if (!g_s3) return FS_FILE_READERROR;

    char local[MAX_PATH];
    WideCharToMultiByte(CP_ACP,0,LocalName,-1,local,MAX_PATH,NULL,NULL);

    if (g_progress)
        g_progress(g_plugin_nr, NULL, LocalName, 0);

    int ok = s3_get_object(g_s3, tp.bucket, tp.key, local);

    if (g_progress)
        g_progress(g_plugin_nr, NULL, LocalName, 100);

    return ok ? FS_FILE_OK : FS_FILE_READERROR;
}

/* FsPutFileW - upload file to S3 */
__declspec(dllexport)
int __stdcall FsPutFileW(const wchar_t* LocalName, const wchar_t* RemoteName,
                          int CopyFlags) {
    (void)CopyFlags;
    TcPath tp;
    parse_tc_path(RemoteName, &tp);
    if (tp.depth < 2 || !tp.bucket[0]) return FS_FILE_NOTSUPPORTED;

    ensure_connected(&tp);
    if (!g_s3) return FS_FILE_WRITEERROR;

    char local[MAX_PATH];
    WideCharToMultiByte(CP_ACP,0,LocalName,-1,local,MAX_PATH,NULL,NULL);

    /* Build key: use the remote name relative to bucket */
    char key[AWS_MAX_PATH_LEN] = "";
    if (tp.depth >= 3 && tp.key[0]) strncpy(key, tp.key, sizeof(key)-1);
    else {
        /* just the filename */
        const wchar_t* fn = wcsrchr(LocalName, L'\\');
        char fn_a[MAX_PATH];
        WideCharToMultiByte(CP_UTF8,0, fn ? fn+1 : LocalName,-1,fn_a,MAX_PATH,NULL,NULL);
        strncpy(key, fn_a, sizeof(key)-1);
    }

    if (g_progress) g_progress(g_plugin_nr, LocalName, NULL, 0);
    int ok = s3_put_object(g_s3, tp.bucket, key, local);
    if (g_progress) g_progress(g_plugin_nr, LocalName, NULL, 100);

    return ok ? FS_FILE_OK : FS_FILE_WRITEERROR;
}

/* FsDeleteFileW */
__declspec(dllexport)
BOOL __stdcall FsDeleteFileW(const wchar_t* RemoteName) {
    TcPath tp;
    parse_tc_path(RemoteName, &tp);
    if (tp.depth < 3 || !tp.key[0]) return FALSE;
    ensure_connected(&tp);
    if (!g_s3) return FALSE;
    return s3_delete_object(g_s3, tp.bucket, tp.key) ? TRUE : FALSE;
}

/* FsMkDirW - create bucket (depth 2) or folder object (depth 3+) */
__declspec(dllexport)
BOOL __stdcall FsMkDirW(const wchar_t* Path) {
    TcPath tp;
    parse_tc_path(Path, &tp);

    if (tp.depth == 2 && tp.bucket[0]) {
        /* Create bucket */
        ensure_connected(&tp);
        if (!g_s3) return FALSE;
        return s3_create_bucket(g_s3, tp.bucket) ? TRUE : FALSE;
    }
    if (tp.depth >= 3 && tp.key[0]) {
        ensure_connected(&tp);
        if (!g_s3) return FALSE;
        char folder_key[AWS_MAX_PATH_LEN];
        strncpy(folder_key, tp.key, sizeof(folder_key)-2);
        size_t kl = strlen(folder_key);
        if (kl == 0 || folder_key[kl-1] != '/') { folder_key[kl]='/'; folder_key[kl+1]='\0'; }
        return s3_put_folder(g_s3, tp.bucket, folder_key) ? TRUE : FALSE;
    }
    return FALSE;
}

/* FsRemoveDirW */
__declspec(dllexport)
BOOL __stdcall FsRemoveDirW(const wchar_t* RemoteName) {
    TcPath tp;
    parse_tc_path(RemoteName, &tp);
    if (tp.depth == 2 && tp.bucket[0]) {
        ensure_connected(&tp);
        if (!g_s3) return FALSE;
        return s3_delete_bucket(g_s3, tp.bucket) ? TRUE : FALSE;
    }
    if (tp.depth >= 3 && tp.key[0]) {
        ensure_connected(&tp);
        if (!g_s3) return FALSE;
        char folder_key[AWS_MAX_PATH_LEN];
        strncpy(folder_key, tp.key, sizeof(folder_key)-2);
        size_t kl = strlen(folder_key);
        if (kl == 0 || folder_key[kl-1] != '/') { folder_key[kl]='/'; folder_key[kl+1]='\0'; }
        return s3_delete_object(g_s3, tp.bucket, folder_key) ? TRUE : FALSE;
    }
    return FALSE;
}

/* FsRenMovFileW - copy + (optionally) delete */
__declspec(dllexport)
int __stdcall FsRenMovFileW(const wchar_t* OldName, const wchar_t* NewName,
                              BOOL Move, BOOL OverWrite, RemoteInfoStruct* ri) {
    (void)OverWrite; (void)ri;
    TcPath src, dst;
    parse_tc_path(OldName, &src);
    parse_tc_path(NewName, &dst);
    if (src.depth < 3 || dst.depth < 3) return FS_FILE_NOTSUPPORTED;

    ensure_connected(&src);
    if (!g_s3) return FS_FILE_READERROR;

    int ok = s3_copy_object(g_s3, src.bucket, src.key, dst.bucket, dst.key);
    if (!ok) return FS_FILE_WRITEERROR;
    if (Move) s3_delete_object(g_s3, src.bucket, src.key);
    return FS_FILE_OK;
}

/* FsExecuteFileW - open folders, handle special actions */
__declspec(dllexport)
int __stdcall FsExecuteFileW(HWND MainWin, wchar_t* RemoteName, const wchar_t* Verb) {
    (void)MainWin; (void)Verb;
    return FS_EXEC_YOURSELF; /* let TC handle directory navigation */
}

/* FsExtractCustomIconW - return custom icon */
__declspec(dllexport)
int __stdcall FsExtractCustomIconW(const wchar_t* RemoteName, int ExtractFlags, HICON* TheIcon) {
    (void)RemoteName; (void)ExtractFlags; (void)TheIcon;
    return FS_ICON_USEDEFAULT;
}

/* FsStatusInfoW */
__declspec(dllexport)
void __stdcall FsStatusInfoW(const wchar_t* RemoteDir, int InfoStartEnd, int InfoOperation) {
    (void)RemoteDir; (void)InfoStartEnd; (void)InfoOperation;
}

/* FsSetCryptCallbackW */
__declspec(dllexport)
void __stdcall FsSetCryptCallbackW(tCryptProcW CryptProc, int CryptoNr, int Flags) {
    g_crypt    = CryptProc;
    g_crypt_nr = CryptoNr;
    (void)Flags;
}

/* FsSetDefaultParams */
__declspec(dllexport)
void __stdcall FsSetDefaultParams(FsDefaultParamStruct* dps) {
    (void)dps;
}

/* FsDisconnectW */
__declspec(dllexport)
BOOL __stdcall FsDisconnectW(const wchar_t* DisconnectRoot) {
    (void)DisconnectRoot;
    if (g_s3) { s3_destroy(g_s3); g_s3 = NULL; g_cur_profile[0]='\0'; }
    return TRUE;
}

/* FsSetAttrW */
__declspec(dllexport)
BOOL __stdcall FsSetAttrW(const wchar_t* RemoteName, int NewAttr) {
    (void)RemoteName; (void)NewAttr;
    return FALSE;
}

/* FsSetTimeW */
__declspec(dllexport)
BOOL __stdcall FsSetTimeW(const wchar_t* RemoteName,
                           FILETIME* CreationTime, FILETIME* LastAccessTime, FILETIME* LastWriteTime) {
    (void)RemoteName; (void)CreationTime; (void)LastAccessTime; (void)LastWriteTime;
    return FALSE;
}

/* FsGetPreviewBitmapW */
__declspec(dllexport)
int __stdcall FsGetPreviewBitmapW(const wchar_t* RemoteName, int width, int height, HBITMAP* ReturnedBitmap) {
    (void)RemoteName; (void)width; (void)height; (void)ReturnedBitmap;
    return 0;
}

/* FsLinksToLocalFiles */
__declspec(dllexport)
BOOL __stdcall FsLinksToLocalFiles(void) {
    return FALSE;
}

/* FsGetLocalNameW */
__declspec(dllexport)
BOOL __stdcall FsGetLocalNameW(wchar_t* RemoteName, int maxlen) {
    (void)RemoteName; (void)maxlen;
    return FALSE;
}

/* FsConnectW */
__declspec(dllexport)
void __stdcall FsConnectW(const wchar_t* ConnectString) {
    (void)ConnectString;
}
