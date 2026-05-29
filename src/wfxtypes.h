/*
 * wfxtypes.h - Total Commander WFX Plugin Type Definitions
 * Based on the official Total Commander WFX plugin SDK
 */
#pragma once
#ifndef WFXTYPES_H
#define WFXTYPES_H

#include <windows.h>
#include <stdint.h>

/* ─── Return codes for FsGetFile / FsPutFile ─── */
#define FS_FILE_OK                   0
#define FS_FILE_EXISTS               1
#define FS_FILE_NOTFOUND             2
#define FS_FILE_READERROR            3
#define FS_FILE_WRITEERROR           4
#define FS_FILE_USERABORT            5
#define FS_FILE_NOTSUPPORTED         6
#define FS_FILE_EXISTSRESUMEALLOWED  7

/* ─── Return codes for FsExecuteFile ─── */
#define FS_EXEC_OK        0
#define FS_EXEC_ERROR     1
#define FS_EXEC_YOURSELF -1
#define FS_EXEC_SYMLINK  -2

/* ─── CopyFlags ─── */
#define FS_COPYFLAGS_OVERWRITE             1
#define FS_COPYFLAGS_RESUME                2
#define FS_COPYFLAGS_MOVE                  4
#define FS_COPYFLAGS_EXISTS_SAMECASE       8
#define FS_COPYFLAGS_EXISTS_DIFFERENTCASE 16

/* ─── RequestType for FsRequestProc ─── */
#define RT_Other             0
#define RT_UserName          1
#define RT_Password          2
#define RT_Account           3
#define RT_UserNameFirewall  4
#define RT_PasswordFirewall  5
#define RT_TargetDir         6
#define RT_URL               7
#define RT_MsgOK             8
#define RT_MsgYesNo          9
#define RT_MsgOKCancel      10

/* ─── Icon return values ─── */
#define FS_ICON_USEDEFAULT        0
#define FS_ICON_EXTRACTED         1
#define FS_ICON_EXTRACTED_DESTROY 2
#define FS_ICON_DELAYED           3
#define FS_ICONFLAG_SMALL         1
#define FS_ICONFLAG_BACKGROUND    2

/* ─── Status info ─── */
#define FS_STATUS_START 0
#define FS_STATUS_END   1
#define FS_STATUS_OP_LIST           1
#define FS_STATUS_OP_GET_SINGLE     2
#define FS_STATUS_OP_GET_MULTI      3
#define FS_STATUS_OP_PUT_SINGLE     4
#define FS_STATUS_OP_PUT_MULTI      5
#define FS_STATUS_OP_RENMOV_SINGLE  6
#define FS_STATUS_OP_RENMOV_MULTI   7
#define FS_STATUS_OP_DELETE         8
#define FS_STATUS_OP_ATTRIB         9
#define FS_STATUS_OP_MKDIR         10
#define FS_STATUS_OP_EXEC          11
#define FS_STATUS_OP_CALCSIZE      12

/* ─── Callback signatures ─── */
typedef int  (__stdcall *tProgressProcW)(int PluginNr, const wchar_t* SourceName,
                                          const wchar_t* TargetName, int PercentDone);
typedef void (__stdcall *tLogProcW)     (int PluginNr, int MsgType, const wchar_t* LogString);
typedef BOOL (__stdcall *tRequestProcW) (int PluginNr, int RequestType,
                                          const wchar_t* CustomTitle, const wchar_t* CustomText,
                                          wchar_t* ReturnedText, int maxlen);
typedef int  (__stdcall *tCryptProcW)   (int PluginNr, int CryptoNr, int Mode,
                                          const wchar_t* ConnectionName, wchar_t* Password,
                                          int maxlen);

/* ─── FsDefaultParamStruct ─── */
#pragma pack(push, 1)
typedef struct {
    int  Size;
    DWORD PluginInterfaceVersionLow;
    DWORD PluginInterfaceVersionHi;
    char DefaultIniName[MAX_PATH];
} FsDefaultParamStruct;

typedef struct {
    int       SizeLow;
    int       SizeHigh;
    FILETIME  LastWriteTime;
    int       Attr;
} RemoteInfoStruct;
#pragma pack(pop)

#endif /* WFXTYPES_H */
