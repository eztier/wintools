#include <windows.h>
#include <strsafe.h>
#include <stdio.h>

void get_current_time(SYSTEMTIME* st, char*  timestamp) {
  GetLocalTime(st);
  sprintf(timestamp, "%04d-%02d-%02d %02d:%02d:%02d", st->wYear, st->wMonth, st->wDay, st->wHour, st->wMinute, st->wSecond);
}

void get_current_date(SYSTEMTIME* st, char*  timestamp) {
  GetLocalTime(st);
  sprintf(timestamp, "%04d-%02d-%02d", st->wYear, st->wMonth, st->wDay);
}

char* setupLogging(const char* logfolder, const char* logfilename, char* logfullpath) {
  SYSTEMTIME st;
  char timestamp[20];

  if (GetFileAttributes(logfolder) == INVALID_FILE_ATTRIBUTES)
    CreateDirectory(logfolder, NULL);
    
  get_current_date(&st, timestamp);

  sprintf(logfullpath, "%s\\%s-%s.log", logfolder, logfilename, timestamp);

  return logfullpath;
}

void LogMessage(const char* logfolder, const char* logfilename, char* lpszFunction, unsigned long dw) {
  // Retrieve the system error message for the last-error code
  void* lpMsgBuf;
  void* lpDisplayBuf;
  SYSTEMTIME st;
  char timestamp[20];

  FormatMessage(
    FORMAT_MESSAGE_ALLOCATE_BUFFER |
    FORMAT_MESSAGE_FROM_SYSTEM |
    FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    dw,
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    (char*)&lpMsgBuf,
    0, NULL);

  lpDisplayBuf = (void*)LocalAlloc(LMEM_ZEROINIT,
    (lstrlen((const char*)lpMsgBuf) + lstrlen((const char*)lpszFunction) + 40) * sizeof(char));

  StringCchPrintf((char*)lpDisplayBuf,
    LocalSize(lpDisplayBuf) / sizeof(char),
    TEXT("%s status code %d: %s"),
    lpszFunction, dw, lpMsgBuf);

  get_current_time(&st, timestamp);

  // Create log file path.
  char lpath[500];
  setupLogging(logfolder, logfilename, lpath);

  FILE* logfile = fopen(lpath, "a+");
  fprintf(logfile, "%s %s", timestamp, (const char*)lpDisplayBuf);
  fclose(logfile);

  LocalFree(lpMsgBuf);
  LocalFree(lpDisplayBuf);
}
