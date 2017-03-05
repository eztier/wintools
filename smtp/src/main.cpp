#include <iostream>
#include <string>
#include "CSmtp.h"
#include "xml-win.h"
#include "common.h"

using namespace std;

struct SmtpSetting {
  string host;
  int port;
  SMTP_SECURITY_TYPE securityType = NO_SECURITY;
  bool authenticate = false;
  string senderName;
  string senderEmail;
  string senderReplyTo;
  vector<string> recipients;
};

void get_time(SYSTEMTIME& st, char*  timestamp) {
  GetLocalTime(&st);
  sprintf(timestamp, "%04d%02d%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

void getSettings(char* filename, SmtpSetting& setting) {
  //read the instruction xml file:
  vector<XELEMENT> xelements;
  int success = ParseXmlFile(filename, xelements);
  if (success != 0) {
    get_time(st, timestamp);
    out_l << timestamp;
    out_l << "|Error-> Failed to read the instruction file: + " << filename << ".\n";
    out_l.flush();
    return;
  }

  vector<XELEMENT>::iterator it;
  for (it = xelements.begin(); it != xelements.end(); it++) {
    if ((*it).NAME.compare("server") == 0) {
      vector<XATTRIBUTE>::iterator its;
      for (its = (*it).ATTRIBUTES.begin(); its != (*it).ATTRIBUTES.end(); its++) {
        if ((*its).NAME.compare("host") == 0) setting.host = (*its).VALUE;
        if ((*its).NAME.compare("port") == 0) setting.port = std::stoi((*its).VALUE);
        setting.securityType = NO_SECURITY;
        if ((*its).NAME.compare("authenticate") == 0) setting.authenticate = ((*its).VALUE == "true" ? true : false);
      }
    }

    if ((*it).NAME.compare("sender") == 0) {
      vector<XATTRIBUTE>::iterator its;
      for (its = (*it).ATTRIBUTES.begin(); its != (*it).ATTRIBUTES.end(); its++) {
        if ((*its).NAME.compare("name") == 0) setting.senderName = (*its).VALUE;
        if ((*its).NAME.compare("email") == 0) setting.senderEmail = (*its).VALUE;
        if ((*its).NAME.compare("replyTo") == 0) setting.senderReplyTo = (*its).VALUE;
      }
    }

    // Currently, xml-win will flatten everything.
    // recipients/recipient becomes just recipient
    if ((*it).NAME.compare("recipient") == 0) {
      vector<XATTRIBUTE>::iterator its1;
      for (its1 = (*it).ATTRIBUTES.begin(); its1 != (*it).ATTRIBUTES.end(); its1++) {
        if ((*its1).NAME.compare("email") == 0) setting.recipients.push_back((*its1).VALUE);
      }
    }
  }
}

int main(int argc, char* argv[]) {
  char* dlog = "#log";
  if (GetFileAttributes(dlog) == INVALID_FILE_ATTRIBUTES)
    CreateDirectory(dlog, NULL);

  char mlog[500];
  if (argc == 1) {
    sprintf(mlog, "%s\\%s", dlog, "smtp.log");
  }
  if (argc > 1) {
    string argfs(argv[1]);
    int i = argfs.rfind("\\");
    if (i != -1) argfs.erase(0, i + 1);
    argfs.erase(argfs.size() - 4, 4);
    sprintf(mlog, "%s\\%s.log", dlog, argfs.c_str());
  }
  out_l.open(mlog);

  //check if file exist
  if (GetFileAttributes(argc > 1 ? argv[1] : "smtp.xml") == INVALID_FILE_ATTRIBUTES) {
    get_time(st, timestamp);
    out_l << timestamp;
    out_l << "|Error-> File " << (argc == 2 ? argv[1] : "smtp.xml") << " does not exist.\n";
    out_l.flush();
    return 1;
  } else {
    get_time(st, timestamp);
    out_l << timestamp;
    out_l << "|Assert-> File " << (argc == 2 ? argv[1] : "smtp.xml") << " exists.\n";
    out_l.flush();
  }

  SmtpSetting setting;
  getSettings(argc > 1 ? argv[1] : "smtp.xml", setting);

  if (argc == 4) {
    bool bError = false;
    try {
      CSmtp mail;
      mail.ConnectRemoteServer(setting.host.c_str(), setting.port, setting.securityType, setting.authenticate);
      mail.SetSenderName(setting.senderName.c_str());
      mail.SetSenderMail(setting.senderEmail.c_str());
      mail.SetReplyTo(setting.senderReplyTo.c_str());
      vector<string>::iterator it;
      for (it = setting.recipients.begin(); it != setting.recipients.end(); it++ ) {
        mail.AddRecipient((*it).c_str());
      }
      mail.SetXPriority(XPRIORITY_NORMAL);
      mail.SetSubject(argv[2]);
      mail.AddMsgLine(argv[3]);
      mail.m_bHTML = true;

      mail.Send();
    } catch (ECSmtp e) {
      bError = true;
      get_time(st, timestamp);
      out_l << timestamp;
      out_l << "|Error-> " << e.GetErrorText().c_str() << "\n";
    }
    if (!bError) {
      get_time(st, timestamp);
      out_l << timestamp;
      out_l << "|Assert-> " << "Mail was send successfully.\n";
    }
  }

  out_l.flush();
  out_l.close();

  return 0;
}
