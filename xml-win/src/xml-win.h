// To ignore:
// error C4996 : 'GetVersionExA' : was declared deprecated
// error C4996 : 'GetVersionExW' was declared deprecated
#pragma warning(disable: 4996)

#include <atlbase.h>
#include <vector>
#include <list>
#include <algorithm>
#include "xmllite.h"

using namespace std;

inline bool __filterAscii(char c) {
  int i = (int)c;
  if (i > 47 && i < 58) //0-9
    return false;
  if (i > 64 && i < 91) //A-Z
    return false;
  if (i > 96 && i < 123) //a-z
    return false;

  return true;
};

//structs
struct XATTRIBUTE {
  string PREFIX;
  string NAME;
  string VALUE;
};

struct XELEMENT {
  string PREFIX;
  string NAME;
  vector<XATTRIBUTE> ATTRIBUTES;
  vector<XELEMENT> CHILDREN;
};

__declspec(dllexport) int ParseXmlFile(char* xmlfile, vector<XELEMENT>& xelements);
int ParseXmlFileEx(char* xmlfile, vector<XELEMENT>& xelements, int num_of_elements);

__declspec(dllexport) int ParseXmlMemory(char* buff, list<XELEMENT>& xelements);
int ParseXmlFileEx(char* xmlfile, vector<XELEMENT>& xelements, int num_of_elements);

int WriteToXml(char* filename, XELEMENT& root, vector<XELEMENT>& elements);
