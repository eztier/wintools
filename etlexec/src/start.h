#include "common.h"
#include "xml-win.h"

using namespace std;

struct PROCESSSTART
{
	string name;
	int sequenceId;
	string fullPath;
	string parameters;
};
