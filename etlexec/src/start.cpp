#include "start.h"

// Signatures
void create_tasks(vector<XELEMENT>&, vector<PROCESSSTART>&);
size_t execute_process(std::wstring, std::wstring);
void get_processes(char*);
void get_time(SYSTEMTIME&, char*);
BOOL IsUserAdminGrp(void);
bool sort_processstart (PROCESSSTART,PROCESSSTART);
std::string wstrtostr2(const std::wstring&); 

int main(int argc, char* argv[]) {

	char* dlog = "#log";
	if (GetFileAttributes(dlog) == INVALID_FILE_ATTRIBUTES)
				CreateDirectory(dlog,NULL);
	
	char mlog[500];
	if (argc == 1){
		sprintf(mlog, "%s\\%s", dlog, "etlexec++.log"); 
	}
	if (argc == 2) {
		string argfs(argv[1]);
		int i = argfs.rfind("\\");
		if (i != -1) argfs.erase(0, i + 1);
		argfs.erase(argfs.size() - 4, 4);
		sprintf(mlog, "%s\\%s%s.log", dlog, "etlexec++", argfs.c_str());
	}
	out_l.open(mlog);

	if (IsUserAdminGrp() == FALSE)
	{
		get_time(st, timestamp);
		out_l << timestamp;
		out_l << "|Error-> User is NOT a member of the Administrators Group.\n";
		out_l.flush();
		out_l.close();
		printf("Error-> User is NOT a member of the Administrators Group.\n");
		return -1;
	}
	
	//check if file exist
	if (GetFileAttributes(argc == 2 ? argv[1] : "etlexec.xml") == INVALID_FILE_ATTRIBUTES){
		get_time(st, timestamp);
		out_l << timestamp;
		out_l << "|Error-> File " << (argc == 2 ? argv[1] : "etlexec.xml") << " does not exist.\n";
		out_l.flush();
		return 1;
	} else{
		get_time(st, timestamp);
		out_l << timestamp;
		out_l << "|Assert-> File " << (argc == 2 ? argv[1] : "etlexec.xml") << " exists.\n";
		out_l.flush();
	}
	get_processes(argc == 2 ? argv[1] : "etlexec.xml");
	return 0;
}

void create_tasks(vector<XELEMENT>& xelements, vector<PROCESSSTART>& tlist) {
	vector<XELEMENT>::iterator it;	
	for(it = xelements.begin(); it != xelements.end(); it++)
	{
		if ((*it).NAME.compare("process") == 0){				
			vector<XATTRIBUTE>::iterator its;
			PROCESSSTART bfile;
			for(its = (*it).ATTRIBUTES.begin(); its != (*it).ATTRIBUTES.end(); its++)
			{	
				if ((*its).NAME.compare("name") == 0) bfile.name = (*its).VALUE;
				if ((*its).NAME.compare("fullPath") == 0) bfile.fullPath = (*its).VALUE;
				if ((*its).NAME.compare("parameters") == 0) bfile.parameters = (*its).VALUE;
				if ((*its).NAME.compare("sequenceId") == 0) { 
					int t;
					if(sscanf((*its).VALUE.c_str(), "%d", &t) == EOF) 
						bfile.sequenceId = -1;
					else
						bfile.sequenceId = t;					 
				}				
			}
			tlist.push_back(bfile);
		}
	}
}

size_t execute_process(std::wstring FullPathToExe, std::wstring Parameters) { 
    size_t iMyCounter = 0, iReturnVal = 0, iPos = 0; 
    DWORD dwExitCode = 0; 
    std::wstring sTempStr = L""; 

    /* - NOTE - You should check here to see if the exe even exists */ 

    /* Add a space to the beginning of the Parameters */ 
    if (Parameters.size() != 0) 
    { 
        if (Parameters[0] != L' ') 
        { 
            Parameters.insert(0,L" "); 
        } 
    } 

    /* The first parameter needs to be the exe itself */ 
    sTempStr = FullPathToExe; 
    iPos = sTempStr.find_last_of(L"\\"); 
    sTempStr.erase(0, iPos +1); 
    Parameters = sTempStr.append(Parameters); 

     /* CreateProcessW can modify Parameters thus we allocate needed memory */ 
    wchar_t * pwszParam = new wchar_t[Parameters.size() + 1]; 
    if (pwszParam == 0) { 
        return 1; 
    } 
    const wchar_t* pchrTemp = Parameters.c_str(); 
    wcscpy_s(pwszParam, Parameters.size() + 1, pchrTemp); 

    /* CreateProcess API initialization */ 
    STARTUPINFOW siStartupInfo; 
    PROCESS_INFORMATION piProcessInfo; 
    memset(&siStartupInfo, 0, sizeof(siStartupInfo)); 
    memset(&piProcessInfo, 0, sizeof(piProcessInfo)); 
    siStartupInfo.cb = sizeof(siStartupInfo); 

    if (CreateProcessW(const_cast<LPCWSTR>(FullPathToExe.c_str()), 
                            pwszParam, 0, 0, false, 
                            CREATE_DEFAULT_ERROR_MODE, 0, 0, 
                            &siStartupInfo, &piProcessInfo) != false) 
    { 
         /* Watch the process. */ 
        dwExitCode = WaitForSingleObject(piProcessInfo.hProcess, INFINITE); 
    } else { 
        /* CreateProcess failed */ 
        iReturnVal = GetLastError();

		string process = wstrtostr2(FullPathToExe);
		string params = wstrtostr2(Parameters);
		get_time(st, timestamp);
		out_l << timestamp;
		out_l << "|Error-> CreateProcessW() failed process: + " << process.c_str() << " parameters: " << params.c_str() << ".\n";
		out_l.flush();	
    } 

    /* Free memory */ 
    delete[]pwszParam; 
    pwszParam = 0; 

    /* Release handles */ 
    CloseHandle(piProcessInfo.hProcess); 
    CloseHandle(piProcessInfo.hThread); 

    return iReturnVal; 
}

void get_processes(char* ftasks) {
	//read the instruction xml file:
	// list<XELEMENT> xelements;
  vector<XELEMENT> xelements;
	int success = ParseXmlFile(ftasks, xelements);
	if (success != 0){
		get_time(st, timestamp);
		out_l << timestamp;
		out_l << "|Error-> Failed to read the instruction file: + " << ftasks << ".\n";
		out_l.flush();
	}

	// now put all the files in vector<DOWNLOADFILE>
	vector<PROCESSSTART> tlist;
	create_tasks(xelements, tlist);
	//sort the liet by sequence id
	sort (tlist.begin(), tlist.end(), sort_processstart);

	jt_tot.begin();
	vector<PROCESSSTART>::iterator it;
	for(it = tlist.begin(); it != tlist.end(); it++) {
		//start the timer
		get_time(st, timestamp);
		out_l << timestamp;
		out_l << "|Assert-> Task started sequenceId: + " << (*it).sequenceId << " name: " << (*it).name.c_str() << " parameters: " << (*it).parameters.c_str() << " fullPath: " << (*it).fullPath.c_str() << ".\n";
		out_l.flush();

		jt.begin();
		//start the process
		std::wstring wargs((*it).parameters.length(), L' '); // Make room for characters
		std::copy((*it).parameters.begin(), (*it).parameters.end(), wargs.begin());		
		
		std::wstring wexe((*it).fullPath.length(), L' ');
		std::copy((*it).fullPath.begin(), (*it).fullPath.end(), wexe.begin());	

		execute_process(wexe, wargs);
		
		//clock timer
		get_time(st, timestamp);
		out_l << timestamp;
		out_l << "|Assert-> Task completed sequenceId: + " << (*it).sequenceId << " name: " << (*it).name.c_str() << " Total elapsed time: ";
		out_l << jt.end() << " sec\n";
		out_l.flush();		
	}
	//clock timer - total
		get_time(st, timestamp);
		out_l << timestamp;
		out_l << "|Assert-> Session completed: " << " Total elapsed time: ";
		out_l << jt_tot.end() << " sec\n";
		out_l.flush();	
	  out_l.close();
}

void get_time(SYSTEMTIME& st, char*  timestamp) {
	GetLocalTime(&st);
	sprintf (timestamp, "%04d%02d%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

/*
  This routine returns TRUE if the caller's process is a member of the Administrators local group. Caller is NOT expected
  to be impersonating anyone and is expected to be able to open its own process and process token.
  Arguments: None.
  Return Value:
  TRUE - Caller has Administrators local group.
  FALSE - Caller does not have Administrators local group.
*/
BOOL IsUserAdminGrp(void) {

	//get the user name
	const unsigned long BUFSIZE = 255;  
	unsigned long dwSize = BUFSIZE;  
	char pbuf[ BUFSIZE + 1];  
	GetUserName(pbuf, &dwSize);

	get_time(st, timestamp);
	out_l << timestamp;
	out_l << "|Assert-> User Name: " << (LPCTSTR)pbuf  << "\n";
	out_l.flush();

	BOOL check;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup; 
	check = AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup);

	if(check) {
		//printf("AllocateAndInitializeSid() is OK\n");
		get_time(st, timestamp);
		out_l << timestamp;
		out_l << "|Assert-> AllocateAndInitializeSid() is OK.\n";
		out_l.flush();
		   if(!CheckTokenMembership(
			  NULL, // uses the impersonation token of the calling thread. If the thread is not impersonating,
						  // the function duplicates the thread's primary token to create an impersonation token.
			   AdministratorsGroup,  // Pointer to a SID structure
			  &check       // Result of the SID
				  ))
			{

			   // If the SID (the 2nd parameter) is present and has the SE_GROUP_ENABLED attribute,
			   // IsMember (3rd parameter) returns TRUE; otherwise, it returns FALSE.
			   //printf("The received value of the third parameter: %u\n", check);
			   get_time(st, timestamp);
			   out_l << timestamp;
			   out_l << "|Warn-> The received value of the third parameter: " << check << ".  CheckTokenMembership() is NOT OK.\n";
			   out_l.flush();
			   check = FALSE;
			   //printf("CheckTokenMembership() is NOT OK\n");
		   } else {
			   //printf("CheckTokenMembership() is OK\n");
         // AllocateAndInitializeSid on success will return 1.
         // However, CheckTokenMembership on success will return 0, so need to set check = TRUE.
         check = TRUE;
			   get_time(st, timestamp);
			   out_l << timestamp;
			   out_l << "|Assert-> CheckTokenMembership() is OK.\n";
			   out_l.flush();
		   }

		   //printf("You are Administrators Local Group.\n");
		   //printf("The received value of the third parameter: %u, last error if any: %u\n", check, GetLastError());
		   
		   get_time(st, timestamp);
		   out_l << timestamp;
		   out_l << "|Assert-> User is in the Administrators Local Group.\n";
		   get_time(st, timestamp);
		   out_l << timestamp;
		   out_l << "|Assert-> The received value of the third parameter for CheckTokenMembership(): " << check << ", last error if any: " << GetLastError() << ".\n";
		   out_l.flush();

		   FreeSid(AdministratorsGroup);
	} else {
	   //printf("AllocateAndInitializeSid() is NOT OK\n");
		get_time(st, timestamp);
		out_l << timestamp;
		out_l << "|Warn-> AllocateAndInitializeSid() is NOT OK.\n";
		out_l.flush();
	}

	return(check);
}

bool sort_processstart (PROCESSSTART i,PROCESSSTART j) { return (i.sequenceId<j.sequenceId); }

std::string wstrtostr2(const std::wstring &wstr) { 
    // Convert a Unicode string to an ASCII string 
    std::string strTo; 
    char *szTo = new char[wstr.length() + 1]; 
    szTo[wstr.size()] = '\0'; 
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, szTo, (int)wstr.length(), NULL, NULL); 
    strTo = szTo; 
    delete[] szTo; 
    return strTo; 
}
