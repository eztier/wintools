#include "xml-win.h"

static const string c_esc_seq_clear_line_s = "\x1b[K";
static const string c_esc_seq_clear_screen_s = "\x1b[J";
static const string c_esc_seq_right_arrow_s = "\x1b[C";
static const string c_backspace_s = "\x08";
static const string c_empty_s = "";

//implement filestream that derives from IStream
class FileStream : public IStream {
  FileStream(HANDLE hFile) {
    _refcount = 1;
    _hFile = hFile;
  }

  ~FileStream() {
    if (_hFile != INVALID_HANDLE_VALUE) {
      ::CloseHandle(_hFile);
    }
  }

public:
  HRESULT static OpenFile(LPCWSTR pName, IStream ** ppStream, bool fWrite) {
    HANDLE hFile = ::CreateFileW(pName, fWrite ? GENERIC_WRITE : GENERIC_READ, FILE_SHARE_READ,
      NULL, fWrite ? CREATE_ALWAYS : OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
      return HRESULT_FROM_WIN32(GetLastError());

    *ppStream = new FileStream(hFile);

    if (*ppStream == NULL)
      CloseHandle(hFile);

    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void ** ppvObject) {
    if (iid == __uuidof(IUnknown)
      || iid == __uuidof(IStream)
      || iid == __uuidof(ISequentialStream)) {
      *ppvObject = static_cast<IStream*>(this);
      AddRef();
      return S_OK;
    } else
      return E_NOINTERFACE;
  }

  virtual ULONG STDMETHODCALLTYPE AddRef(void) {
    return (ULONG)InterlockedIncrement(&_refcount);
  }

  virtual ULONG STDMETHODCALLTYPE Release(void) {
    ULONG res = (ULONG)InterlockedDecrement(&_refcount);
    if (res == 0)
      delete this;
    return res;
  }

  // ISequentialStream Interface
public:
  virtual HRESULT STDMETHODCALLTYPE Read(void* pv, ULONG cb, ULONG* pcbRead) {
    BOOL rc = ReadFile(_hFile, pv, cb, pcbRead, NULL);
    return (rc) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
  }

  virtual HRESULT STDMETHODCALLTYPE Write(void const* pv, ULONG cb, ULONG* pcbWritten) {
    BOOL rc = WriteFile(_hFile, pv, cb, pcbWritten, NULL);
    return rc ? S_OK : HRESULT_FROM_WIN32(GetLastError());
  }

  // IStream Interface
public:
  virtual HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER) {
    return E_NOTIMPL;
  }

  virtual HRESULT STDMETHODCALLTYPE CopyTo(IStream*, ULARGE_INTEGER, ULARGE_INTEGER*,
    ULARGE_INTEGER*) {
    return E_NOTIMPL;
  }

  virtual HRESULT STDMETHODCALLTYPE Commit(DWORD) {
    return E_NOTIMPL;
  }

  virtual HRESULT STDMETHODCALLTYPE Revert(void) {
    return E_NOTIMPL;
  }

  virtual HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) {
    return E_NOTIMPL;
  }

  virtual HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) {
    return E_NOTIMPL;
  }

  virtual HRESULT STDMETHODCALLTYPE Clone(IStream **) {
    return E_NOTIMPL;
  }

  virtual HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER liDistanceToMove, DWORD dwOrigin,
    ULARGE_INTEGER* lpNewFilePointer) {
    DWORD dwMoveMethod;

    switch (dwOrigin) {
    case STREAM_SEEK_SET:
      dwMoveMethod = FILE_BEGIN;
      break;
    case STREAM_SEEK_CUR:
      dwMoveMethod = FILE_CURRENT;
      break;
    case STREAM_SEEK_END:
      dwMoveMethod = FILE_END;
      break;
    default:
      return STG_E_INVALIDFUNCTION;
      break;
    }

    if (SetFilePointerEx(_hFile, liDistanceToMove, (PLARGE_INTEGER)lpNewFilePointer,
      dwMoveMethod) == 0)
      return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE Stat(STATSTG* pStatstg, DWORD grfStatFlag) {
    if (GetFileSizeEx(_hFile, (PLARGE_INTEGER)&pStatstg->cbSize) == 0)
      return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
  }

private:
  HANDLE _hFile;
  LONG _refcount;
};


//helper functions
string& replaceAll(string& context, const string& from, const string& to) {
  size_t lookHere = 0;
  size_t foundHere;
  while ((foundHere = context.find(from, lookHere)) != string::npos) {
    context.replace(foundHere, from.size(), to);
    lookHere = foundHere + to.size();
  }
  return context;
};

std::string wstrtostr(const std::wstring &wstr) {
  // Convert a Unicode string to an ASCII string 
  std::string strTo;
  char *szTo = new char[wstr.length() + 1];
  szTo[wstr.size()] = '\0';
  WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, szTo, (int)wstr.length(), NULL, NULL);
  strTo = szTo;
  delete[] szTo;
  return strTo;
}

std::wstring strtowstr(const std::string &str) {
  // Convert an ASCII string to a Unicode String 
  std::wstring wstrTo;
  wchar_t *wszTo = new wchar_t[str.length() + 1];
  wszTo[str.size()] = L'\0';
  MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, wszTo, (int)str.length());
  wstrTo = wszTo;
  delete[] wszTo;
  return wstrTo;
}

HRESULT WriteAttributes(IXmlReader* pReader, XELEMENT& p_xelement) {
  const WCHAR* pwszPrefix;
  const WCHAR* pwszLocalName;
  const WCHAR* pwszValue;
  const WCHAR* pwszNamespaceUri;

  HRESULT hr = pReader->MoveToFirstAttribute();

  if (S_FALSE == hr)
    return hr;
  if (S_OK != hr) {
    //wprintf(L"\nXmlLite Error: %08.8lx\n", hr);
    return hr;
  }
  if (S_OK == hr) {
    while (TRUE) {
      if (!pReader->IsDefault()) {
        XATTRIBUTE xattribute;
        UINT cwchPrefix;
        if (FAILED(hr = pReader->GetPrefix(&pwszPrefix, &cwchPrefix))) {
          //wprintf(L"Error getting prefix, error is %08.8lx", hr);
          return -1;
        }
        if (FAILED(hr = pReader->GetLocalName(&pwszLocalName, NULL))) {
          //wprintf(L"Error, Method: GetLocalName, error is %08.8lx", hr);
          return -1;
        }
        if (FAILED(hr = pReader->GetValue(&pwszValue, NULL))) {
          //wprintf(L"Error, Method: GetValue, error is %08.8lx", hr);
          return -1;
        }

        wstring wstr_pwszLocalName(pwszLocalName);
        wstring wstr_pwszValue(pwszValue);
        string str_pwszLocalName = wstrtostr(wstr_pwszLocalName);
        string str_pwszValue = wstrtostr(wstr_pwszValue);

        if (cwchPrefix > 0) {
          wstring wstr(pwszPrefix);
          string str_pwszPrefix = wstrtostr(wstr);
          //wprintf(L"%s:%s=\"%s\" ", pwszPrefix, pwszLocalName, pwszValue);
          xattribute.PREFIX = str_pwszPrefix;
          xattribute.NAME = str_pwszLocalName;
          xattribute.VALUE = str_pwszValue;
        } else {
          //wprintf(L"%s=\"%s\" ", pwszLocalName, pwszValue);					
          xattribute.NAME = str_pwszLocalName;
          xattribute.VALUE = str_pwszValue;
        }
        if (FAILED(hr = pReader->GetNamespaceUri(&pwszNamespaceUri, NULL))) {
          //wprintf(L"Error, Method: GetNamespaceUri, error is %08.8lx", hr);
          return -1;
        }
        //wprintf(L"Namespace=%s\n", pwszNamespaceUri);
        p_xelement.ATTRIBUTES.push_back(xattribute);
      }

      if (S_OK != pReader->MoveToNextAttribute()) {
        break;
      }
    }
  }
  return hr;
}

int ParseXmlFile(char* xmlfile, vector<XELEMENT>& xelements) {
  HRESULT hr;
  CComPtr<IStream> pFileStream;
  CComPtr<IXmlReader> pReader;
  XmlNodeType nodetype;
  const WCHAR* pwszPrefix;
  const WCHAR* pwszLocalName;
  const WCHAR* pwszNamespaceUri;
  UINT cwchPrefix;

  //convert char* to wchar_t
  int lenA = lstrlenA(xmlfile);
  int lenW;
  BSTR unicodestr = nullptr;
  lenW = ::MultiByteToWideChar(CP_ACP, 0, xmlfile, lenA, 0, 0);
  if (lenW > 0) {
    // Check whether conversion was successful
    unicodestr = ::SysAllocStringLen(0, lenW);
    ::MultiByteToWideChar(CP_ACP, 0, xmlfile, lenA, unicodestr, lenW);
  } else {
    // handle the error
  }

  //Open read-only input stream
  if (FAILED(hr = FileStream::OpenFile(unicodestr, &pFileStream, FALSE))) {
    //wprintf(L"Error creating file reader, error is %08.8lx", hr);
    return -1;
  }

  // when done, free the BSTR
  ::SysFreeString(unicodestr);

  if (FAILED(hr = CreateXmlReader(__uuidof(IXmlReader), (void**)&pReader, NULL))) {
    //wprintf(L"Error creating xml reader, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pReader->SetInput(pFileStream))) {
    //wprintf(L"Error setting input for reader, error is %08.8lx", hr);
    return -1;
  }

  while (true) {
    hr = pReader->Read(&nodetype);
    if (S_FALSE == hr)
      break;
    if (S_OK != hr) {
      //wprintf(L"\nXmlLite Error: %08.8lx\n", hr);
      return -1;
    }
    switch (nodetype) {
    case XmlNodeType_Element:

      XELEMENT xelement;

      if (FAILED(hr = pReader->GetPrefix(&pwszPrefix, &cwchPrefix))) {
        //wprintf(L"Error, Method: GetPrefix, error is %08.8lx", hr);
        return -1;
      }
      if (FAILED(hr = pReader->GetLocalName(&pwszLocalName, NULL))) {
        //wprintf(L"Error, Method: GetLocalName, error is %08.8lx", hr);
        return -1;
      }

      wstring wstr_pwszLocalName(pwszLocalName);
      string str_pwszLocalName = wstrtostr(wstr_pwszLocalName);

      if (cwchPrefix > 0) {
        //wprintf(L"%s:%s ", pwszPrefix, pwszLocalName);
        wstring wstr(pwszPrefix);
        string str_pwszPrefix = wstrtostr(wstr);
        xelement.PREFIX = str_pwszPrefix;
        xelement.NAME = str_pwszLocalName;
      } else {
        //wprintf(L"%s ", pwszLocalName);
        xelement.PREFIX = "";
        xelement.NAME = str_pwszLocalName;
      }
      if (FAILED(hr = pReader->GetNamespaceUri(&pwszNamespaceUri, NULL))) {
        //wprintf(L"Error, Method: GetNamespaceUri, error is %08.8lx", hr);
        return -1;
      }
      //wprintf(L"Namespace=%s\n", pwszNamespaceUri);

      if (FAILED(hr = WriteAttributes(pReader, xelement))) {
        //wprintf(L"Error, Method: WriteAttributes, error is %08.8lx", hr);
        //return -1;
      }
      xelements.push_back(xelement);
      break;
    }
  }

  //wprintf(L"\n");
  return 0;
}

int ParseXmlFileEx(char* xmlfile, vector<XELEMENT>& xelements, int num_of_elements) {

  HRESULT hr;
  CComPtr<IStream> pFileStream;
  CComPtr<IXmlReader> pReader;
  XmlNodeType nodetype;
  const WCHAR* pwszPrefix;
  const WCHAR* pwszLocalName;
  const WCHAR* pwszNamespaceUri;
  UINT cwchPrefix;

  if (num_of_elements < 1) return -1;

  //convert char* to wchar_t
  int lenA = lstrlenA(xmlfile);
  int lenW;
  BSTR unicodestr = nullptr;
  lenW = ::MultiByteToWideChar(CP_ACP, 0, xmlfile, lenA, 0, 0);
  if (lenW > 0) {
    // Check whether conversion was successful
    unicodestr = ::SysAllocStringLen(0, lenW);
    ::MultiByteToWideChar(CP_ACP, 0, xmlfile, lenA, unicodestr, lenW);
  } else {
    // handle the error
  }

  //Open read-only input stream
  if (FAILED(hr = FileStream::OpenFile(unicodestr, &pFileStream, FALSE))) {
    return -1;
  }

  // when done, free the BSTR
  ::SysFreeString(unicodestr);

  if (FAILED(hr = CreateXmlReader(__uuidof(IXmlReader), (void**)&pReader, NULL))) {
    return -1;
  }

  if (FAILED(hr = pReader->SetInput(pFileStream))) {
    return -1;
  }

  while (num_of_elements > 0) {
    hr = pReader->Read(&nodetype);
    if (S_FALSE == hr)
      break;
    if (S_OK != hr) {
      return -1;
    }
    switch (nodetype) {
    case XmlNodeType_Element:

      XELEMENT xelement;

      if (FAILED(hr = pReader->GetPrefix(&pwszPrefix, &cwchPrefix)))
        return -1;

      if (FAILED(hr = pReader->GetLocalName(&pwszLocalName, NULL)))
        return -1;

      wstring wstr_pwszLocalName(pwszLocalName);
      string str_pwszLocalName = wstrtostr(wstr_pwszLocalName);

      if (cwchPrefix > 0) {
        wstring wstr(pwszPrefix);
        string str_pwszPrefix = wstrtostr(wstr);
        xelement.PREFIX = str_pwszPrefix;
        xelement.NAME = str_pwszLocalName;
      } else {
        xelement.PREFIX = "";
        xelement.NAME = str_pwszLocalName;
      }

      if (FAILED(hr = pReader->GetNamespaceUri(&pwszNamespaceUri, NULL)))
        return -1;

      if (FAILED(hr = WriteAttributes(pReader, xelement))) {
        //ignore
      }
      xelements.push_back(xelement);

      //decrement
      num_of_elements--;
      break;
    }
  }

  return num_of_elements;
}

int ParseXmlMemory(char* buff, list<XELEMENT>& xelements) {
  HRESULT hr;
  CComPtr<IStream> pStream;
  CComPtr<IXmlReader> pReader;

  //Create stream on global
  if (FAILED(CreateStreamOnHGlobal(NULL, TRUE, &pStream)))
    return -1;

  //Write the decrypted data into the stream
  DWORD dim;
  if (FAILED(pStream->Write(buff, strlen(buff), &dim)))
    return -1;
  if (FAILED(hr = CreateXmlReader(__uuidof(IXmlReader), (void**)&pReader, NULL)))
    return -1;

  //Rewind seek of the stream to initial position
  LARGE_INTEGER position;
  position.QuadPart = 0;
  if (FAILED(pStream->Seek(position, STREAM_SEEK_SET, NULL)))
    return 1;

  //Assign stream to reader
  if (FAILED(hr = pReader->SetInput(pStream)))
    return -1;

  //Read xml
  XmlNodeType nodetype;
  const WCHAR* pwszPrefix;
  const WCHAR* pwszLocalName;
  const WCHAR* pwszNamespaceUri;
  UINT cwchPrefix;

  while (true) {
    hr = pReader->Read(&nodetype);
    if (S_FALSE == hr)
      break;
    if (S_OK != hr) {
      return -1;
    }
    switch (nodetype) {
    case XmlNodeType_Element:

      XELEMENT xelement;

      if (FAILED(hr = pReader->GetPrefix(&pwszPrefix, &cwchPrefix))) {
        return -1;
      }
      if (FAILED(hr = pReader->GetLocalName(&pwszLocalName, NULL))) {
        return -1;
      }

      wstring wstr_pwszLocalName(pwszLocalName);
      string str_pwszLocalName = wstrtostr(wstr_pwszLocalName);

      if (cwchPrefix > 0) {
        wstring wstr(pwszPrefix);
        string str_pwszPrefix = wstrtostr(wstr);
        xelement.PREFIX = str_pwszPrefix;
        xelement.NAME = str_pwszLocalName;
      } else {
        xelement.PREFIX = "";
        xelement.NAME = str_pwszLocalName;
      }
      if (FAILED(hr = pReader->GetNamespaceUri(&pwszNamespaceUri, NULL))) {
        return -1;
      }

      if (FAILED(hr = WriteAttributes(pReader, xelement))) {
        //ignore            
        //return -1;
      }
      xelements.push_back(xelement);
      break;
    }
  }

  //clean the stream
  ::GlobalFree(pStream);
  pStream = NULL;
}

int test_xml_write(char* filename) {
  HRESULT hr;
  CComPtr<IStream> pOutFileStream;
  CComPtr<IXmlWriter> pWriter;

  //Open writeable output stream
  if (FAILED(hr = SHCreateStreamOnFileA(filename, STGM_CREATE | STGM_WRITE, &pOutFileStream))) {
    wprintf(L"Error creating file writer, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = CreateXmlWriter(__uuidof(IXmlWriter), (void**)&pWriter, NULL))) {
    wprintf(L"Error creating xml writer, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->SetOutput(pOutFileStream))) {
    wprintf(L"Error, Method: SetOutput, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->SetProperty(XmlWriterProperty_Indent, TRUE))) {
    wprintf(L"Error, Method: SetProperty XmlWriterProperty_Indent, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteStartDocument(XmlStandalone_Omit))) {
    wprintf(L"Error, Method: WriteStartDocument, error is %08.8lx", hr);
    return -1;
  }

  // if you want to use a DTD using either the SYSTEM or PUBLIC identifiers,
  // or if you want to use an internal DTD subset, you can modify the following
  // call to WriteDocType.
  if (FAILED(hr = pWriter->WriteDocType(L"root", NULL, NULL, NULL))) {
    wprintf(L"Error, Method: WriteDocType, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteProcessingInstruction(L"xml-stylesheet",
    L"href=\"mystyle.css\" title=\"Compact\" type=\"text/css\""))) {
    wprintf(L"Error, Method: WriteProcessingInstruction, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteStartElement(NULL, L"root", NULL))) {
    wprintf(L"Error, Method: WriteStartElement, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteStartElement(NULL, L"sub", NULL))) {
    wprintf(L"Error, Method: WriteStartElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteAttributeString(NULL, L"myAttr", NULL,
    L"1234"))) {
    wprintf(L"Error, Method: WriteAttributeString, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteString(
    L"Markup is <escaped> for this string"))) {
    wprintf(L"Error, Method: WriteString, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteFullEndElement())) {
    wprintf(L"Error, Method: WriteFullEndElement, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteStartElement(NULL, L"anotherChild", NULL))) {
    wprintf(L"Error, Method: WriteStartElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteString(L"some text"))) {
    wprintf(L"Error, Method: WriteString, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteFullEndElement())) {
    wprintf(L"Error, Method: WriteFullEndElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteWhitespace(L"\n"))) {
    wprintf(L"Error, Method: WriteWhitespace, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteCData(L"This is CDATA text."))) {
    wprintf(L"Error, Method: WriteCData, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteWhitespace(L"\n"))) {
    wprintf(L"Error, Method: WriteWhitespace, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteStartElement(NULL, L"containsCharacterEntity", NULL))) {
    wprintf(L"Error, Method: WriteStartElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteCharEntity(L'a'))) {
    wprintf(L"Error, Method: WriteCharEntity, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteFullEndElement())) {
    wprintf(L"Error, Method: WriteFullEndElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteWhitespace(L"\n"))) {
    wprintf(L"Error, Method: WriteWhitespace, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteStartElement(NULL, L"containsChars", NULL))) {
    wprintf(L"Error, Method: WriteStartElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteChars(L"abcdefghijklm", 5))) {
    wprintf(L"Error, Method: WriteChars, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteFullEndElement())) {
    wprintf(L"Error, Method: WriteFullEndElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteWhitespace(L"\n"))) {
    wprintf(L"Error, Method: WriteWhitespace, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteStartElement(NULL, L"containsEntity", NULL))) {
    wprintf(L"Error, Method: WriteStartElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteEntityRef(L"myEntity"))) {
    wprintf(L"Error, Method: WriteEntityRef, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteEndElement())) {
    wprintf(L"Error, Method: WriteEndElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteWhitespace(L"\n"))) {
    wprintf(L"Error, Method: WriteWhitespace, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteStartElement(NULL, L"containsName", NULL))) {
    wprintf(L"Error, Method: WriteStartElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteName(L"myName"))) {
    wprintf(L"Error, Method: WriteName, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteEndElement())) {
    wprintf(L"Error, Method: WriteEndElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteWhitespace(L"\n"))) {
    wprintf(L"Error, Method: WriteWhitespace, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteStartElement(NULL, L"containsNmToken", NULL))) {
    wprintf(L"Error, Method: WriteStartElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteNmToken(L"myNmToken"))) {
    wprintf(L"Error, Method: WriteNmToken, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteEndElement())) {
    wprintf(L"Error, Method: WriteEndElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteWhitespace(L"\n"))) {
    wprintf(L"Error, Method: WriteWhitespace, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteComment(L"This is a comment"))) {
    wprintf(L"Error, Method: WriteComment, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteWhitespace(L"\n"))) {
    wprintf(L"Error, Method: WriteWhitespace, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteRaw(L"<elementWrittenRaw/>"))) {
    wprintf(L"Error, Method: WriteRaw, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteWhitespace(L"\n"))) {
    wprintf(L"Error, Method: WriteWhitespace, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteRawChars(L"<rawCharacters/>", 16))) {
    wprintf(L"Error, Method: WriteRawChars, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteWhitespace(L"\n"))) {
    wprintf(L"Error, Method: WriteWhitespace, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteElementString(NULL, L"myElement", NULL, L"myValue"))) {
    wprintf(L"Error, Method: WriteElementString, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteFullEndElement())) {
    wprintf(L"Error, Method: WriteFullEndElement, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->WriteWhitespace(L"\n"))) {
    wprintf(L"Error, Method: WriteWhitespace, error is %08.8lx", hr);
    return -1;
  }

  // WriteEndDocument closes any open elements or attributes
  if (FAILED(hr = pWriter->WriteEndDocument())) {
    wprintf(L"Error, Method: WriteEndDocument, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->Flush())) {
    wprintf(L"Error, Method: Flush, error is %08.8lx", hr);
    return -1;
  }

  return 0;

}

int RecurseXmlElements(CComPtr<IXmlWriter>& pWriter, vector<XELEMENT>& elements) {
  HRESULT hr;
  for (vector<XELEMENT>::iterator iter = elements.begin(); iter != elements.end(); iter++) {

    //only take a-z, A-Z, 0-9 for names
    (*iter).NAME.resize(std::remove_if((*iter).NAME.begin(), (*iter).NAME.end(), __filterAscii) - (*iter).NAME.begin());

    if (FAILED(hr = pWriter->WriteStartElement(NULL, (strtowstr((*iter).NAME)).c_str(), NULL))) {
      wprintf(L"Error, Method: WriteStartElement, error is %08.8lx", hr);
      return -1;
    }

    for (vector<XATTRIBUTE>::iterator itera = (*iter).ATTRIBUTES.begin(); itera != (*iter).ATTRIBUTES.end(); itera++) {
      //get rid of control commands and backspace characters

      replaceAll((*itera).VALUE, c_esc_seq_clear_line_s, c_empty_s);
      replaceAll((*itera).VALUE, c_esc_seq_clear_screen_s, c_empty_s);
      replaceAll((*itera).VALUE, c_esc_seq_right_arrow_s, c_empty_s);
      replaceAll((*itera).VALUE, c_backspace_s, c_empty_s);

      if (FAILED(hr = pWriter->WriteAttributeString(NULL, (strtowstr((*itera).NAME)).c_str(), NULL,
        (strtowstr((*itera).VALUE).c_str())))) {
        wprintf(L"Error, Method: WriteAttributeString, error is %08.8lx", hr);
        return -1;
      }
    }

    if ((*iter).CHILDREN.size() > 0) {
      RecurseXmlElements(pWriter, (*iter).CHILDREN);

      if (FAILED(hr = pWriter->WriteFullEndElement())) {
        wprintf(L"Error, Method: WriteFullEndElement, error is %08.8lx", hr);
        return -1;
      }
    } else {
      if (FAILED(hr = pWriter->WriteEndElement())) {
        wprintf(L"Error, Method: WriteEndElement, error is %08.8lx", hr);
        return -1;
      }
    }
  }
}

int WriteToXml(char* filename, XELEMENT& root, vector<XELEMENT>& elements) {
  HRESULT hr;
  CComPtr<IStream> pOutFileStream;
  CComPtr<IXmlWriter> pWriter;

  //Open writeable output stream
  if (FAILED(hr = SHCreateStreamOnFileA(filename, STGM_CREATE | STGM_WRITE, &pOutFileStream))) {
    wprintf(L"Error creating file writer, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = CreateXmlWriter(__uuidof(IXmlWriter), (void**)&pWriter, NULL))) {
    wprintf(L"Error creating xml writer, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->SetOutput(pOutFileStream))) {
    wprintf(L"Error, Method: SetOutput, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->SetProperty(XmlWriterProperty_Indent, TRUE))) {
    wprintf(L"Error, Method: SetProperty XmlWriterProperty_Indent, error is %08.8lx", hr);
    return -1;
  }

  if (FAILED(hr = pWriter->WriteStartDocument(XmlStandalone_Omit))) {
    wprintf(L"Error, Method: WriteStartDocument, error is %08.8lx", hr);
    return -1;
  }

  // if you want to use a DTD using either the SYSTEM or PUBLIC identifiers,
  // or if you want to use an internal DTD subset, you can modify the following
  // call to WriteDocType.
  /*
  if (FAILED(hr = pWriter->WriteDocType(strtowstr(rootname).c_str(), NULL, NULL, NULL)))
  {
  wprintf(L"Error, Method: WriteDocType, error is %08.8lx", hr);
  return -1;
  }
  */

  if (FAILED(hr = pWriter->WriteStartElement(NULL, strtowstr(root.NAME).c_str(), NULL))) {
    wprintf(L"Error, Method: WriteStartElement, error is %08.8lx", hr);
    return -1;
  }
  //write the root attributes
  for (vector<XATTRIBUTE>::iterator itera = root.ATTRIBUTES.begin(); itera != root.ATTRIBUTES.end(); itera++) {
    if (FAILED(hr = pWriter->WriteAttributeString(NULL, (strtowstr((*itera).NAME)).c_str(), NULL,
      (strtowstr((*itera).VALUE).c_str())))) {
      wprintf(L"Error, Method: WriteAttributeString, error is %08.8lx", hr);
      return -1;
    }
  }
  //--------------------------------------------------------------------------------------------------------
  // BODY
  //--------------------------------------------------------------------------------------------------------
  RecurseXmlElements(pWriter, elements);
  /*
  for(vector<XELEMENT>::iterator iter = elements.begin(); iter != elements.end(); iter++)
  {
  if (FAILED(hr = pWriter->WriteStartElement(NULL, (strtowstr((*iter).NAME)).c_str(), NULL)))
  {
  wprintf(L"Error, Method: WriteStartElement, error is %08.8lx", hr);
  return -1;
  }

  for(vector<XATTRIBUTE>::iterator itera = (*iter).ATTRIBUTES.begin(); itera != (*iter).ATTRIBUTES.end(); itera++)
  {
  if (FAILED(hr = pWriter->WriteAttributeString(NULL, (strtowstr((*itera).NAME)).c_str(), NULL,
  (strtowstr((*itera).VALUE).c_str() ))))
  {
  wprintf(L"Error, Method: WriteAttributeString, error is %08.8lx", hr);
  return -1;
  }
  }
  }
  */

  // WriteEndDocument closes any open elements or attributes
  if (FAILED(hr = pWriter->WriteEndDocument())) {
    wprintf(L"Error, Method: WriteEndDocument, error is %08.8lx", hr);
    return -1;
  }
  if (FAILED(hr = pWriter->Flush())) {
    wprintf(L"Error, Method: Flush, error is %08.8lx", hr);
    return -1;
  }

  return 0;
}

/*
COM_VERIFY(writer->WriteStartDocument(XmlStandalone_Omit));
COM_VERIFY(writer->WriteStartElement(0, L"html", L"http://www.w3.org/1999/xhtml"));
COM_VERIFY(writer->WriteStartElement(0, L"head", 0));
COM_VERIFY(writer->WriteElementString(0, L"title", 0, L"My Web Page"));
COM_VERIFY(writer->WriteEndElement()); // </head>
COM_VERIFY(writer->WriteStartElement(0, L"body", 0));
COM_VERIFY(writer->WriteElementString(0, L"p", 0, L"Hello world!"));
COM_VERIFY(writer->WriteEndDocument());
*/