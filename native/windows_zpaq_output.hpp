// Keep Vault's Windows extraction boundary. Included by zpaq.cpp after its
// common path validator; this file is never compiled into the macOS build.
#ifndef KEEPVAULT_WINDOWS_ZPAQ_OUTPUT_HPP
#define KEEPVAULT_WINDOWS_ZPAQ_OUTPUT_HPP

namespace keepvault_windows_output {

struct OwnedHandle {
  HANDLE value;
  explicit OwnedHandle(HANDLE handle): value(handle) {}
  ~OwnedHandle() { if (value!=INVALID_HANDLE_VALUE) CloseHandle(value); }
  OwnedHandle(const OwnedHandle&)=delete;
  OwnedHandle& operator=(const OwnedHandle&)=delete;
};

typedef std::shared_ptr<OwnedHandle> Handle;
static std::mutex mutex;
static Handle root;
static std::map<string, Handle> directories;
static std::map<string, Handle> files;

static BY_HANDLE_FILE_INFORMATION inspect(HANDLE handle, bool directory) {
  BY_HANDLE_FILE_INFORMATION info={};
  if (!GetFileInformationByHandle(handle, &info)
      || (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)
      || bool(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=directory
      || (!directory && info.nNumberOfLinks!=1))
    error("unsafe bound Windows extraction object");
  return info;
}

static bool same(const BY_HANDLE_FILE_INFORMATION& left,
                 const BY_HANDLE_FILE_INFORMATION& right) {
  return left.dwVolumeSerialNumber==right.dwVolumeSerialNumber
      && left.nFileIndexHigh==right.nFileIndexHigh
      && left.nFileIndexLow==right.nFileIndexLow;
}

static void require_root() {
  if (!root) error("bound Windows extraction root is unavailable");
  const BY_HANDLE_FILE_INFORMATION info=inspect(root->value, true);
  if (uint64_t(info.dwVolumeSerialNumber)!=g_keepvault_expected_root_device
      || ((uint64_t(info.nFileIndexHigh)<<32)|info.nFileIndexLow)
          !=g_keepvault_expected_root_inode)
    error("bound Windows extraction root identity changed");
}

// NtCreateFile resolves a single leaf relative to the already-open parent.
// FILE_CREATE rejects pre-created entries and Win32 case/name aliases before
// any truncation. FILE_OPEN_REPARSE_POINT prevents final-link traversal.
static Handle create_child(HANDLE parent, const string& leaf, bool directory) {
  if (leaf.empty() || leaf.find_first_of("/\\:")!=string::npos)
    error("invalid bound Windows extraction leaf");
  typedef NTSTATUS (NTAPI *NtCreateFileFunction)(PHANDLE, ACCESS_MASK,
      POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
      ULONG, ULONG, PVOID, ULONG);
  static NtCreateFileFunction create_file=reinterpret_cast<NtCreateFileFunction>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
  if (!create_file) error("NtCreateFile is unavailable");
  std::wstring name=utow(leaf.c_str());
  if (name.empty() || name.size()>32766)
    error("invalid bound Windows extraction leaf encoding");
  UNICODE_STRING unicode={};
  unicode.Length=USHORT(name.size()*sizeof(wchar_t));
  unicode.MaximumLength=unicode.Length;
  unicode.Buffer=&name[0];
  OBJECT_ATTRIBUTES attributes={};
  attributes.Length=sizeof(attributes);
  attributes.RootDirectory=parent;
  attributes.ObjectName=&unicode;
  attributes.Attributes=0x40; // OBJ_CASE_INSENSITIVE
  IO_STATUS_BLOCK status_block={};
  HANDLE created=INVALID_HANDLE_VALUE;
  const ACCESS_MASK access=directory
      ? FILE_LIST_DIRECTORY|FILE_TRAVERSE|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|SYNCHRONIZE
      : GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE;
  const ULONG sharing=FILE_SHARE_READ|(directory ? FILE_SHARE_WRITE : 0);
  const ULONG options=0x00200000 // FILE_OPEN_REPARSE_POINT
      | 0x00000020 // FILE_SYNCHRONOUS_IO_NONALERT
      | (directory ? 0x00000001 : 0x00000040); // DIRECTORY/NON_DIRECTORY_FILE
  const NTSTATUS status=create_file(&created, access, &attributes, &status_block,
      NULL, FILE_ATTRIBUTE_NORMAL, sharing, 2 /* FILE_CREATE */, options, NULL, 0);
  if (status<0 || created==INVALID_HANDLE_VALUE)
    error("Windows output entry was pre-created, colliding, or could not be created");
  Handle result(new OwnedHandle(created));
  inspect(created, directory);
  return result;
}

// Keep every created directory and file open until all extraction workers have
// joined. Directory handles deny rename; file handles deny both write and
// rename. Reopening a fragment duplicates our held file object instead of
// resolving its pathname again. The existing native entry budget bounds the
// number of retained objects, and this layer enforces the hard ceiling too.
static void reserve_handle() {
  if (directories.size()+files.size()>KEEPVAULT_MAX_EXTRACTED_FILES)
    error("bound Windows output exceeds the extracted-entry handle budget");
}

static Handle directory(const string& path, bool create) {
  require_root();
  Handle current=root;
  string prefix;
  size_t start=0;
  while (start<path.size()) {
    const size_t separator=path.find('/', start);
    const size_t end=separator==string::npos ? path.size() : separator;
    const string leaf=path.substr(start, end-start);
    if (!prefix.empty()) prefix+='/';
    prefix+=leaf;
    std::map<string, Handle>::iterator known=directories.find(prefix);
    if (known==directories.end()) {
      if (!create) error("Windows output directory was not created by this extraction");
      reserve_handle();
      Handle child=create_child(current->value, leaf, true);
      known=directories.insert(std::make_pair(prefix, child)).first;
    }
    current=known->second;
    inspect(current->value, true);
    if (separator==string::npos) break;
    start=separator+1;
  }
  return current;
}

static void metadata(HANDLE handle, int64_t date, int64_t attr) {
  FILE_BASIC_INFO info={};
  bool change=false;
  if (date>0) {
    SYSTEMTIME time={};
    time.wYear=WORD(date/10000000000LL%10000);
    time.wMonth=WORD(date/100000000%100);
    time.wDay=WORD(date/1000000%100);
    time.wHour=WORD(date/10000%100);
    time.wMinute=WORD(date/100%100);
    time.wSecond=WORD(date%100);
    FILETIME file_time={};
    if (!SystemTimeToFileTime(&time, &file_time))
      error("invalid bound Windows output timestamp");
    info.LastWriteTime.HighPart=LONG(file_time.dwHighDateTime);
    info.LastWriteTime.LowPart=file_time.dwLowDateTime;
    change=true;
  }
  if ((attr&255)=='w') {
    const DWORD allowed=FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN
        |FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_TEMPORARY
        |FILE_ATTRIBUTE_OFFLINE|FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    info.FileAttributes=DWORD(attr>>8)&allowed;
    if (!info.FileAttributes) info.FileAttributes=FILE_ATTRIBUTE_NORMAL;
    change=true;
  }
  if (change && !SetFileInformationByHandle(handle, FileBasicInfo, &info, sizeof(info)))
    error("cannot set bound Windows output metadata");
}

static void require_empty_root() {
  vector<uint64_t> buffer(8192);
  for (;;) {
    if (!GetFileInformationByHandleEx(root->value, FileIdBothDirectoryInfo,
        &buffer[0], DWORD(buffer.size()*sizeof(buffer[0])))) {
      if (GetLastError()==ERROR_NO_MORE_FILES) return;
      error("cannot enumerate bound Windows extraction root");
    }
    size_t offset=0;
    for (;;) {
      const FILE_ID_BOTH_DIR_INFO* entry=reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(
          reinterpret_cast<const unsigned char*>(&buffer[0])+offset);
      const bool dot=entry->FileNameLength==2 && entry->FileName[0]==L'.';
      const bool dotdot=entry->FileNameLength==4
          && entry->FileName[0]==L'.' && entry->FileName[1]==L'.';
      if (!dot && !dotdot)
        error("bound Windows extraction root was not empty before output");
      if (!entry->NextEntryOffset) break;
      offset+=entry->NextEntryOffset;
      if (offset>buffer.size()*sizeof(buffer[0])-sizeof(FILE_ID_BOTH_DIR_INFO))
        error("invalid Windows extraction-root enumeration");
    }
  }
}

} // namespace keepvault_windows_output

static void keepvault_windows_release_output() {
  using namespace keepvault_windows_output;
  g_keepvault_windows_output_active=false;
  files.clear();
  directories.clear();
  root.reset();
}

static void keepvault_windows_initialize_output_root() {
  using namespace keepvault_windows_output;
  if (!g_keepvault_has_expected_root_device || !g_keepvault_has_expected_root_inode)
    error("v12 Windows extraction requires the expected output-root volume and file index");
  if (root) error("Windows extraction root was initialized more than once");
  HANDLE handle=CreateFileW(L".", FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
      // The managed caller already holds this exact root with DELETE access
      // and without FILE_SHARE_DELETE. Share its handle while retaining the
      // caller's rename exclusion for the entire native operation.
      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (handle==INVALID_HANDLE_VALUE) error("cannot open bound Windows extraction root");
  root.reset(new OwnedHandle(handle));
  try {
    require_root();
    require_empty_root();
    directories[""]=root;
    g_keepvault_windows_output_failed.store(false);
    g_keepvault_windows_output_active=true;
  }
  catch (...) {
    keepvault_windows_release_output();
    throw;
  }
}

static FP keepvault_windows_open_output(const string& path, bool create_new) {
  using namespace keepvault_windows_output;
  const string canonical=keepvault_canonical_output_path(path);
  const size_t separator=canonical.rfind('/');
  const string parent=separator==string::npos ? string() : canonical.substr(0, separator);
  const string leaf=separator==string::npos ? canonical : canonical.substr(separator+1);
  std::lock_guard<std::mutex> guard(mutex);
  if (g_keepvault_windows_output_failed.load()) error("Windows output previously failed");
  Handle parent_handle=directory(parent, true);
  std::map<string, Handle>::iterator known=files.find(canonical);
  if (create_new) {
    if (known!=files.end()) error("duplicate bound Windows output file");
    reserve_handle();
    if (g_keepvault_test_output_open_error.exchange(0))
      error("injected bound Windows output open failure");
    Handle created=create_child(parent_handle->value, leaf, false);
    known=files.insert(std::make_pair(canonical, created)).first;
  }
  else if (known==files.end()) {
    error("Windows output file was not created by this extraction");
  }
  inspect(known->second->value, false);
  HANDLE result=INVALID_HANDLE_VALUE;
  if (!DuplicateHandle(GetCurrentProcess(), known->second->value, GetCurrentProcess(),
      &result, 0, FALSE, DUPLICATE_SAME_ACCESS))
    error("cannot duplicate bound Windows output file");
  return result;
}

static void keepvault_windows_makepath(const string& path, int64_t date, int64_t attr) {
  using namespace keepvault_windows_output;
  const bool is_directory=!path.empty() && (path.back()=='/' || path.back()=='\\');
  const string canonical=keepvault_canonical_output_path(path);
  const size_t separator=canonical.rfind('/');
  const string parent=is_directory ? canonical
      : (separator==string::npos ? string() : canonical.substr(0, separator));
  std::lock_guard<std::mutex> guard(mutex);
  if (g_keepvault_windows_output_failed.load()) error("Windows output previously failed");
  Handle handle=directory(parent, true);
  if (is_directory) metadata(handle->value, date, attr);
}

static void keepvault_windows_close(const string& path, int64_t date, int64_t attr, FP fp) {
  using namespace keepvault_windows_output;
  // Take ownership before any validation which can throw. The retained map
  // handle stays valid; every caller-provided duplicate is closed exactly once.
  OwnedHandle closing(fp);
  const string canonical=keepvault_canonical_output_path(path);
  std::lock_guard<std::mutex> guard(mutex);
  require_root();
  std::map<string, Handle>::iterator found=files.find(canonical);
  const bool is_directory=found==files.end();
  Handle held=is_directory ? directory(canonical, false) : found->second;
  const BY_HANDLE_FILE_INFORMATION identity=inspect(held->value, is_directory);
  if (fp!=FPNULL && !same(identity, inspect(fp, is_directory)))
    error("Windows output close refers to a different object");
  metadata(held->value, date, attr);
  if (fp!=FPNULL) {
    closing.value=INVALID_HANDLE_VALUE;
    if (keepvault_checked_fclose(fp)!=0) error("bound Windows output close failed");
  }
}

// Existing v12 streaming comments are "size YYYYMMDDhhmmss [w|u]attributes"
// on the first segment and just "size" on continuations. The former Windows
// parallel writer carried the comment through decoding but discarded it.
static void keepvault_windows_parse_stream_metadata(const string& comment,
    size_t payload_bytes, bool first, int64_t& date, int64_t& attr) {
  size_t cursor=0;
  const auto number=[&](uint64_t maximum) {
    const size_t start=cursor;
    uint64_t value=0;
    while (cursor<comment.size() && comment[cursor]>='0' && comment[cursor]<='9') {
      const unsigned digit=unsigned(comment[cursor++]-'0');
      if (value>(maximum-digit)/10) error("stream metadata number exceeds its bound");
      value=value*10+digit;
    }
    if (cursor==start) error("missing stream metadata number");
    return value;
  };
  if (number(KEEPVAULT_PIPE_MAX_UNCOMPRESSED)!=payload_bytes)
    error("stream metadata length does not match the decoded segment");
  if (!first) {
    if (cursor!=comment.size()) error("continuation stream segment contains new metadata");
    return;
  }
  if (cursor>=comment.size() || comment[cursor++]!=' ')
    error("stream member has no timestamp metadata");
  const size_t date_start=cursor;
  date=int64_t(number(29991231235959ULL));
  if (cursor-date_start!=14 || date<19000101000000LL)
    error("invalid stream member timestamp");
  // Validate calendar fields even during list-only inspection.
  SYSTEMTIME time={};
  time.wYear=WORD(date/10000000000LL%10000);
  time.wMonth=WORD(date/100000000%100);
  time.wDay=WORD(date/1000000%100);
  time.wHour=WORD(date/10000%100);
  time.wMinute=WORD(date/100%100);
  time.wSecond=WORD(date%100);
  FILETIME encoded={};
  if (!SystemTimeToFileTime(&time, &encoded)) error("invalid stream member calendar date");
  attr=0;
  if (cursor<comment.size()) {
    if (comment[cursor++]!=' ' || cursor>=comment.size()
        || (comment[cursor]!='w' && comment[cursor]!='u'))
      error("invalid stream member attribute kind");
    const char kind=comment[cursor++];
    attr=int64_t(number(UINT32_MAX))<<8;
    attr|=kind;
  }
  if (cursor!=comment.size()) error("unexpected trailing stream metadata");
}

static int keepvault_windows_output_self_test() {
  using namespace keepvault_windows_output;
  OwnedHandle probe(CreateFileW(L".", FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT, NULL));
  const BY_HANDLE_FILE_INFORMATION info=inspect(probe.value, true);
  g_keepvault_expected_root_device=info.dwVolumeSerialNumber;
  const uint64_t index=(uint64_t(info.nFileIndexHigh)<<32)|info.nFileIndexLow;
  g_keepvault_expected_root_inode=index^1;
  g_keepvault_has_expected_root_device=g_keepvault_has_expected_root_inode=true;
  bool mismatch=false;
  try { keepvault_windows_initialize_output_root(); }
  catch (const std::exception&) { mismatch=true; }
  if (!mismatch) error("Windows output accepted a different root identity");
  g_keepvault_expected_root_inode=index;
  keepvault_windows_initialize_output_root();

  const unsigned char sentinel[4]={1, 2, 3, 4};
  {
    OwnedHandle foreign(CreateFileW(L"preexisting", GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL));
    DWORD written=0;
    if (foreign.value==INVALID_HANDLE_VALUE
        || !WriteFile(foreign.value, sentinel, sizeof(sentinel), &written, NULL)
        || written!=sizeof(sentinel)) error("cannot create Windows precreation sentinel");
  }
  bool precreated=false;
  try { OwnedHandle unexpected(keepvault_windows_open_output("preexisting", true)); }
  catch (const std::exception&) { precreated=true; }
  {
    OwnedHandle foreign(CreateFileW(L"preexisting", GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
    unsigned char contents[4]={};
    DWORD read=0;
    if (!precreated || foreign.value==INVALID_HANDLE_VALUE
        || !ReadFile(foreign.value, contents, sizeof(contents), &read, NULL)
        || read!=sizeof(contents) || memcmp(contents, sentinel, sizeof(contents)))
      error("Windows output truncated a pre-created file");
  }
  if (!CreateDirectoryW(L"precreated-dir", NULL)) error("cannot create directory sentinel");
  bool directory_collision=false;
  try { keepvault_windows_makepath("precreated-dir/escape", 0, 0); }
  catch (const std::exception&) { directory_collision=true; }
  if (!directory_collision || GetFileAttributesW(L"precreated-dir\\escape")!=INVALID_FILE_ATTRIBUTES)
    error("Windows output traversed a pre-created directory");

  // Mount-point reparse creation does not require Developer Mode or the
  // symbolic-link privilege, so this exercises a real NTFS junction on normal
  // release-test hosts. The target is a sibling of the attempted output path.
  std::vector<wchar_t> target_buffer(32768, 0);
  const DWORD target_length=GetFullPathNameW(L"precreated-dir", 32768, target_buffer.data(), NULL);
  if (!target_length || target_length>=32768 || !CreateDirectoryW(L"junction", NULL))
    error("cannot prepare Windows junction self-test");
  const std::wstring substitute=std::wstring(L"\\??\\")+target_buffer.data();
  const std::wstring printable=target_buffer.data();
  const size_t path_bytes=(substitute.size()+1+printable.size()+1)*sizeof(wchar_t);
  vector<unsigned char> reparse(16+path_bytes, 0);
  const DWORD mount_point_tag=0xA0000003;
  memcpy(&reparse[0], &mount_point_tag, sizeof(mount_point_tag));
  const WORD data_length=WORD(8+path_bytes);
  const WORD substitute_length=WORD(substitute.size()*sizeof(wchar_t));
  const WORD print_offset=WORD(substitute_length+sizeof(wchar_t));
  const WORD print_length=WORD(printable.size()*sizeof(wchar_t));
  memcpy(&reparse[4], &data_length, 2);
  memcpy(&reparse[10], &substitute_length, 2);
  memcpy(&reparse[12], &print_offset, 2);
  memcpy(&reparse[14], &print_length, 2);
  memcpy(&reparse[16], substitute.c_str(), substitute_length);
  memcpy(&reparse[16+print_offset], printable.c_str(), print_length);
  {
    OwnedHandle junction(CreateFileW(L"junction", GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT, NULL));
    DWORD returned=0;
    if (junction.value==INVALID_HANDLE_VALUE || !DeviceIoControl(junction.value,
        0x000900A4 /* FSCTL_SET_REPARSE_POINT */, &reparse[0], DWORD(reparse.size()),
        NULL, 0, &returned, NULL)) error("cannot install Windows junction self-test");
  }
  bool reparse_rejected=false;
  try { OwnedHandle unexpected(keepvault_windows_open_output("junction/escape", true)); }
  catch (const std::exception&) { reparse_rejected=true; }
  if (!reparse_rejected || GetFileAttributesW(L"precreated-dir\\escape")!=INVALID_FILE_ATTRIBUTES)
    error("Windows output followed a junction");

  keepvault_windows_makepath("bound/payload", 0, 0);
  FP output=keepvault_windows_open_output("bound/payload", true);
  if (fwrite(sentinel, 1, sizeof(sentinel), output)!=sizeof(sentinel))
    error("cannot write bound Windows self-test output");
  keepvault_windows_close("bound/payload", 20260909010203LL, 0, output);
  if (MoveFileW(L"bound", L"moved-bound") || MoveFileW(L"bound\\payload", L"moved-file"))
    error("Windows output permitted a bound subtree/file rename");
  OwnedHandle attacker(CreateFileW(L"bound\\payload", GENERIC_WRITE,
      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL));
  if (attacker.value!=INVALID_HANDLE_VALUE)
    error("Windows output admitted a writer between fragments");
  FP reopened=keepvault_windows_open_output("bound/payload", false);
  if (fseeko(reopened, 0, SEEK_SET)) error("cannot seek bound Windows output");
  unsigned char actual[4]={};
  if (fread(actual, 1, sizeof(actual), reopened)!=sizeof(actual)
      || memcmp(actual, sentinel, sizeof(actual)))
    error("Windows output fragment reopen changed its object or bytes");
  keepvault_windows_close("bound/payload", 0, 0, reopened);
  bool alias=false;
  try { OwnedHandle unexpected(keepvault_windows_open_output("BOUND/payload", true)); }
  catch (const std::exception&) { alias=true; }
  if (!alias) error("Windows output accepted a case-colliding directory");
  bool invalid_utf8=false;
  try { OwnedHandle unexpected(keepvault_windows_open_output("bad\xC0\xAFname", true)); }
  catch (const std::exception&) { invalid_utf8=true; }
  if (!invalid_utf8) error("Windows output accepted an overlong UTF-8 separator");
  const string unicode="unicode-\xF0\x9F\x94\x90";
  FP unicode_file=keepvault_windows_open_output(unicode, true);
  keepvault_windows_close(unicode, 0, 0, unicode_file);
  if (wtou(utow(unicode.c_str()).c_str())!=unicode)
    error("Windows output did not roundtrip supplementary Unicode");
  int64_t parsed_date=0, parsed_attr=0;
  keepvault_windows_parse_stream_metadata("4 20240229123456 w33", 4, true, parsed_date, parsed_attr);
  if (parsed_date!=20240229123456LL || parsed_attr!=('w'|(int64_t(33)<<8)))
    error("Windows stream metadata parser changed valid fields");
  keepvault_windows_parse_stream_metadata("4", 4, false, parsed_date, parsed_attr);
  const char* bad_comments[]={"4", "5 20240229123456", "4 20240230123456",
      "4 20240229123456 w4294967296", "4 20240229123456 w33 trailing",
      "18446744073709551615 20240229123456"};
  for (size_t i=0; i<sizeof(bad_comments)/sizeof(bad_comments[0]); ++i) {
    bool rejected=false;
    try { keepvault_windows_parse_stream_metadata(bad_comments[i], 4, true, parsed_date, parsed_attr); }
    catch (const std::exception&) { rejected=true; }
    if (!rejected) error("Windows stream metadata parser accepted malformed fields");
  }
  keepvault_windows_release_output();
  fprintf(stderr, "windows_output_root_identity=fail_closed\n"
      "windows_output_precreation=fail_closed\n"
      "windows_output_directory_precreation=fail_closed\n"
      "windows_output_junction=fail_closed\n"
      "windows_output_rename=denied\n"
      "windows_output_fragment_writer=denied\n"
      "windows_output_case_alias=fail_closed\n"
      "windows_output_utf8=fail_closed\n"
      "windows_output_supplementary_unicode=preserved\n"
      "windows_output_stream_metadata=validated\n");
  return 0;
}

#endif
