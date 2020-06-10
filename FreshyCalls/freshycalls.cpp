#include "freshycalls.hpp"


/*
 * Given a syscall stub name iterates the `addresses_map` to find out the associated stub address
 *
 * @param[in] `stub_name` the syscall stub name
 * @return the syscall stub address
 */

uintptr_t FreshycallsClass::get_stub_addr(const std::string &stub_name) {
  for (const auto &pair : addresses_map) {
    if (pair.second == stub_name) {
      return pair.first;
    }
  }

  std::ostringstream error_msg_stream;
  error_msg_stream << "[get_stub_addr] No stub called '" << stub_name << "' " << "found!";
  throw std::runtime_error(error_msg_stream.str());
}


/*
 * Given a syscall stub address tries to find the `syscall` instruction address associated. Returns 0 if not found
 *
 * @param[in] `stub_addr` the syscall stub address
 * @return the `syscall` instruction address or 0
 */

uintptr_t FreshycallsClass::get_syscall_inst_addr(uintptr_t stub_addr) {
  uintptr_t syscall_inst_addr;

  // Windows 10
  if (*(reinterpret_cast<unsigned char *>(stub_addr + 0x12)) == 0x0F &&
      *(reinterpret_cast<unsigned char *>(stub_addr + 0x13)) == 0x05) {
    syscall_inst_addr = stub_addr + 0x12;
  }

    // prior to Windows 10
  else if (*(reinterpret_cast<unsigned char *>(stub_addr + 0x8)) == 0x0F &&
      *(reinterpret_cast<unsigned char *>(stub_addr + 0x9)) == 0x05) {
    syscall_inst_addr = stub_addr + 0x8;
  }

    // not found
  else {
    syscall_inst_addr = 0;
  }

  return syscall_inst_addr;
}


/*
 * Wrapper around `NtProtectVirtualMemory`
 * Warning! `NtProtectVirtualMemory` will not only change the protection of the memory range you provide but also the
 * page that contains that memory range
 *
 * @param[in] `h_process` handle to the target process
 * @param[in] `base_addr` base address of the memory to change protection
 * @param[in] `mem_size` number of bytes to change protection
 * @param[in] `new_protection` the new protection
 * @return a f`unction_result_with_output` with the old protection as output
 */

function_result_with_output<NTSTATUS, ULONG> FreshycallsClass::protect_mem(HANDLE h_process, uintptr_t base_addr,
                                                                           size_t mem_size, ULONG new_protection) {
  ULONG old_protection = 0;
  uintptr_t page_addr = base_addr;
  SIZE_T page_size = mem_size;

  auto result =
      caller<NTSTATUS>("NtProtectVirtualMemory", h_process, &page_addr, &page_size, new_protection, &old_protection)
          .result;

  return {result, old_protection};
}


/*
 * Wrapper around `NtWriteVirtualMemory`
 *
 * @param[in] `h_process` handle to the target process
 * @param[in] `base_addr` base address of the memory to write
 * @param[in] `mem_size` number of bytes to write
 * @param[in] `buffer` pointer to the buffer to write
 * @return a `function_result`
 */

function_result<NTSTATUS> FreshycallsClass::write_mem(HANDLE h_process, uintptr_t base_addr, size_t mem_size,
                                                      void *buffer) {

  auto result = caller<NTSTATUS>("NtWriteVirtualMemory", h_process, base_addr, buffer, mem_size, nullptr).result;

  return function_result<NTSTATUS>(result);
}


/*
 * Given a stub name tries to replace the stub memory with `stub_template` so you can use an alternate function that
 * indirectly calls that stub """safely"""
 *
 * @param[in] `target_stub` the target stub name
 * @optparam[in] `h_process` handle to the process to unhook the stub from
 * @return a `std::vector<unsigned char>` that contains the original memory
 */

std::vector<unsigned char> FreshycallsClass::unhook_stub(const std::string &target_stub, HANDLE h_process) {
  std::vector<unsigned char> new_stub_mem;

  uintptr_t stub_addr;
  try {
    stub_addr = get_stub_addr(target_stub);
  }
  catch (const std::runtime_error &e) {
    std::cout << e.what() << std::endl;
    exit(-1);
  }

  const auto next_stub = std::next(addresses_map.find(stub_addr));

  size_t stub_size;
  if (next_stub == addresses_map.end()) {
    stub_size = sizeof(stub_template);
  } else {
    stub_size = next_stub->first - stub_addr;
  }

  DWORD syscall_no = syscalls_map.find(target_stub)->second;
  unsigned char syscall_no_bytes[sizeof(DWORD)] = {0};
  memcpy(syscall_no_bytes, &syscall_no, sizeof(DWORD));

  new_stub_mem.insert(new_stub_mem.begin(), &stub_template[0], &stub_template[sizeof(stub_template)]);
  new_stub_mem.at(4) = syscall_no_bytes[0];
  new_stub_mem.at(5) = syscall_no_bytes[1];

  auto original_mem = read_to_vector<unsigned char>(h_process, stub_addr, stub_size).
      throw_if_unexpected(NTSTATUS(0),
                          "[unhook_stub] Something happened reading the memory of '%s': 0x{{result_as_hex}}",
                          target_stub.data());

  const auto original_protection = protect_mem(h_process, stub_addr, stub_size, PAGE_EXECUTE_READWRITE).
      throw_if_unexpected(NTSTATUS(0),
                          "[unhook_stub] Something happened making the memory of the page that contains '%s' writable: 0x{{result_as_hex}}",
                          target_stub.data());

  write_mem(h_process, stub_addr, stub_size, new_stub_mem.data()).
      throw_if_unexpected(NTSTATUS(0),
                          "[unhook_stub] Something happened writing our patch in '%s': 0x{{result_as_hex}}",
                          target_stub.data());

  protect_mem(h_process, stub_addr, stub_size, original_protection).
      throw_if_unexpected(NTSTATUS(0),
                          "[unhook_stub] Something happened making the memory of the page that contains '%s' back to original protection: 0x{{result_as_hex}}",
                          target_stub.data());

  return original_mem;
}


/*
 * Given a stub name and a `std::vector<unsigned char>` tries to replace n bytes from the stub memory with the bytes
 * inside the vector
 *
 * @param[in] `target_stub` the target stub name
 * @param[in] `mem` a `std::vector<unsigned char>` which contains the bytes to replace in the stub
 * @optparam[in] `h_process` handle to the process to unhook the stub from
 */

void FreshycallsClass::patch_stub(const std::string &target_stub, std::vector<unsigned char> mem,
                                  HANDLE h_process) {
  uintptr_t stub_addr;
  try {
    stub_addr = get_stub_addr(target_stub);
  }
  catch (const std::runtime_error &e) {
    std::cout << e.what() << std::endl;
    exit(-1);
  }

  size_t patch_size = mem.size();

  const auto original_protection = protect_mem(h_process, stub_addr, patch_size, PAGE_EXECUTE_READWRITE).
      throw_if_unexpected(NTSTATUS(0),
                          "[patch_stub] Something happened making the memory of the page that contains '%s' writable: 0x{{result_as_hex}}",
                          target_stub.data());

  write_mem(h_process, stub_addr, patch_size, mem.data()).
      throw_if_unexpected(NTSTATUS(0),
                          "[patch_stub] Something happened writing our patch in '%s': 0x{{result_as_hex}}",
                          target_stub.data());

  protect_mem(h_process, stub_addr, patch_size, original_protection).
      throw_if_unexpected(NTSTATUS(0),
                          "[patch_stub] Something happened making the memory of the page that contains '%s' back to original protection: 0x{{result_as_hex}}",
                          target_stub.data());
}


/*
 * Converts a given string into a NT Path
 *
 * @param[in] `str` the string that contains the path to transform
 * @return a `UNICODE_STRING` with the path
 */

__UNICODE_STRING FreshycallsClass::string_to_ntpath(const std::string &str) {
  __UNICODE_STRING ntpath;

  auto tmp_wstr = string_to_wstring(str);

  module_caller<bool>("ntdll.dll", "RtlDosPathNameToNtPathName_U", tmp_wstr.data(), &ntpath, nullptr, nullptr).
      throw_if_unexpected(true,
                          "[string_to_ntpath] Something happened transforming the UNICODE_STRING into a NT Path: 0x{{result_as_hex}}");

  return ntpath;
}