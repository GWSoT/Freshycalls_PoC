#include "freshycalls.hpp"
#include <algorithm>
#include <utility>


/*
 * Given a PEB and a module name searches in the current process the module in memory and returns the corresponding
 * base address. We do this by iterating through the given PEB
 *
 * @param[in] `peb` current process PEB
 * @param[in] `target_module` name of the module to locate
 * @return the module base address
 */

uintptr_t FreshycallsClass::get_module_addr(__PEB peb, std::string target_module) {
  std::transform(target_module.begin(), target_module.end(), target_module.begin(), std::tolower);
  const auto w_target_module = string_to_wstring(target_module);

  PLIST_ENTRY list_head = peb.Ldr->InMemoryOrderModuleList.Flink;

  for (PLIST_ENTRY current_entry = list_head->Flink; current_entry != list_head->Blink;
       current_entry = current_entry->Flink) {
    auto p_module = CONTAINING_RECORD(current_entry, __LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);

    std::wstring module_name(p_module->BaseDllName.Buffer, p_module->BaseDllName.Length / sizeof(wchar_t));
    std::transform(module_name.begin(), module_name.end(), module_name.begin(), std::tolower);

    if (module_name == w_target_module) {
      return uintptr_t(p_module->DllBase);
    }
  }

  std::ostringstream error_msg_stream;
  error_msg_stream << "[get_module_addr] Module '" << target_module.data() << "' " << "not found!";
  throw std::runtime_error(error_msg_stream.str());
}


/*
 * Given a PEB and a module name searches in the remote process the module in memory and returns the corresponding
 * base address. We do this by iterating through the given PEB
 *
 * @param[in] `peb` remote process PEB
 * @param[in] `target_module` name of the module to locate
 * @param[in] `h_process` remote process that contains the module
 * @return the module base address
 */

uintptr_t FreshycallsClass::get_module_addr(__PEB peb, std::string target_module, HANDLE h_process) {
  std::transform(target_module.begin(), target_module.end(), target_module.begin(), std::tolower);
  const auto w_target_module = string_to_wstring(target_module);

  const auto ldr_data = read_mem<__PEB_LDR_DATA>(h_process, uintptr_t(peb.Ldr), sizeof(__PEB_LDR_DATA)).
      throw_if_unexpected(NTSTATUS(0),
                          "[get_module_addr] Something happened reading the loader data of the remote process: 0x{{result_as_hex}}");

  const auto list_head_addr = reinterpret_cast<uintptr_t>(CONTAINING_RECORD(ldr_data.InMemoryOrderModuleList.Flink,
                                                                            __LDR_DATA_TABLE_ENTRY,
                                                                            InMemoryOrderModuleList));
  const auto list_head = read_mem<__LDR_DATA_TABLE_ENTRY>(h_process, list_head_addr, sizeof(__LDR_DATA_TABLE_ENTRY)).
      throw_if_unexpected(NTSTATUS(0),
                          "[get_module_addr] Something happened reading the module list head of the remote process: 0x{{result_as_hex}}");

  auto module_entry_addr = reinterpret_cast<uintptr_t>(CONTAINING_RECORD(list_head.InMemoryOrderModuleList.Flink,
                                                                         __LDR_DATA_TABLE_ENTRY,
                                                                         InMemoryOrderModuleList));
  auto module_data = read_mem<__LDR_DATA_TABLE_ENTRY>(h_process, module_entry_addr, sizeof(__LDR_DATA_TABLE_ENTRY)).
      throw_if_unexpected(NTSTATUS(0),
                          "[get_module_addr] Something happened reading the data of a module inside the remote process: 0x{{result_as_hex}}");

  while (module_data.InMemoryOrderModuleList.Flink != list_head.InMemoryOrderModuleList.Blink) {

    const auto module_name_buffer =
        read_to_vector<wchar_t>(h_process, uintptr_t(module_data.BaseDllName.Buffer), module_data.BaseDllName.Length).
            throw_if_unexpected(NTSTATUS(0),
                                "[get_module_addr] Something happened reading the module name buffer inside the remote process: 0x{{result_as_hex}}");

    std::wstring module_name(module_name_buffer.data(), module_data.BaseDllName.Length / sizeof(wchar_t));
    std::transform(module_name.begin(), module_name.end(), module_name.begin(), std::tolower);

    if (module_name == w_target_module) {
      return uintptr_t(module_data.DllBase);
    }

    module_entry_addr = reinterpret_cast<uintptr_t>(CONTAINING_RECORD(module_data.InMemoryOrderModuleList.Flink,
                                                                      __LDR_DATA_TABLE_ENTRY,
                                                                      InMemoryOrderModuleList));
    module_data = read_mem<__LDR_DATA_TABLE_ENTRY>(h_process, module_entry_addr, sizeof(__LDR_DATA_TABLE_ENTRY)).
        throw_if_unexpected(NTSTATUS(0),
                            "[get_module_addr] Something happened reading the data of a module inside the remote process: 0x{{result_as_hex}}");
  }

  std::ostringstream error_msg_stream;
  error_msg_stream << "[get_module_addr] Module '" << target_module.data() << "' " << "not found!";
  throw std::runtime_error(error_msg_stream.str());
}


/*
 * Given a module name (and optionally a process) tries to get the PEB of the process and locate the module
 *
 * @param[in] `target_module` name of the module to locate
 * @optparam[in] `h_process` handle to the process that contains the module
 * @return the module base address
 */

uintptr_t FreshycallsClass::get_module_addr(std::string target_module, HANDLE h_process) {
  std::transform(target_module.begin(), target_module.end(), target_module.begin(), std::tolower);

  __PEB p_peb;

  if (h_process == HANDLE(-1)) {
    p_peb = *reinterpret_cast<__PPEB>(__readgsqword(0x60));
    return get_module_addr(p_peb, target_module);

  } else {
    __PROCESS_BASIC_INFORMATION psi;

    caller<NTSTATUS>("NtQueryInformationProcess", h_process, 0, &psi, sizeof(psi), nullptr).
        throw_if_unexpected(NTSTATUS(0),
                            "[get_module_addr] Something happened querying the PEB of the remote process: 0x{{result_as_hex}}");

    p_peb = read_mem<__PEB>(h_process, uintptr_t(psi.PebBaseAddress), sizeof(__PEB)).
        throw_if_unexpected(NTSTATUS(0),
                            "[get_module_addr] Something happened reading the PEB of the remote process: 0x{{result_as_hex}}");

    return get_module_addr(p_peb, target_module, h_process);
  }
}


/*
 * Given a module base address and a function name tries to iterate the export directory of a remote process
 * to find the base address of the targeted function
 *
 * @param[in] `module_addr` base address of the module that contains the function
 * @param[in] `target_function` the name of the function to locate
 * @param[in] `h_process` handle to the process that contains the function
 * @return the function base address
 */

uintptr_t FreshycallsClass::get_function_addr(uintptr_t module_addr, std::string target_function,
                                              HANDLE h_process) {
  std::transform(target_function.begin(), target_function.end(), target_function.begin(), std::tolower);

  auto const dos_header = read_mem<IMAGE_DOS_HEADER>(h_process, module_addr, sizeof(IMAGE_DOS_HEADER)).
      throw_if_unexpected(NTSTATUS(0),
                          "[get_function_addr] Something happened reading the IMAGE_DOS_HEADER of the module at %p inside a remote process: 0x{{result_as_hex}}",
                          module_addr);

  auto const
      nt_headers = read_mem<IMAGE_NT_HEADERS>(h_process, (module_addr + dos_header.e_lfanew), sizeof(IMAGE_NT_HEADERS)).
      throw_if_unexpected(NTSTATUS(0),
                          "[get_function_addr] Something happened reading the IMAGE_NT_HEADERS of the module at %p inside a remote process: 0x{{result_as_hex}}",
                          module_addr);

  auto const export_dir = read_mem<IMAGE_EXPORT_DIRECTORY>(h_process,
                                                           (module_addr + nt_headers.OptionalHeader.DataDirectory[0]
                                                               .VirtualAddress),
                                                           sizeof(IMAGE_EXPORT_DIRECTORY)).
      throw_if_unexpected(NTSTATUS(0),
                          "[get_function_addr] Something happened reading the IMAGE_EXPORT_DIRECTORY of the module at %p inside a remote process: 0x{{result_as_hex}}",
                          module_addr);

  auto const functions_table = read_to_vector<DWORD>(h_process,
                                                     (module_addr + export_dir.AddressOfFunctions),
                                                     sizeof(DWORD) * export_dir.NumberOfNames).
      throw_if_unexpected(NTSTATUS(0),
                          "[get_function_addr] Something happened reading the functions table of the module at %p: 0x{{result_as_hex}}",
                          module_addr);

  auto const names_table = read_to_vector<DWORD>(h_process,
                                                 (module_addr + export_dir.AddressOfNames),
                                                 sizeof(DWORD) * export_dir.NumberOfNames).
      throw_if_unexpected(NTSTATUS(0),
                          "[get_function_addr] Something happened reading the names table of the module at %p: 0x{{result_as_hex}}",
                          module_addr);

  auto const names_ordinals = read_to_vector<WORD>(h_process,
                                                   (module_addr + export_dir.AddressOfNameOrdinals),
                                                   sizeof(WORD) * export_dir.NumberOfNames).
      throw_if_unexpected(NTSTATUS(0),
                          "[get_function_addr] Something happened reading the names ordinals of the module at %p: 0x{{result_as_hex}}",
                          module_addr);

  for (size_t i = 0; i < export_dir.NumberOfNames; i++) {
    std::string function_name(reinterpret_cast<char *>(module_addr + names_table.at(i)));
    std::transform(function_name.begin(), function_name.end(), function_name.begin(), std::tolower);

    if (target_function == function_name) {
      const WORD function_ordinal = names_ordinals[i];
      const uintptr_t function_addr = module_addr + functions_table.at(function_ordinal);

      return function_addr;
    }
  }

  std::ostringstream error_msg_stream;
  error_msg_stream << "[get_function_addr] Function '" << target_function.data() << "' " << "not found!";
  throw std::runtime_error(error_msg_stream.str());
}


/*
 * Given a module base address and a function name tries to iterate the export directory of the current process
 * to find the base address of the targeted function
 *
 * @param[in] `module_addr` base address of the module that contains the function
 * @param[in] `target_function` the name of the function to locate
 * @return the function base address
 */

uintptr_t FreshycallsClass::get_function_addr(uintptr_t module_addr, std::string target_function) {
  std::transform(target_function.begin(), target_function.end(), target_function.begin(), std::tolower);

  auto const dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_addr);
  auto const nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(module_addr + dos_header->e_lfanew);
  auto const export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(module_addr
      + nt_headers->OptionalHeader.DataDirectory[0].VirtualAddress);

  auto const functions_table = reinterpret_cast<PDWORD>(module_addr + export_dir->AddressOfFunctions);
  auto const names_table = reinterpret_cast<PDWORD>(module_addr + export_dir->AddressOfNames);
  auto const names_ordinals = reinterpret_cast<PWORD>(module_addr + export_dir->AddressOfNameOrdinals);

  for (size_t i = 0; i < export_dir->NumberOfNames; i++) {
    std::string function_name(reinterpret_cast<char *>(module_addr + names_table[i]));
    std::transform(function_name.begin(), function_name.end(), function_name.begin(), std::tolower);

    if (target_function == function_name) {
      const WORD function_ordinal = names_ordinals[i];
      uintptr_t function_addr = module_addr + functions_table[function_ordinal];

      return function_addr;
    }
  }

  std::ostringstream error_msg_stream;
  error_msg_stream << "[get_function_addr] Function '" << target_function.data() << "' " << "not found!";
  throw std::runtime_error(error_msg_stream.str());
}


/*
 * Given a module name and a function name tries to locate the module and then iterate the export directory to find out
 * the targeted function
 *
 * @param[in] `target_module` name of the module that contains the function
 * @param[in] `target_function` name of the function to locate
 * @optparam[in] `h_process`
 * @return the function base address
 */

uintptr_t FreshycallsClass::get_function_addr(std::string target_module, std::string target_function,
                                              HANDLE h_process) {
  uintptr_t module_addr;

  try {
    if (h_process == HANDLE(-1)) {
      module_addr = get_module_addr(std::move(target_module));
      return get_function_addr(module_addr, std::move(target_function));
    } else {
      module_addr = get_module_addr(std::move(target_module), h_process);
      return get_function_addr(module_addr, std::move(target_function), h_process);
    }
  }
  catch (const std::runtime_error &e) {
    std::cout << e.what() << std::endl;
    exit(-1);
  }
}