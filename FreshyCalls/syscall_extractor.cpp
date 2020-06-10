#include "freshycalls.hpp"


/*
 * Extracts the addresses of every syscall stub within ntdll.dll by iterating the export directory. The addresses in
 * memory of each stub have the same order as the syscall numbers, hence the stub at the lowest address will be the
 * one with the lowest syscall number (0).
 * For this reason, we store the address as the key of the map. By default `std::map` is sorted in ascending
 * order by key.
 *
 * @return a `std::map` with the addresses and names of every syscall stub found
 */

AddressMap_t FreshycallsClass::extract_addresses() {
  AddressMap_t addresses;
  uintptr_t ntdll_addr;

  try {
    ntdll_addr = get_module_addr("ntdll.dll");
  }
  catch (const std::runtime_error &e) {
    std::cout << e.what() << std::endl;
    exit(-1);
  }

  auto const dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(ntdll_addr);
  auto const nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(ntdll_addr + dos_header->e_lfanew);
  auto const export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(ntdll_addr
      + nt_headers->OptionalHeader.DataDirectory[0].VirtualAddress);

  auto const functions_table = reinterpret_cast<PDWORD>(ntdll_addr + export_dir->AddressOfFunctions);
  auto const names_table = reinterpret_cast<PDWORD>(ntdll_addr + export_dir->AddressOfNames);
  auto const names_ordinals = reinterpret_cast<PWORD>(ntdll_addr + export_dir->AddressOfNameOrdinals);

  for (size_t i = 0; i < export_dir->NumberOfNames; i++) {
    const std::string function_name(reinterpret_cast<char *>(ntdll_addr + names_table[i]));

    // Our stub should start with "Nt" but not with "Ntdll"
    if (function_name.rfind("Nt", 0) == 0 && function_name.rfind("Ntdll", 0) == std::string::npos) {
      const WORD function_ordinal = names_ordinals[i];
      uintptr_t function_addr = ntdll_addr + functions_table[function_ordinal];

      addresses.insert(std::make_pair(function_addr, function_name));
    }
  }

  return addresses;
}


/*
 * Given a `std::map` makes another using the stub name as key and the syscall number by value. As the map will be
 * sorted, we can get every syscall number by iterating each element of the map while adding one to the syscall number
 * (so the first element of the map is syscall number 0 and so on)
 *
 * param[in] `addresses` a `std::map` with the addresses and names of every syscall stub found
 */

SyscallMap_t FreshycallsClass::extract_syscalls(const AddressMap_t &addresses) {
  SyscallMap_t syscalls;

  DWORD syscall_no = 0;
  for (const auto &pair : addresses) {
    syscalls.insert(std::make_pair(pair.second, syscall_no));

    syscall_no++;
  }

  return syscalls;
}