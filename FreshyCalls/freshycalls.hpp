#pragma once
#include "common.hpp"

class FreshycallsClass {


  /*
   * A template of how a (non-hooked) syscall stub should look. Used by `unhook_stub`
   */

  const unsigned char stub_template[11] = {
      0x49, 0x89, 0xCA,                      // mov r10, rcx
      0xB8, 0xFF, 0xFF, 0x00, 0x00,          // mov eax, XXX
      0x0F, 0x05,                            // syscall
      0xC3                                   // ret
  };

  AddressMap_t extract_addresses();
  static SyscallMap_t extract_syscalls(const AddressMap_t &addresses);
  uintptr_t get_stub_addr(const std::string &stub_name);
  static uintptr_t get_syscall_inst_addr(uintptr_t stub_addr);

 public:
  AddressMap_t addresses_map;
  SyscallMap_t syscalls_map;

  FreshycallsClass() {
    addresses_map = extract_addresses();
    syscalls_map = extract_syscalls(addresses_map);
  }


  /*
   * Given a syscall stub name calls the corresponding system service using `manual_syscall_stub`
   *
   * @tparam `ReturnType` the type of what the service returns as output
   * @tparam `Args...` every argument type needed to call the service
   *
   * @param[in] `stub_name` the name of the target service stub
   * @param[in] `args...` every argument type needed to call the service
   * @return the output of the system service call
   */

  template<typename ReturnType, typename... Args>
  function_result<ReturnType> direct_caller(const std::string &stub_name, Args ... args) {
    using function_def = ReturnType(__cdecl *)(DWORD, Args ...);
    function_def function = reinterpret_cast<decltype(function)>(&manual_syscall_stub);

    DWORD syscall_no = syscalls_map.find(stub_name.data())->second;
    ReturnType output = function(syscall_no, std::forward<Args>(args)...);

    return function_result<ReturnType>(output);
  }


  /*
   * Given a syscall stub name tries to call the corresponding system service using `masked_syscall_stub`. If
   * the `syscall` instruction is present in the stub, it will call `direct_caller`
   *
   * @tparam `ReturnType` the type of what the service returns as output
   * @tparam `Args...` every argument type needed to call the service
   *
   * @param[in] `stub_name` the name of the target service stub
   * @param[in] `args...` every argument type needed to call the service
   * @return a `function_result` of `ReturnType` type
   */

  template<typename ReturnType, typename... Args>
  function_result<ReturnType> caller(const std::string &stub_name, Args ... args) {
    uintptr_t syscall_inst_addr;

    try {
      syscall_inst_addr = get_syscall_inst_addr(get_stub_addr(stub_name));
    }
    catch (const std::runtime_error &e) {
      std::cout << e.what() << std::endl;
      exit(-1);
    }

    if (syscall_inst_addr == 0) {
      // if the syscall instruction is not found in the stub use `manual_syscall_stub`
      return direct_caller<ReturnType>(stub_name, std::forward<Args>(args)...);

    } else {
      DWORD syscall_no = syscalls_map.find(stub_name.data())->second;

      using function_def = ReturnType(__cdecl *)(uintptr_t, DWORD, Args ...);
      function_def function = reinterpret_cast<decltype(function)>(&masked_syscall_stub);
      ReturnType output = function(syscall_inst_addr, syscall_no, std::forward<Args>(args)...);
      return function_result<ReturnType>(output);
    }
  }


  /*
   * Given a module name and a function name tries to locate both and call them
   *
   * @tparam `ReturnType` the type of what the function returns as output
   * @tparam `Args...` every argument type needed to call the function
   *
   * @param[in] `module_name` the module name that contains the function
   * @param[in] `function_name` the name of the function to call
   * @param[in] `args...` every argument type needed to call the function
   * @return a `function_result` of `ReturnType` type
   */

  template<typename ReturnType, typename... Args>
  function_result<ReturnType> module_caller(const std::string &module_name,
                                            const std::string &function_name,
                                            Args... args) {
    try {
      uintptr_t function_addr = get_function_addr(module_name, function_name);
      using function_def = ReturnType(__cdecl *)(Args ...);
      function_def function = reinterpret_cast<decltype(function)>(function_addr);
      ReturnType output = function(std::forward<Args>(args)...);
      return function_result<ReturnType>(output);
    }
    catch (std::runtime_error &e) {
      std::cout << e.what() << std::endl;
      exit(-1);
    }
  }


  /*
   * Given a module base address and a function name tries to locate the function and call it
   *
   * @tparam `ReturnType` the type of what the function returns as output
   * @tparam `Args...` every argument type needed to call the function
   *
   * @param[in] `module_name` the base address of the module that contains the function
   * @param[in] `function_name` the name of the function to call
   * @param[in] `args...` every argument type needed to call the function
   * @return a `function_result` of `ReturnType` type
   */

  template<typename ReturnType, typename... Args>
  function_result<ReturnType> module_caller(uintptr_t module_addr, const std::string &function_name,
                                            Args... args) {
    try {
      const uintptr_t function_addr = get_function_addr(module_addr.data(), function_name);
      using function_def = ReturnType(__cdecl *)(Args ...);
      function_def function = reinterpret_cast<decltype(function)>(function_addr);
      ReturnType output = function(std::forward<Args>(args)...);
      return function_result<ReturnType>(output);
    }
    catch (std::runtime_error &e) {
      std::cout << e.what() << std::endl;
      exit(-1);
    }
  }


  /*
   * Wrapper around `NtReadVirtualMemory` that tries to cast the memory read to the given `OutputType` type
   * Warning! This should work fine with basic types and structures. However, with more complex types like
   * `std::vector`, `std::map` or `std::tuple` it may crash, not compile or run into some undefined behaviour
   *
   * @tparam `OutputType` the type to cast the memory to
   *
   * @param[in] `h_process` the process handle to read the memory from
   * @param[in] `base_addr` the base address to start reading from
   * @param[in] `mem_size` number of bytes to read
   * @return a `function_result_with_output` with the casted memory as output
   */

  // if the type is a pointer
  template<typename OutputType>
  typename std::enable_if<std::is_pointer<OutputType>::value,
                          function_result_with_output<NTSTATUS, OutputType>>::type read_mem(HANDLE h_process,
                                                                                            uintptr_t base_addr,
                                                                                            size_t mem_size) {

    std::vector<unsigned char> mem_buffer;
    mem_buffer.resize(mem_size);
    OutputType output;

    auto result =
        caller<NTSTATUS>("NtReadVirtualMemory", h_process, base_addr, mem_buffer.data(), mem_size, nullptr).result;

    output = reinterpret_cast<OutputType>(mem_buffer.data());
    return function_result_with_output<NTSTATUS, OutputType>(result, output);
  }

  // if the type isn't a pointer
  template<typename OutputType>
  typename std::enable_if<!std::is_pointer<OutputType>::value,
                          function_result_with_output<NTSTATUS, OutputType>>::type read_mem(HANDLE h_process,
                                                                                            uintptr_t base_addr,
                                                                                            size_t mem_size) {

    std::vector<unsigned char> mem_buffer;
    mem_buffer.resize(mem_size);
    OutputType output;

    auto result =
        caller<NTSTATUS>("NtReadVirtualMemory", h_process, base_addr, mem_buffer.data(), mem_size, nullptr).result;

    output = *(new((OutputType *)mem_buffer.data()) OutputType);
    return function_result_with_output<NTSTATUS, OutputType>(result, output);
  }


  /*
   * Wrapper around `NtReadVirtualMemory` that tries to cast the memory read into a std::vector of `VectorType` type
   * Warning! This should work fine with basic types and structures. However, with more complex types like
   * `std::vector`, `std::map` or `std::tuple` it may crash, not compile or run into some undefined behaviour
   *
   * @tparam `VectorType` the type of the vector to cast the memory to
   *
   * @param[in] `h_process` the process handle to read the memory from
   * @param[in] `base_addr` the base address to start reading from
   * @param[in] `mem_size` number of bytes to read
   * @return a `function_result_with_output` with the casted memory as output
   */

  template<typename VectorType>
  function_result_with_output<NTSTATUS, std::vector<VectorType>> read_to_vector(HANDLE h_process, uintptr_t base_addr,
                                                                                size_t mem_size) {
    std::vector<VectorType> mem_buffer;
    mem_buffer.resize(mem_size);

    auto result =
        caller<NTSTATUS>("NtReadVirtualMemory", h_process, base_addr, mem_buffer.data(), mem_size, nullptr).result;

    return function_result_with_output<NTSTATUS, std::vector<VectorType>>(result, mem_buffer);
  }

  __UNICODE_STRING string_to_ntpath(const std::string &str);

  uintptr_t get_module_addr(__PEB p_peb, std::string target_module);
  uintptr_t get_module_addr(__PEB p_peb, std::string target_module, HANDLE h_process);
  uintptr_t get_module_addr(std::string target_module, HANDLE h_process = HANDLE(-1));

  uintptr_t get_function_addr(std::string module_name, std::string target_function, HANDLE h_process = HANDLE(-1));
  uintptr_t get_function_addr(uintptr_t module_addr, std::string target_function);
  uintptr_t get_function_addr(uintptr_t module_addr, std::string target_function, HANDLE h_process);

  std::vector<unsigned char> unhook_stub(const std::string &target_stub, HANDLE h_process = HANDLE(-1));
  void patch_stub(const std::string &target_stub, std::vector<unsigned char> mem,
                  HANDLE h_process = HANDLE(-1));

  function_result<NTSTATUS> write_mem(HANDLE h_process, uintptr_t base_addr, size_t mem_size, void *buffer);
  function_result_with_output<NTSTATUS, ULONG> protect_mem(HANDLE h_process, uintptr_t base_addr,
                                                           size_t mem_size, ULONG new_protection);
};