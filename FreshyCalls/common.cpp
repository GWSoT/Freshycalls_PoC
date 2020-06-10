#include "common.hpp"


/*
 * This small shellcode takes a syscall number as the first argument and calls the associated system service using the
 * rest of the arguments. As the syscall number is the first argument, we need to realign the stack and move forward
 * every subsequent argument by 1 (second argument becomes first, third becomes second, ... n becomes n-1).
 *
 * We are telling the linker to allocate this shellcode at the .text segment so we don't need to change it's protection
 * to execute it.
 */

#pragma section(".text")
__declspec(allocate(".text")) unsigned char manual_syscall_stub[] = {
    0x48, 0x89, 0xC8,                                    // mov rax, rcx
    0x48, 0x89, 0xD1,                                    // mov rcx, rdx
    0x4C, 0x89, 0xC2,                                    // mov rdx, r8
    0x4D, 0x89, 0xC8,                                    // mov r8, r9
    0x4C, 0x8B, 0x4C, 0x24, 0x28,                        // mov r9, [rsp+28h]
    0x49, 0x89, 0xCA,                                    // mov r10, rcx
    0x48, 0x83, 0xC4, 0x08,                              // add rsp, 8
    0x0F, 0x05,                                          // syscall
    0x48, 0x83, 0xEC, 0x08,                              // sub rsp, 8
    0xC3                                                 // ret
};


/*
 * This shellcode takes an address as the first argument and a syscall number as the second. The address passed
 * should be of a `syscall` instruction. As with `manual_syscall_stub`, we need to realign the stack and move forward
 * every argument by 2 (third becomes first, forth becomes second, ... n becomes n-2).
 *
 * Leveraging this trampoline we make use of the ret and syscall instruction of the real stub so our return address will
 * be within the memory of the stub (ntdll!NtReadVirtualMemory for example) avoiding manual syscall loggings that may
 * depend on these values
 */

#pragma section(".text")
__declspec(allocate(".text")) unsigned char masked_syscall_stub[] = {
    0x41, 0x55,                                          // push r13
    0x41, 0x56,                                          // push r14
    0x49, 0x89, 0xCE,                                    // mov r14, rcx
    0x49, 0x89, 0xD5,                                    // mov r13, rdx
    0x4C, 0x89, 0xC1,                                    // mov rcx, r8
    0x4C, 0x89, 0xCA,                                    // mov rdx, r9
    0x4C, 0x8B, 0x44, 0x24, 0x38,                        // mov r8, [rsp+38h]
    0x4C, 0x8B, 0x4C, 0x24, 0x40,                        // mov r9, [rsp+40h]
    0x48, 0x83, 0xC4, 0x28,                              // add rsp, 28h
    0x4C, 0x8D, 0x1D, 0x0C, 0x00, 0x00, 0x00,            // lea r11, [rip+0xC] ----
    0x41, 0xFF, 0xD3,                                    // call r11               |
    0x48, 0x83, 0xEC, 0x28,                              // sub rsp, 28h           |
    0x41, 0x5E,                                          // pop r14                |
    0x41, 0x5D,                                          // pop r13                |
    0xC3,                                                // ret                    |
    //                                                                             |
    0x4C, 0x89, 0xE8,                                    // mov rax, r13      <----
    0x49, 0x89, 0xCA,                                    // mov r10, rcx
    0x41, 0xFF, 0xE6                                     // jmp r14
};


/*
 * Converts a string into a wstring using `MultiByteToWideChar`
 *
 * @param[in] `str` the string to convert
 * @return a wstring equivalent to `str`
 */

std::wstring string_to_wstring(const std::string &str) {
  int no_chars = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), nullptr, 0);
  std::wstring wstr(no_chars, 0);

  MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), LPWSTR(wstr.data()), no_chars);

  return wstr;
}

