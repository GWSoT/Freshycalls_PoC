#pragma once

#include <Windows.h>
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include "windows_structs.hpp"

extern unsigned char manual_syscall_stub[];
extern unsigned char masked_syscall_stub[];


/*
 * Some aliases to easily use maps
 */

using AddressMap_t = std::map<uintptr_t, std::string>;
using SyscallMap_t = std::map<std::string, DWORD>;

std::wstring string_to_wstring(const std::string &str);


/*
 * Takes a template and formats it with the given arguments.
 * Be aware this function is REALLY bug prone as it takes a message template with n arguments and passes it
 * directly to `snprintf`
 *
 * @tparam `ResultType` the result type of the function that gives the error
 * @tparam `FormatArgs...` every argument type needed by msg_template
 *
 * @param[in] `result` the result of the function that gives the error
 * @param[in] `msg_template` the error message template
 * @optparam[in] `format_args...` every argument needed by msg_template
 * @return a `std::string` with the formatted message
 */

template<typename ResultType, typename... FormatArgs>
std::string format_error_message(ResultType result, std::string msg_template, FormatArgs... format_args) {
  if (msg_template.find("{{result_as_hex}}") != std::string::npos) {
    std::ostringstream hex_result;
    hex_result << std::hex << std::uppercase << result;
    msg_template
        .replace(msg_template.find("{{result_as_hex}}"), std::string("{{result_as_hex}}").length(), hex_result.str());
  }

  const size_t msg_size = snprintf(nullptr, 0, msg_template.c_str(), std::forward<FormatArgs>(format_args)...);
  if (msg_size <= 0) {
    throw std::runtime_error("Something happened formatting the message template.");
  }

  auto formatted_msg = new char[msg_size + 1];
  snprintf(formatted_msg, msg_size + 1, msg_template.c_str(), std::forward<FormatArgs>(format_args)...);

  return std::string(formatted_msg);
}


/*
 * A structure that represents the result of a function that has no output (or the output is the actual result of that
 * function)
 *
 * @tparam `ResultType` function's result type
 */

template<typename ResultType>
struct function_result {
  ResultType result;

  explicit function_result(ResultType actual_result) {
    result = actual_result;
  }


  /*
   * Given a expected result and an error message (or template), throws a `std::runtime_error` if the result of the
   * function is not the expected one
   *
   * @tparam `FormatArgs...` every argument type needed by error_msg
   *
   * @param[in] `expected_result` the expected function result
   * @param[in] `error_msg` the error message or the error message template to format
   * @optparam[in] `format_args...` every argument needed by error_msg
   * @return the function result
   */

  template<typename... FormatArgs>
  ResultType throw_if_unexpected(ResultType expected_result, const std::string &error_msg,
                                 FormatArgs... format_args) {
    if (result != expected_result) {
      throw std::runtime_error(format_error_message<ResultType>(result, error_msg,
                                                                std::forward<FormatArgs>(format_args)...));
    } else {
      return result;
    }
  }
};


/*
 * A structure that represents the result of a function with a custom output
 *
 * @tparam `ResultType` the function result type
 * @tparam `OutputType` the function output type
 */

template<typename ReturnType, typename OutputType>
struct function_result_with_output {
  ReturnType result;
  OutputType output;

  function_result_with_output(ReturnType actual_result, OutputType actual_output) {
    result = actual_result;
    output = actual_output;
  }


  /*
   * Given a expected result and an error message (or template), throws a `std::runtime_error` if the result of the
   * function is not the expected one
   *
   * @tparam `FormatArgs...` every argument type needed by error_msg
   *
   * @param[in] `expected_result` the expected function result
   * @param[in] `error_msg` the error message or the error message template to format
   * @optparam[in] `format_args...` every argument needed by error_msg
   * @return the custom function output
   */

  template<typename... FormatArgs>
  OutputType throw_if_unexpected(ReturnType expected_result, const std::string &error_msg,
                                 FormatArgs... format_args) {
    if (result != expected_result) {
      throw std::runtime_error(format_error_message<ReturnType>(result, error_msg.data(),
                                                                std::forward<FormatArgs>(format_args)...));
    } else {
      return output;
    }
  }
};