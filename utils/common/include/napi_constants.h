 /*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License") };
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NAPI_CONSTANTS_H
#define NAPI_CONSTANTS_H

#include <cstddef>
#include <string_view>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
inline constexpr std::string_view COOPERATE_NAME { "cooperate" };
inline constexpr std::string_view COOPERATE_MESSAGE_NAME { "cooperateMessage" };
inline constexpr std::string_view COOPERATE_MOUSE_NAME { "cooperateMouse" };
inline constexpr std::string_view DRAG_TYPE { "drag" };
inline const std::string DEV_INPUT_PATH { "/dev/input/" };
inline constexpr std::string_view CALL_FUNCTION { "napi_call_function" };
inline constexpr std::string_view CREATE_OBJECT { "napi_create_object" };
inline constexpr std::string_view CREATE_INT32 { "napi_create_int32" };
inline constexpr std::string_view CREATE_REFERENCE { "napi_create_reference" };
inline constexpr std::string_view DEFINE_PROPERTIES { "napi_define_properties" };
inline constexpr std::string_view DEFINE_CLASS { "napi_define_class" };
inline constexpr std::string_view GET_CB_INFO { "napi_get_cb_info" };
inline constexpr std::string_view GET_GLOBAL { "napi_get_global" };
inline constexpr std::string_view GET_REFERENCE_VALUE { "napi_get_reference_value" };
inline constexpr std::string_view GET_UV_EVENT_LOOP { "napi_get_uv_event_loop" };
inline constexpr std::string_view GET_NAMED_PROPERTY { "napi_get_named_property" };
inline constexpr std::string_view HAS_NAMED_PROPERTY { "napi_has_named_property" };
inline constexpr std::string_view NEW_INSTANCE { "napi_new_instance" };
inline constexpr std::string_view SET_NAMED_PROPERTY { "napi_set_named_property" };
inline constexpr std::string_view STRICT_EQUALS { "napi_strict_equals" };
inline constexpr std::string_view TYPEOF { "napi_typeof" };
inline constexpr std::string_view UNWRAP { "napi_unwrap" };
inline constexpr std::string_view WRAP { "napi_wrap" };
inline constexpr std::string_view CREATE_STRING_UTF8 { "napi_create_string_utf8" };
inline constexpr std::string_view CREATE_ARRAY { "napi_create_array" };
inline constexpr std::string_view CREATE_INT64 { "napi_create_int64" };
inline constexpr std::string_view SET_ELEMENT { "napi_set_element" };
inline constexpr std::string_view CREAT_ASYNC_WORK { "napi_create_async_work" };
inline constexpr std::string_view QUEUE_ASYNC_WORK { "napi_queue_async_work_with_qos" };
inline constexpr int32_t ZERO_PARAM { 0 };
inline constexpr int32_t ONE_PARAM { 1 };
inline constexpr int32_t TWO_PARAM { 2 };
inline constexpr int32_t THREE_PARAM { 3 };
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // NAPI_CONSTANTS_H