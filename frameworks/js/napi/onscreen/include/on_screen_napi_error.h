/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
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

#ifndef ONSCREEN_NAPI_ERROR_H
#define ONSCREEN_NAPI_ERROR_H

#include <map>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
constexpr int32_t PERMISSION_EXCEPTION { 201 };
constexpr int32_t NO_SYSTEM_API { 202 };
constexpr int32_t PARAM_EXCEPTION { 401 };
constexpr int32_t DEVICE_EXCEPTION { 801 };
constexpr int32_t SERVICE_EXCEPTION { 34000001 };
constexpr int32_t NOT_IN_WHITELIST_EXCEPTION { 34000002 };
constexpr int32_t INVALID_WINDOW_ID_EXCEPTION { 34000003 };
constexpr int32_t EVENT_ID_NOT_FIND_EXCEPTION { 34000004 };

extern std::map<int32_t, std::string> ERROR_MESSAGES;
napi_value CreateOnScreenNapiError(const napi_env &env, int32_t errCode, const std::string &errMessage);
std::optional<std::string> GetOnScreenErrMsg(int32_t errCode);
void ThrowOnScreenErr(const napi_env &env, int32_t errCode, const std::string &printMsg);
void ThrowOnScreenErrByPromise(const napi_env &env, int32_t errCode, const std::string &printMsg,
    napi_value &value);
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ONSCREEN_NAPI_ERROR_H