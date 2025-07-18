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
// TODO 这个需要加吗，因为能获取权限的一定是system hap
constexpr int32_t NO_SYSTEM_API { 202 };
constexpr int32_t PARAM_EXCEPTION { 401 };
constexpr int32_t DEVICE_EXCEPTION { 801 };
// TODO 根据syscap id修改错误编码
constexpr int32_t SERVICE_EXCEPTION { 32500001 };
const std::map<int32_t, std::string> ERROR_MESSAGES = {
    {PERMISSION_EXCEPTION, "Permission check failed."},
    {NO_SYSTEM_API, "Permission check failed. A non-system application uses the system API."},
    {PARAM_EXCEPTION, "Params check failed."},
    {DEVICE_EXCEPTION, "The device does not support this API."},
    {SERVICE_EXCEPTION, "Service exception."}
};
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