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

#ifndef UNDERAGE_MODEL_NAPI_ERROR_H
#define UNDERAGE_MODEL_NAPI_ERROR_H

#include <map>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
constexpr int32_t PERMISSION_EXCEPTION { 201 };
constexpr int32_t PARAM_EXCEPTION { 401 };
constexpr int32_t DEVICE_EXCEPTION { 801 };
constexpr int32_t SERVICE_EXCEPTION { 33900001 };
constexpr int32_t SUBSCRIBE_EXCEPTION { 33900002 };
constexpr int32_t UNSUBSCRIBE_EXCEPTION { 33900003 };

napi_value CreateUnderageModelNapiError(const napi_env &env, int32_t errorCode, const std::string &errorMsg);
std::optional<std::string> GetUnderageModelErrMsg(int32_t errorCode);
void ThrowUnderageModelErr(const napi_env &env, int32_t errorCode, const std::string &printMsg);
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // UNDERAGE_MODEL_NAPI_ERROR_H