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

#ifndef DISTANCE_MEASUREMENT_NAPI_ERROR_H
#define DISTANCE_MEASUREMENT_NAPI_ERROR_H

#include <map>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Msdp {
constexpr int32_t PERMISSION_EXCEPTION { 201 };
constexpr int32_t DEVICE_EXCEPTION { 801 };
constexpr int32_t SERVICE_EXCEPTION { 35100001 };
constexpr int32_t SUBSCRIBE_EXCEPTION { 35100002 };
constexpr int32_t UNSUBSCRIBE_EXCEPTION { 35100003 };
constexpr int32_t PARAMETER_EXCEPTION { 35100004 };

napi_value CreateDistanceMeasurementNapiError(napi_env env, int32_t errCode, const std::string &errMessage);
std::optional<std::string> GetDistanceMeasurementNapiErrMsg(int32_t errorCode);
void ThrowErr(napi_env env, int32_t errCode, const std::string &printMsg);
} // namespace Msdp
} // namespace OHOS
#endif //  DISTANCE_MEASUREMENT_NAPI_ERROR_H
