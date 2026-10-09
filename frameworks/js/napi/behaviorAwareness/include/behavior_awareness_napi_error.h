/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef BEHAVIOR_AWARENESS_NAPI_ERROR_H
#define BEHAVIOR_AWARENESS_NAPI_ERROR_H

#include <map>
#include <optional>
#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
enum BehaviorAwarenessNapiErrCode {
    RET_NO_SYSTEM_API = 202,
    RET_PARAM_EXCEPTION = 401,
    RET_SERVICE_EXCEPTION = 32500001,
    RET_UNSUBSCRIBE_EXCEPTION = 32500003,
};

extern std::map<int32_t, std::string> NAPI_ERROR_MESSAGES;

napi_value CreateBehaviorAwarenessNapiError(const napi_env &env, int32_t errCode,
    const std::string &errMessage);
std::optional<std::string> GetBehaviorAwarenessErrMsg(int32_t errCode);
void ThrowBehaviorAwarenessErr(const napi_env &env, int32_t errCode, const std::string &printMsg);
void ThrowBehaviorAwarenessErrByPromise(const napi_env &env, int32_t errCode,
    const std::string &printMsg, napi_value &value);
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BEHAVIOR_AWARENESS_NAPI_ERROR_H
