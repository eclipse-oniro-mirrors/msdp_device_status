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
#include <map>

#include "taihe/runtime.hpp"
#include "ani_error_utils.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "AniErrorUtils"

namespace OHOS {
namespace Msdp {
namespace DeviceStatusV1 {
const std::map<int32_t, std::string> ERROR_MESSAGES = {
    {NO_SYSTEM_API, "Permission check failed. A non-system application uses the system API."},
    {PARAM_EXCEPTION, "Params check failed."},
    {DEVICE_EXCEPTION, "The device does not support this API."},
    {SERVICE_EXCEPTION, "Service exception."},
    {SUBSCRIBE_EXCEPTION, "Subscription failed."},
    {UNSUBSCRIBE_EXCEPTION, "Unsubscription failed."}
};
}}}

namespace ani_errorutils {
using namespace OHOS::Msdp::DeviceStatusV1;

void ThrowError(int32_t code, const char* message)
{
    FI_HILOGE("ThrowError, code = %{public}d", code);
    if (message == nullptr) {
        return;
    }
    std::string errMsg(message);
    taihe::set_business_error(code, errMsg);
}

std::optional<std::string> GetDeviceStatusErrMsg(int32_t errCode)
{
    auto iter = ERROR_MESSAGES.find(errCode);
    if (iter != ERROR_MESSAGES.end()) {
        return iter->second;
    }
    FI_HILOGE("Error messages not found");
    return std::nullopt;
}

void ThrowDeviceStatusErr(int32_t errCode)
{
    std::optional<std::string> msg = GetDeviceStatusErrMsg(errCode);
    if (!msg) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        return;
    }
    ThrowError(errCode, msg.value().c_str());
}

} //ani_errorutils