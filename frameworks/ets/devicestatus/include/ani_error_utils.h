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
#ifndef OHOS_ANI_ERROR_UTILS_H
#define OHOS_ANI_ERROR_UTILS_H

namespace ani_errorutils {
void ThrowError(int32_t code, const char* message);
void ThrowDeviceStatusErr(int32_t errCode);
}

namespace OHOS {
namespace Msdp {
namespace DeviceStatusV1 {
constexpr int32_t NO_SYSTEM_API { 202 };
constexpr int32_t PARAM_EXCEPTION { 401 };
constexpr int32_t DEVICE_EXCEPTION { 801 };
constexpr int32_t SERVICE_EXCEPTION { 32500001 };
constexpr int32_t SUBSCRIBE_EXCEPTION { 32500002 };
constexpr int32_t UNSUBSCRIBE_EXCEPTION { 32500003 };

}}}
#endif