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

#ifndef ROOM_LOCATION_NAPI_ERROR_H
#define ROOM_LOCATION_NAPI_ERROR_H

#include <map>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Msdp {
constexpr int32_t PERMISSION_EXCEPTION { 201 };
constexpr int32_t DEVICE_EXCEPTION { 801 };
constexpr int32_t SERVICE_EXCEPTION { 33800001 };
constexpr int32_t SUBSCRIBE_EXCEPTION { 33800002 };
constexpr int32_t UNSUBSCRIBE_EXCEPTION { 33800003 };
constexpr int32_t SETINOFS_EXCEPTION { 33800004 };
constexpr int32_t GETRES_EXCEPTION { 33800005 };
const std::map<int32_t, std::string> ERROR_MESSAGES = {
    {PERMISSION_EXCEPTION, "Permission exception"},
    {DEVICE_EXCEPTION, "The device does not support this API."},
    {SERVICE_EXCEPTION, "Service exception."},
    {SUBSCRIBE_EXCEPTION, "Subscription failed."},
    {UNSUBSCRIBE_EXCEPTION, "Unsubscription failed."},
    {SETINOFS_EXCEPTION, "Failed to set device information."},
    {GETRES_EXCEPTION, "Failed to obtain room-level location information."}
};

napi_value CreateRoomLocationNapiError(napi_env env, int32_t errCode, const std::string &errMessage);
std::optional<std::string> GetRoomLocationErrMsg(int32_t errorCode);
void ThrowErr(napi_env env, int32_t errCode, const std::string &printMsg);
} // namespace Msdp
} // namespace OHOS
#endif // ROOM_LOCATION_NAPI_ERROR_H
