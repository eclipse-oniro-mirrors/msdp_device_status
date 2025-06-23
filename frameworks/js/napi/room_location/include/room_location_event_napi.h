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

#ifndef ROOM_LOCATION_EVENT_NAPI_H
#define ROOM_LOCATION_EVENT_NAPI_H

#include <bitset>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <set>
#include <mutex>
#include "napi/native_api.h"

namespace OHOS {
namespace Msdp {
class RoomLocationEventListener {
public:
    napi_ref handlerRef = nullptr;
};

class RoomLocationEventNapi {
public:
    RoomLocationEventNapi(napi_env env, napi_value thisVar);
    RoomLocationEventNapi() = default;
    virtual ~RoomLocationEventNapi();
    virtual void UpdateEnv(napi_env env, napi_value jsThis);
    virtual void ClearEnv();
    virtual bool AddCallback(const std::string pkgName, napi_value handler);
    virtual void RemoveCallback(const std::string pkgName);
    virtual void OnRoomEvent(size_t argc, const napi_value *argv);
protected:
    std::mutex mutex_;
    std::atomic<napi_env> env_ {nullptr};
    napi_ref thisVarRef_ {nullptr};
    std::string packageName_;

    std::map<std::string, std::shared_ptr<RoomLocationEventListener>> roomEventMap_;

    bool IsSameValue(const napi_env &env, const napi_value &lhs, const napi_value &rhs);
    bool InsertRef(std::shared_ptr<RoomLocationEventListener> listener, const napi_value &handler);
};
} // namespace Msdp
} // namespace OHOS
#endif // ROOM_LOCATION_EVENT_NAPI_H
