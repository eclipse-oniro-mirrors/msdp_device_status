/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef DEVICESTATUS_EVENT_H
#define DEVICESTATUS_EVENT_H

#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "napi/native_api.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
struct BoomerangEventListener {
    napi_ref onHandlerRef { nullptr };
};

class BoomerangEvent {
public:
    BoomerangEvent(napi_env env);
    BoomerangEvent() = default;
    virtual ~BoomerangEvent();

    virtual bool On(int32_t eventType, napi_value handler, bool isOnce);
    virtual bool Off(int32_t eventType, napi_value handler);

protected:
    virtual bool OffOnce(int32_t eventType, napi_value handler);
    virtual void OnEvent(int32_t eventType, size_t argc, int32_t value, bool isOnce);
    void CheckRet(int32_t eventType, size_t argc, int32_t value,
        std::shared_ptr<BoomerangEventListener> &typeHandler);
    void SendRet(int32_t eventType, int32_t value, napi_value &result);
    void ClearEventMap();
    bool RemoveAllCallback(int32_t eventType);
    bool SaveCallbackByEvent(int32_t eventType, napi_value handler, bool isOnce,
        std::map<int32_t, std::list<std::shared_ptr<BoomerangEventListener>>> events);
    bool IsNoExistCallback(std::list<std::shared_ptr<BoomerangEventListener>>,
        napi_value handler, int32_t eventType);
    void SaveCallback(int32_t eventType, napi_ref onHandlerRef, bool isOnce);

    napi_env env_ { nullptr };
    napi_ref thisVarRef_ { nullptr };
    std::mutex mutex_;
    std::map<int32_t, std::list<std::shared_ptr<BoomerangEventListener>>> events_;
    std::map<int32_t, std::list<std::shared_ptr<BoomerangEventListener>>> eventOnces_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_EVENT_H
