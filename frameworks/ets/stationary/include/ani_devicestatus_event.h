/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANI_DEVICESTATUS_EVENT_H
#define ANI_DEVICESTATUS_EVENT_H

#include <list>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <ani.h>

#include "ohos.stationary.proj.hpp"
#include "ohos.stationary.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
constexpr int32_t PARAM_ERROR { 401 };
constexpr int32_t SERVICE_EXCEPTION { 32500001 };
struct AniDeviceStatusEventListener {
    ani_ref onHandlerRef { nullptr };
};

class AniDeviceStatusEvent {
public:
    AniDeviceStatusEvent() = default;
    virtual ~AniDeviceStatusEvent();

    static std::shared_ptr<AniDeviceStatusEvent> GetInstance();
    virtual bool On(int32_t eventType, ani_ref handler, bool isOnce);
    virtual bool Off(int32_t eventType, ani_ref handler);
    void OnDeviceStatusChangedDone(int32_t type, int32_t value, bool isOnce);
    virtual bool OffOnce(int32_t eventType, ani_ref handler);
    void ClearEventMap();
    bool RemoveAllCallback(int32_t eventType);

protected:
    bool SaveCallbackByEvent(int32_t eventType, ani_ref handler, bool isOnce,
        std::map<int32_t, std::list<std::shared_ptr<AniDeviceStatusEventListener>>> events);
    bool IsNoExistCallback(std::list<std::shared_ptr<AniDeviceStatusEventListener>>,
        ani_ref handler, int32_t eventType);
    void SaveCallback(int32_t eventType, ani_ref handler, bool isOnce);
    void CheckRet(int32_t eventType, size_t argc, int32_t value,
        std::shared_ptr<AniDeviceStatusEventListener> &typeHandler);
    virtual void OnEvent(int32_t eventType, size_t argc, int32_t value, bool isOnce);

    std::vector<Data> data_;
    std::mutex mapMutex_;
    std::map<int32_t, std::list<std::shared_ptr<AniDeviceStatusEventListener>>> events_;
    std::map<int32_t, std::list<std::shared_ptr<AniDeviceStatusEventListener>>> eventOnces_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ANI_DEVICESTATUS_EVENT_H