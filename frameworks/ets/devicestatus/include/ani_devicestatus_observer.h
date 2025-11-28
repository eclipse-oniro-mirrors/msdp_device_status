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
#ifndef OHOS_ANI_DEVICESTATUS_OBSERVER_UTILS_H
#define OHOS_ANI_DEVICESTATUS_OBSERVER_UTILS_H

#include <mutex>
#include <optional>

#include "ohos.multimodalAwareness.deviceStatus.proj.hpp"
#include "ohos.multimodalAwareness.deviceStatus.impl.hpp"
#include "devicestatus_callback_stub.h"
#include "devicestatus_define.h"
#include "iremote_dev_sta_callback.h"
#include "taihe/runtime.hpp"
#include "event_handler.h"
#include "event_runner.h"

using JsOnSteadyStandingCallbackType =
    ::taihe::callback<void(::ohos::multimodalAwareness::deviceStatus::SteadyStandingStatus)>;

namespace ani_observerutils {
using namespace OHOS;
using namespace OHOS::Msdp;

struct StandCallbackInfo {
    JsOnSteadyStandingCallbackType taiheCallback_;
    DeviceStatus::OnChangedValue state_;
};

class AniDeviceStatusCallback : public DeviceStatus::DeviceStatusCallbackStub {
public:
    explicit AniDeviceStatusCallback() = default;
    virtual ~AniDeviceStatusCallback() {}

    bool IsTaiheStandCallbackExist(JsOnSteadyStandingCallbackType const& taiheCallback);
    bool AddTaiheStandCallback(JsOnSteadyStandingCallbackType &taiheCallback);
    bool RemoveTaiheStandCallback(std::optional<JsOnSteadyStandingCallbackType> optTaiheCallback, bool &isEmpty);
    bool SendEventToMainThread(const std::function<void()> func);
    void OnDeviceStatusChanged(const DeviceStatus::Data &devicestatusData) override;
    void OnDeviceStatusChangedInMainThread(const DeviceStatus::Data &devicestatusData);

private:
    static std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_;
    std::recursive_mutex callbackMutex_;
    std::vector<StandCallbackInfo> taiheStandcallbackList_;
};

}
#endif