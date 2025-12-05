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
#include "ani_devicestatus_observer.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "AniObserverUtils"

namespace ani_observerutils {

std::shared_ptr<OHOS::AppExecFwk::EventHandler> AniDeviceStatusCallback::mainHandler_;

bool AniDeviceStatusCallback::IsTaiheStandCallbackExist(JsOnSteadyStandingCallbackType const& taiheCallback)
{
    std::lock_guard<std::recursive_mutex> guard(callbackMutex_);
    for (auto &item : taiheStandcallbackList_) {
        if (item.taiheCallback_ == taiheCallback) {
            FI_HILOGI("IsTaiheStandCallbackExist return true");
            return true;
        }
    }
    return false;
}

bool AniDeviceStatusCallback::AddTaiheStandCallback(JsOnSteadyStandingCallbackType &taiheCallback)
{
    FI_HILOGI("AddTaiheStandCallback");
    std::lock_guard<std::recursive_mutex> guard(callbackMutex_);
    if (IsTaiheStandCallbackExist(taiheCallback)) {
        return false;
    }
    StandCallbackInfo item = { taiheCallback, DeviceStatus::OnChangedValue::VALUE_INVALID };
    taiheStandcallbackList_.emplace_back(item);
    return true;
}

bool AniDeviceStatusCallback::RemoveTaiheStandCallback(std::optional<JsOnSteadyStandingCallbackType> optTaiheCallback,
    bool &isEmpty)
{
    FI_HILOGI("RemoveTaiheStandCallback");
    std::lock_guard<std::recursive_mutex> guard(callbackMutex_);
    size_t oldCount = taiheStandcallbackList_.size();
    if (!optTaiheCallback.has_value()) {
        taiheStandcallbackList_.clear();
        isEmpty = true;
        if (oldCount > 0) {
            return true;
        }
        return false;
    }
    auto paramCallback = optTaiheCallback.value();
    for (auto iter = taiheStandcallbackList_.begin(); iter != taiheStandcallbackList_.end();) {
        if (paramCallback == iter->taiheCallback_) {
            iter = taiheStandcallbackList_.erase(iter);
            FI_HILOGI("RemoveTaiheStandCallback, remove item");
        } else {
            ++iter;
        }
    }
    if (0 == taiheStandcallbackList_.size()) {
        isEmpty = true;
    }
    if (oldCount != taiheStandcallbackList_.size()) {
        return true;
    }
    return false;
}

bool AniDeviceStatusCallback::SendEventToMainThread(const std::function<void()> func)
{
    if (func == nullptr) {
        return false;
    }
    if (!mainHandler_) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        if (!runner) {
            FI_HILOGI("GetMainEventRunner failed");
            return false;
        }
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    mainHandler_->PostTask(func, "", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    return true;
}

void AniDeviceStatusCallback::OnDeviceStatusChanged(const DeviceStatus::Data &devicestatusData)
{
    FI_HILOGI("OnDeviceStatusChanged &devicestatusData %{public}p", &devicestatusData);
    wptr<AniDeviceStatusCallback> weakthis = this;
    SendEventToMainThread([devicestatusData, weakthis] {
        auto sptrthis = weakthis.promote();
        if (sptrthis != nullptr) {
            sptrthis->OnDeviceStatusChangedInMainThread(devicestatusData);
        }
    });
}

void AniDeviceStatusCallback::OnDeviceStatusChangedInMainThread(const DeviceStatus::Data &devicestatusData)
{
    using namespace ohos::multimodalAwareness;
    FI_HILOGI("OnDeviceStatusChangedInMainThread %{public}d", devicestatusData.value);
    static auto sTaiheEnter =
        deviceStatus::SteadyStandingStatus(deviceStatus::SteadyStandingStatus::key_t::STATUS_ENTER);
    static auto sTaiheExit =
        deviceStatus::SteadyStandingStatus(deviceStatus::SteadyStandingStatus::key_t::STATUS_EXIT);

    std::vector<StandCallbackInfo> tmpCallbackList;
    {
        std::lock_guard<std::recursive_mutex> guard(callbackMutex_);
        for (auto& item : taiheStandcallbackList_) {
            if (devicestatusData.value == item.state_) {
                continue;
            }
            item.state_ = devicestatusData.value;
            if (item.state_ == DeviceStatus::OnChangedValue::VALUE_ENTER ||
                item.state_ == DeviceStatus::OnChangedValue::VALUE_EXIT) {
                StandCallbackInfo cacheItem = {item.taiheCallback_, item.state_};
                tmpCallbackList.emplace_back(cacheItem);
            }
        }
    }
    for (auto& cacheItem : tmpCallbackList) {
        if (cacheItem.state_ == DeviceStatus::OnChangedValue::VALUE_ENTER) {
            cacheItem.taiheCallback_(sTaiheEnter);
        } else {
            cacheItem.taiheCallback_(sTaiheExit);
        }
    };
    tmpCallbackList.clear();
}

}