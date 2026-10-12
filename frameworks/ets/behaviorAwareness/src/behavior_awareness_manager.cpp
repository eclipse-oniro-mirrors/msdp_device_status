/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "behavior_awareness_manager.h"

#include <vector>

#include "devicestatus_common.h"
#include "devicestatus_define.h"
#include "intention_client.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
BehaviorAwarenessManager::BehaviorAwarenessManager()
{
    InitSaReviveCallback();
}

BehaviorAwarenessManager &BehaviorAwarenessManager::GetInstance()
{
    static BehaviorAwarenessManager instance;
    return instance;
}

void BehaviorAwarenessManager::InitSaReviveCallback()
{
    INTENTION_CLIENT->SetSaReviveCallback([this]() {
        this->ReSubscribe();
    });
}

int32_t BehaviorAwarenessManager::SubscribePerception(const SubscribeOptions &options,
    const sptr<IRemoteBehaviorAwarenessCallback> &callback)
{
    CALL_DEBUG_ENTER;
    FI_HILOGI("SubscribePerception: domain:%{public}d", static_cast<int32_t>(options.domain));
    int32_t ret = INTENTION_CLIENT->SubscribePerception(options, callback);
    if (ret != RET_OK) {
        FI_HILOGE("SubscribePerception failed, ret:%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        std::string key = BuildSubscriptionKey(options);
        auto iter = subscriptions_.find(key);
        if (iter != subscriptions_.end()) {
            iter->second.options = options;
            iter->second.callback = callback;
            FI_HILOGI("SubscribePerception: subscription updated for key:%{public}s", key.c_str());
        } else {
            subscriptions_[key] = CachedSubscription { options, callback };
            FI_HILOGI("SubscribePerception: subscription cached for key:%{public}s", key.c_str());
        }
    }
    return RET_OK;
}

int32_t BehaviorAwarenessManager::UnsubscribePerception(const sptr<IRemoteBehaviorAwarenessCallback> &callback)
{
    CALL_DEBUG_ENTER;
    if (callback == nullptr) {
        // offPerception() no-arg: unsubscribe every cached subscription individually.
        // A null callback cannot traverse the IDL proxy (it rejects null [in] remote
        // objects), so we never pass nullptr through IPC; instead iterate the local
        // cache and call the per-callback unsubscribe for each entry.
        std::vector<sptr<IRemoteBehaviorAwarenessCallback>> snapshot;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            for (auto &item : subscriptions_) {
                if (item.second.callback != nullptr) {
                    snapshot.push_back(item.second.callback);
                }
            }
            subscriptions_.clear();
        }
        int32_t lastErr = RET_OK;
        for (const auto &cb : snapshot) {
            int32_t ret = INTENTION_CLIENT->UnsubscribePerception(cb);
            if (ret != RET_OK) {
                FI_HILOGE("UnsubscribePerception(one) failed, ret:%{public}d", ret);
                lastErr = ret;
            }
        }
        FI_HILOGI("UnsubscribePerception: removed %{public}zu subscription(s)", snapshot.size());
        return lastErr;
    }
    int32_t ret = INTENTION_CLIENT->UnsubscribePerception(callback);
    if (ret != RET_OK) {
        FI_HILOGE("UnsubscribePerception failed, ret:%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto it = subscriptions_.begin(); it != subscriptions_.end(); ++it) {
            if (it->second.callback == callback) {
                subscriptions_.erase(it);
                FI_HILOGI("UnsubscribePerception: matching subscription removed");
                break;
            }
        }
    }
    return RET_OK;
}

int32_t BehaviorAwarenessManager::SubmitFeedback(const FeedbackData &feedback)
{
    CALL_DEBUG_ENTER;
    FI_HILOGI("SubmitFeedback: eventId:%{public}s", feedback.perceptionEventId.c_str());
    return INTENTION_CLIENT->SubmitFeedback(feedback);
}

void BehaviorAwarenessManager::ReSubscribe()
{
    CALL_DEBUG_ENTER;
    std::vector<CachedSubscription> snapshot;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (subscriptions_.empty()) {
            FI_HILOGI("ReSubscribe: no subscription to restore");
            return;
        }
        for (const auto &item : subscriptions_) {
            snapshot.push_back(item.second);
        }
    }
    int32_t restored = 0;
    for (const auto &entry : snapshot) {
        if (entry.callback == nullptr) {
            continue;
        }
        int32_t ret = INTENTION_CLIENT->SubscribePerception(entry.options, entry.callback);
        if (ret != RET_OK) {
            FI_HILOGE("ReSubscribe failed for one subscription, ret:%{public}d", ret);
            continue;
        }
        ++restored;
    }
    FI_HILOGI("ReSubscribe: restored %{public}d subscription(s)", restored);
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
