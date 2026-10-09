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
        lastOptions_ = options;
        lastCallback_ = callback;
        hasSubscription_ = true;
    }
    FI_HILOGI("SubscribePerception: subscription created");
    return RET_OK;
}

int32_t BehaviorAwarenessManager::UnsubscribePerception(const sptr<IRemoteBehaviorAwarenessCallback> &callback)
{
    CALL_DEBUG_ENTER;
    FI_HILOGI("UnsubscribePerception");
    int32_t ret = INTENTION_CLIENT->UnsubscribePerception(callback);
    if (ret != RET_OK) {
        FI_HILOGE("UnsubscribePerception failed, ret:%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        lastCallback_ = nullptr;
        hasSubscription_ = false;
    }
    FI_HILOGI("UnsubscribePerception: subscription removed");
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
    SubscribeOptions options;
    sptr<IRemoteBehaviorAwarenessCallback> callback;
    bool hasSub = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        hasSub = hasSubscription_;
        callback = lastCallback_;
        options = lastOptions_;
    }
    if (!hasSub || callback == nullptr) {
        FI_HILOGI("ReSubscribe: no subscription to restore");
        return;
    }
    int32_t ret = INTENTION_CLIENT->SubscribePerception(options, callback);
    if (ret != RET_OK) {
        FI_HILOGE("ReSubscribe failed, ret:%{public}d", ret);
        return;
    }
    FI_HILOGI("ReSubscribe: subscription restored");
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
