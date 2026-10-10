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

#include "ohos.multimodalAwareness.behaviorAwareness.impl.h"
#include <accesstoken_kit.h>
#include <ipc_skeleton.h>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
#include "devicestatus_define.h"
#include "behavior_awareness_callback_taihe.h"
#include "behavior_awareness_manager.h"

namespace ANI::MultimodalAwareness {
using namespace OHOS;
using namespace OHOS::Msdp::DeviceStatus;
using namespace taihe;
using namespace ohos::multimodalAwareness::behaviorAwareness;
using namespace OHOS::Msdp::DeviceStatus::BehaviorAwareness;

std::mutex g_mtx;
std::map<std::string, sptr<BehaviorAwarenessCallbackTaihe>> g_callbacks;

bool CheckCallerIsSystemApp()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        return true;
    }
    auto fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return Security::AccessToken::AccessTokenKit::IsSystemAppByFullTokenID(fullTokenId);
}

enum BehaviorAwarenessErrCode {
    RET_NO_SYSTEM_API = 202,
    RET_PARAM_EXCEPTION = 401,
    RET_SERVICE_EXCEPTION = 32500001,
    RET_UNSUBSCRIBE_EXCEPTION = 32500003,
};

std::map<int32_t, std::string> ERROR_MESSAGES = {
    { RET_NO_SYSTEM_API, "Permission verification failed. A non-system application uses the system API." },
    { RET_PARAM_EXCEPTION, "Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; "
        "2. Incorrect parameter types; 3. Parameter verification failed." },
    { RET_SERVICE_EXCEPTION, "Service exception." },
    { RET_UNSUBSCRIBE_EXCEPTION, "Unsubscription failed." },
};

std::string GetErrMsg(int32_t errCode)
{
    auto iter = ERROR_MESSAGES.find(errCode);
    if (iter != ERROR_MESSAGES.end()) {
        return iter->second;
    }
    FI_HILOGE("Error messages not found");
    return "";
}

void ThrowBehaviorAwarenessErr(int32_t errCode, const std::string &printMsg)
{
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", printMsg.c_str(), errCode);
    auto msg = GetErrMsg(errCode);
    if (msg.empty()) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        taihe::set_business_error(RET_SERVICE_EXCEPTION, "Service exception.");
        return;
    }
    taihe::set_business_error(errCode, msg.c_str());
}

static int32_t ConvertPatternType(const std::string &ptStr)
{
    namespace BA = OHOS::Msdp::DeviceStatus::BehaviorAwareness;
    if (ptStr == "timePattern") {
        return static_cast<int32_t>(BA::PatternType::TIME_PATTERN);
    }
    if (ptStr == "locationPattern") {
        return static_cast<int32_t>(BA::PatternType::LOCATION_PATTERN);
    }
    if (ptStr == "eventPattern") {
        return static_cast<int32_t>(BA::PatternType::EVENT_PATTERN);
    }
    return -1;
}

void OnPerception(ohos::multimodalAwareness::behaviorAwareness::SubscribeInfo info,
    callback_view<void(ohos::multimodalAwareness::behaviorAwareness::PerceptionEvent const &)> callback)
{
    FI_HILOGI("OnPerception: onPerception entry");
    OHOS::Msdp::DeviceStatus::BehaviorAwareness::SubscribeOptions nativeOptions;
    std::string domainStr(static_cast<const char*>(info.domain));
    if (domainStr == "habitAwareness") {
        nativeOptions.domain = OHOS::Msdp::DeviceStatus::BehaviorAwareness::PerceptionDomain::HABIT_AWARENESS;
    } else {
        ThrowBehaviorAwarenessErr(RET_PARAM_EXCEPTION, "invalid domain");
        return;
    }
    if (info.patternTypes.has_value()) {
        for (auto pt : info.patternTypes.value()) {
            std::string ptStr(static_cast<const char*>(pt));
            int32_t ptVal = ConvertPatternType(ptStr);
            if (ptVal >= 0) {
                nativeOptions.patternTypes.push_back(ptVal);
            }
        }
    }
    auto callbackPtr = std::make_shared<taihe::callback<
        void(ohos::multimodalAwareness::behaviorAwareness::PerceptionEvent const &)>>(callback);
    auto newCallback = new (std::nothrow) BehaviorAwarenessCallbackTaihe(callbackPtr);
    if (newCallback == nullptr) {
        ThrowBehaviorAwarenessErr(RET_SERVICE_EXCEPTION, "failed to create callback");
        return;
    }
    int32_t errNum = BehaviorAwarenessManager::GetInstance().SubscribePerception(nativeOptions, newCallback);
    if (errNum != RET_OK) {
        ThrowBehaviorAwarenessErr(errNum, "subscribe failed");
        return;
    }
    std::string key = OHOS::Msdp::DeviceStatus::BehaviorAwareness::BuildSubscriptionKey(nativeOptions);
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_callbacks[key] = newCallback;
    }
    FI_HILOGI("OnPerception: success, key:%{public}s", key.c_str());
}

void OffPerception(
    optional_view<callback<void(ohos::multimodalAwareness::behaviorAwareness::PerceptionEvent const &)>> callback)
{
    FI_HILOGI("OffPerception: offPerception entry");
    if (!CheckCallerIsSystemApp()) {
        FI_HILOGE("OffPerception: non-system app");
        ThrowBehaviorAwarenessErr(RET_NO_SYSTEM_API, "non-system app");
        return;
    }
    if (!callback.has_value()) {
        int32_t errNum = BehaviorAwarenessManager::GetInstance().UnsubscribePerception(nullptr);
        if (errNum != RET_OK) {
            ThrowBehaviorAwarenessErr(errNum, "unsubscribe failed");
            return;
        }
        std::lock_guard<std::mutex> lk(g_mtx);
        g_callbacks.clear();
        FI_HILOGI("OffPerception: all subscriptions removed");
        return;
    }
    auto userCb = callback.value();
    std::vector<std::pair<std::string, sptr<BehaviorAwarenessCallbackTaihe>>> matches;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        for (auto &item : g_callbacks) {
            if (item.second != nullptr && item.second->Matches(userCb)) {
                matches.emplace_back(item.first, item.second);
            }
        }
    }
    if (matches.empty()) {
        ThrowBehaviorAwarenessErr(RET_UNSUBSCRIBE_EXCEPTION, "no active subscription");
        return;
    }
    int32_t lastErr = RET_OK;
    for (auto &m : matches) {
        int32_t err = BehaviorAwarenessManager::GetInstance().UnsubscribePerception(m.second);
        if (err != RET_OK) {
            lastErr = err;
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        for (auto &m : matches) {
            g_callbacks.erase(m.first);
        }
    }
    if (lastErr != RET_OK) {
        ThrowBehaviorAwarenessErr(lastErr, "unsubscribe failed");
        return;
    }
    FI_HILOGI("OffPerception: removed %{public}zu subscription(s)", matches.size());
}

void SubmitFeedback(ohos::multimodalAwareness::behaviorAwareness::FeedbackData feedback)
{
    FI_HILOGI("SubmitFeedback: submitFeedback entry");
    OHOS::Msdp::DeviceStatus::BehaviorAwareness::FeedbackData nativeFeedback;
    nativeFeedback.perceptionEventId = std::string(feedback.perceptionEventId.c_str());
    nativeFeedback.feedbackType = static_cast<OHOS::Msdp::DeviceStatus::BehaviorAwareness::FeedbackType>(
        static_cast<int32_t>(feedback.feedbackType));
    nativeFeedback.feedbackTime = feedback.feedbackTime;
    int32_t errNum = BehaviorAwarenessManager::GetInstance().SubmitFeedback(nativeFeedback);
    if (errNum != RET_OK) {
        ThrowBehaviorAwarenessErr(errNum, "submitFeedback failed");
    }
}
} // namespace ANI::MultimodalAwareness

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_OnPerception(ANI::MultimodalAwareness::OnPerception);
TH_EXPORT_CPP_API_OffPerception(ANI::MultimodalAwareness::OffPerception);
TH_EXPORT_CPP_API_SubmitFeedback(ANI::MultimodalAwareness::SubmitFeedback);
// NOLINTEND
