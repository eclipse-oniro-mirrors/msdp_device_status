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

#include "behavior_awareness_server.h"

#include <charconv>
#include <functional>
#include <sstream>
#include <string>

#include "accesstoken_kit.h"
#include "devicestatus_common.h"
#include "devicestatus_define.h"
#include "feedback_store.h"
#include "hap_token_info.h"
#include "parameters.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
using DeathCallback = std::function<void(const wptr<IRemoteObject> &)>;

class BehaviorAwarenessDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit BehaviorAwarenessDeathRecipient(DeathCallback callback) : callback_(callback) {}
    ~BehaviorAwarenessDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        if (callback_) {
            callback_(remote);
        }
    }
private:
    DeathCallback callback_;
};

namespace {

std::string GetCallerBundleName(const CallingContext &context)
{
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        Security::AccessToken::NativeTokenInfo tokenInfo;
        if (Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(context.tokenId, tokenInfo) != RET_OK) {
            FI_HILOGE("GetNativeTokenInfo failed, tokenId:%{public}u", context.tokenId);
            return "";
        }
        return tokenInfo.processName;
    }
    Security::AccessToken::HapTokenInfo hapInfo;
    int32_t ret = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(context.tokenId, hapInfo);
    if (ret != RET_OK) {
        FI_HILOGE("GetHapTokenInfo failed, ret:%{public}d, tokenId:%{public}u", ret, context.tokenId);
        return "";
    }
    return hapInfo.bundleName;
}

bool IsCallerSystemApp(const CallingContext &context)
{
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        return true;
    }
    return Security::AccessToken::AccessTokenKit::IsSystemAppByFullTokenID(context.fullTokenId);
}
} // namespace

const std::vector<std::string> BehaviorAwarenessServer::SUPPORT_DEVICE_TYPE_ = { "phone" };

bool BehaviorAwarenessServer::CheckDeviceType()
{
    std::string deviceType = OHOS::system::GetParameter(DEVICE_TYPE_PARA_NAME, "");
    return std::find(SUPPORT_DEVICE_TYPE_.begin(), SUPPORT_DEVICE_TYPE_.end(), deviceType)
        != SUPPORT_DEVICE_TYPE_.end();
}

std::string BehaviorAwarenessServer::BuildSubscriptionKey(const std::string &bundleName,
    const SubscribeOptions &options)
{
    std::ostringstream oss;
    oss << bundleName << ":" << static_cast<int32_t>(options.domain);
    for (int32_t pt : options.patternTypes) {
        oss << ":" << pt;
    }
    return oss.str();
}

int32_t BehaviorAwarenessServer::SubscribePerception(const CallingContext &context,
    const SubscribeOptions &options, const sptr<IRemoteBehaviorAwarenessCallback> &callback)
{
    CALL_DEBUG_ENTER;
    if (!IsCallerSystemApp(context)) {
        FI_HILOGE("SubscribePerception: non-system app");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (!CheckDeviceType()) {
        FI_HILOGE("SubscribePerception: device not support");
        return DEVICE_NOT_SUPPORT;
    }
    std::string bundleName = GetCallerBundleName(context);
    if (bundleName.empty()) {
        FI_HILOGE("SubscribePerception: failed to get caller bundleName");
        return SERVICE_EXCEPTION;
    }
    std::string key = BuildSubscriptionKey(bundleName, options);
    FI_HILOGI("SubscribePerception: bundleName:%{public}s, domain:%{public}d, key:%{public}s",
        bundleName.c_str(), static_cast<int32_t>(options.domain), key.c_str());

    std::lock_guard<std::mutex> lock(mtx_);
    auto iter = subscriptions_.find(key);
    if (iter != subscriptions_.end()) {
        // Same key exists — overwrite callback (not error)
        if (deathRecipient_ != nullptr && iter->second.callback != nullptr) {
            iter->second.callback->AsObject()->RemoveDeathRecipient(deathRecipient_);
        }
        iter->second.callback = callback;
        iter->second.domain = options.domain;
        iter->second.patternTypes = options.patternTypes;
        if (deathRecipient_ != nullptr && callback != nullptr) {
            callback->AsObject()->AddDeathRecipient(deathRecipient_);
        }
        FI_HILOGI("SubscribePerception: subscription updated (overwritten) for key:%{public}s", key.c_str());
        return RET_OK;
    }

    // New key — insert new subscription
    InitDeathRecipient();
    SaveSubscription(key, options, callback);
    if (deathRecipient_ != nullptr && callback != nullptr) {
        callback->AsObject()->AddDeathRecipient(deathRecipient_);
    }
    FI_HILOGI("SubscribePerception: subscription created for key:%{public}s", key.c_str());
    return RET_OK;
}

int32_t BehaviorAwarenessServer::RemoveAllSubscriptions(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(mtx_);
    int32_t removed = 0;
    for (auto it = subscriptions_.begin(); it != subscriptions_.end();) {
        if (it->first.find(bundleName + ":") != 0) {
            ++it;
            continue;
        }
        if (deathRecipient_ != nullptr && it->second.callback != nullptr) {
            it->second.callback->AsObject()->RemoveDeathRecipient(deathRecipient_);
        }
        it = subscriptions_.erase(it);
        ++removed;
    }
    return removed;
}

int32_t BehaviorAwarenessServer::RemoveMatchingSubscription(
    const std::string &bundleName, const sptr<IRemoteBehaviorAwarenessCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = subscriptions_.begin(); it != subscriptions_.end(); ++it) {
        if (it->first.find(bundleName + ":") != 0) {
            continue;
        }
        if (it->second.callback == nullptr) {
            continue;
        }
        if (it->second.callback->AsObject() != callback->AsObject()) {
            continue;
        }
        if (deathRecipient_ != nullptr) {
            callback->AsObject()->RemoveDeathRecipient(deathRecipient_);
        }
        RemoveSubscription(it->first);
        FI_HILOGI("UnsubscribePerception: removed for key:%{public}s", it->first.c_str());
        return RET_OK;
    }
    return UNSUBSCRIBE_EXCEPTION;
}

int32_t BehaviorAwarenessServer::UnsubscribePerception(const CallingContext &context,
    const sptr<IRemoteBehaviorAwarenessCallback> &callback)
{
    CALL_DEBUG_ENTER;
    if (!IsCallerSystemApp(context)) {
        FI_HILOGE("UnsubscribePerception: non-system app");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (!CheckDeviceType()) {
        FI_HILOGE("UnsubscribePerception: device not support");
        return DEVICE_NOT_SUPPORT;
    }
    std::string bundleName = GetCallerBundleName(context);
    if (bundleName.empty()) {
        FI_HILOGE("UnsubscribePerception: failed to get caller bundleName");
        return SERVICE_EXCEPTION;
    }
    FI_HILOGI("UnsubscribePerception: bundleName:%{public}s", bundleName.c_str());
    if (callback == nullptr) {
        int32_t removed = RemoveAllSubscriptions(bundleName);
        if (removed == 0) {
            FI_HILOGE("UnsubscribePerception: no subscription for %{public}s", bundleName.c_str());
            return UNSUBSCRIBE_EXCEPTION;
        }
        FI_HILOGI("UnsubscribePerception: removed %{public}d for %{public}s", removed, bundleName.c_str());
        return RET_OK;
    }
    int32_t ret = RemoveMatchingSubscription(bundleName, callback);
    if (ret == UNSUBSCRIBE_EXCEPTION) {
        FI_HILOGE("UnsubscribePerception: not found or mismatch for %{public}s", bundleName.c_str());
    }
    return ret;
}

int32_t BehaviorAwarenessServer::ValidateFeedback(const FeedbackData &feedback)
{
    if (feedback.perceptionEventId.empty()) {
        FI_HILOGE("ValidateFeedback: perceptionEventId is empty");
        return PARAM_EXCEPTION;
    }
    size_t pos = feedback.perceptionEventId.find('_');
    if (pos == std::string::npos || pos + 1 >= feedback.perceptionEventId.length()) {
        FI_HILOGE("ValidateFeedback: perceptionEventId format invalid, missing '_' separator or empty suffix, "
            "value:%{public}s", feedback.perceptionEventId.c_str());
        return PARAM_EXCEPTION;
    }
    std::string prefix = feedback.perceptionEventId.substr(0, pos);
    if (prefix != PERCEPTION_DOMAIN_HABIT_AWARENESS_STR) {
        FI_HILOGE("ValidateFeedback: perceptionEventId prefix is not a valid PerceptionDomain enum value, "
            "prefix:%{public}s, value:%{public}s", prefix.c_str(), feedback.perceptionEventId.c_str());
        return PARAM_EXCEPTION;
    }
    std::string suffix = feedback.perceptionEventId.substr(pos + 1);
    int64_t parsedValue = 0;
    auto [ptr, ec] = std::from_chars(suffix.data(), suffix.data() + suffix.size(), parsedValue);
    if (ec != std::errc() || ptr != suffix.data() + suffix.size()) {
        FI_HILOGE("ValidateFeedback: perceptionEventId id suffix cannot parse to valid int, value:%{public}s, "
            "suffix:%{public}s", feedback.perceptionEventId.c_str(), suffix.c_str());
        return PARAM_EXCEPTION;
    }
    if (parsedValue <= 0) {
        FI_HILOGE("ValidateFeedback: perceptionEventId id is non-positive, value:%{public}s, id:%{public}" PRId64,
            feedback.perceptionEventId.c_str(), parsedValue);
        return PARAM_EXCEPTION;
    }
    int32_t ft = static_cast<int32_t>(feedback.feedbackType);
    if (ft < static_cast<int32_t>(FeedbackType::ACCEPT) ||
        ft > static_cast<int32_t>(FeedbackType::NOT_PUSHED)) {
        FI_HILOGE("ValidateFeedback: feedbackType out of range, value:%{public}d", ft);
        return PARAM_EXCEPTION;
    }
    if (feedback.feedbackTime <= 0) {
        FI_HILOGE("ValidateFeedback: feedbackTime invalid, value:%{public}" PRId64, feedback.feedbackTime);
        return PARAM_EXCEPTION;
    }
    return RET_OK;
}

int32_t BehaviorAwarenessServer::SubmitFeedback(const CallingContext &context, const FeedbackData &feedback)
{
    CALL_DEBUG_ENTER;
    if (!IsCallerSystemApp(context)) {
        FI_HILOGE("SubmitFeedback: non-system app");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (!CheckDeviceType()) {
        FI_HILOGE("SubmitFeedback: device not support");
        return DEVICE_NOT_SUPPORT;
    }
    int32_t ret = ValidateFeedback(feedback);
    if (ret != RET_OK) {
        FI_HILOGE("SubmitFeedback: param invalid, eventId:%{public}s, ret:%{public}d",
            feedback.perceptionEventId.c_str(), ret);
        return ret;
    }
    ret = FeedbackStore::GetInstance().InsertFeedback(feedback);
    if (ret != RET_OK) {
        FI_HILOGE("SubmitFeedback: InsertFeedback failed, service not started, ret:%{public}d, "
            "eventId:%{public}s", ret, feedback.perceptionEventId.c_str());
        return ret;
    }
    std::string bundleName = GetCallerBundleName(context);
    FI_HILOGI("SubmitFeedback: success, bundleName:%{public}s, eventId:%{public}s, type:%{public}d",
        bundleName.c_str(), feedback.perceptionEventId.c_str(),
        static_cast<int32_t>(feedback.feedbackType));
    return RET_OK;
}

void BehaviorAwarenessServer::NotifyClient(const PerceptionEventData &event)
{
    CALL_DEBUG_ENTER;
    std::vector<sptr<IRemoteBehaviorAwarenessCallback>> callbacks;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        FI_HILOGD("NotifyClient: pushing event to %{public}zu subscribers", subscriptions_.size());
        for (auto &[key, info] : subscriptions_) {
            if (info.callback == nullptr) {
                FI_HILOGE("NotifyClient: callback is null for key:%{public}s", key.c_str());
                continue;
            }
            callbacks.push_back(info.callback);
        }
    }
    for (const auto &callback : callbacks) {
        callback->OnBehaviorAwareness(event);
    }
}

void BehaviorAwarenessServer::SaveSubscription(const std::string &key, const SubscribeOptions &options,
    const sptr<IRemoteBehaviorAwarenessCallback> &callback)
{
    SubscriptionInfo info;
    info.domain = options.domain;
    info.patternTypes = options.patternTypes;
    info.callback = callback;
    subscriptions_[key] = info;
}

void BehaviorAwarenessServer::RemoveSubscription(const std::string &key)
{
    subscriptions_.erase(key);
}

void BehaviorAwarenessServer::InitDeathRecipient()
{
    if (deathRecipient_ != nullptr) {
        return;
    }
    auto callback = [this](const wptr<IRemoteObject> &remote) {
        this->OnRemoteDied(remote);
    };
    deathRecipient_ = new (std::nothrow) BehaviorAwarenessDeathRecipient(callback);
}

void BehaviorAwarenessServer::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    CALL_DEBUG_ENTER;
    sptr<IRemoteObject> client = remote.promote();
    if (client == nullptr) {
        FI_HILOGE("OnRemoteDied: failed to promote remote object");
        return;
    }
    int32_t cleaned = 0;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (auto it = subscriptions_.begin(); it != subscriptions_.end();) {
            if (it->second.callback != nullptr && it->second.callback->AsObject() == client) {
                std::string key = it->first;
                it = subscriptions_.erase(it);
                ++cleaned;
                FI_HILOGI("OnRemoteDied: cleaned subscription for key:%{public}s", key.c_str());
            } else {
                ++it;
            }
        }
    }
    if (cleaned == 0) {
        FI_HILOGD("OnRemoteDied: no matching subscription found");
    }
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
