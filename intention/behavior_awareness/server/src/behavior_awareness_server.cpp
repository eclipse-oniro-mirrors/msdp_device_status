/**
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

#include "behavior_awareness_server.h"

#include <functional>
#include <sstream>

#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "devicestatus_common.h"
#include "devicestatus_define.h"

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
    std::string bundleName = GetCallerBundleName(context);
    if (bundleName.empty()) {
        FI_HILOGE("SubscribePerception: failed to get caller bundleName");
        return SERVICE_EXCEPTION;
    }
    std::string key = BuildSubscriptionKey(bundleName, options);
    FI_HILOGI("SubscribePerception: bundleName:%{public}s, domain:%{public}d, key:%{public}s",
        bundleName.c_str(), static_cast<int32_t>(options.domain), key.c_str());

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

int32_t BehaviorAwarenessServer::SubmitFeedback(const CallingContext &context, const FeedbackData &feedback)
{
    CALL_DEBUG_ENTER;
    if (!IsCallerSystemApp(context)) {
        FI_HILOGE("SubmitFeedback: non-system app");
        return COMMON_NOT_SYSTEM_APP;
    }
    std::string bundleName = GetCallerBundleName(context);
    FI_HILOGI("SubmitFeedback: bundleName:%{public}s, eventId:%{public}s, type:%{public}d",
        bundleName.c_str(), feedback.perceptionEventId.c_str(), static_cast<int32_t>(feedback.feedbackType));
    return RET_OK;
}

void BehaviorAwarenessServer::NotifyClient(const PerceptionEventData &event)
{
    CALL_DEBUG_ENTER;
    FI_HILOGD("NotifyClient: pushing event to %{public}zu subscribers", subscriptions_.size());
    for (auto &[key, info] : subscriptions_) {
        if (info.callback == nullptr) {
            FI_HILOGE("NotifyClient: callback is null for key:%{public}s", key.c_str());
            continue;
        }
        info.callback->OnBehaviorAwareness(event);
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
    if (cleaned == 0) {
        FI_HILOGD("OnRemoteDied: no matching subscription found");
    }
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
