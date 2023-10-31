/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "fusion_device_profile_adapter.h"

#include <set>

#include "cJSON.h"
#include "distributed_device_profile_client.h"
#include "singleton.h"

#include "devicestatus_define.h"

using namespace ::OHOS;
using namespace ::OHOS::DeviceProfile;

namespace {
constexpr HiviewDFX::HiLogLabel LABEL { LOG_CORE, Msdp::MSDP_DOMAIN_ID, "FusionDeviceProfile" };
const std::string SERVICE_ID { "deviceStatus" };
} // namespace

struct JsonParser {
    JsonParser() = default;
    ~JsonParser()
    {
        if (json != nullptr) {
            cJSON_Delete(json);
            json = nullptr;
        }
    }
    operator cJSON *()
    {
        return json;
    }
    cJSON *json = nullptr;
};

class ProfileEventCallback final : public IProfileEventCallback {
public:
    explicit ProfileEventCallback(CICrossStateListener *listener);
    ~ProfileEventCallback();

    void OnSyncCompleted(const SyncResult &syncResults) override;
    void OnProfileChanged(const ProfileChangeNotification &changeNotification) override;
    bool SupportProfileEvent(ProfileEvent event) const;
    void AddProfileEvent(ProfileEvent event);
    void RemoveProfileEvents(const std::list<ProfileEvent> &profileEvents);

    bool HasProfileEvent() const
    {
        return !profileEvents_.empty();
    }

private:
    CICrossStateListener *listener_ { nullptr };
    std::set<ProfileEvent> profileEvents_;
};

class FusionDeviceProfileAdapter {
    DECLARE_DELAYED_REF_SINGLETON(FusionDeviceProfileAdapter);

public:
    int32_t UpdateCrossSwitchState(bool state);
    int32_t SyncCrossSwitchState(bool state, const std::vector<std::string> &deviceIds);
    bool GetCrossSwitchState(const std::string &deviceId);
    int32_t RegisterCrossStateListener(const std::string &deviceId,
        const std::shared_ptr<ProfileEventCallback> &callback);
    int32_t UnregisterCrossStateListener(const std::string &deviceId);

private:
    void SaveSubscribeInfos(const std::string &deviceId,
                            const std::shared_ptr<ProfileEventCallback> &callback,
                            std::list<SubscribeInfo> &subscribeInfos);
    void RemoveFailedSubscriptions(const std::string &deviceId, const std::list<ProfileEvent> &failedEvents);

private:
    std::map<std::string, std::shared_ptr<ProfileEventCallback>> callbacks_;
    const std::string characteristicsName_ = "currentStatus";
};

ProfileEventCallback::ProfileEventCallback(CICrossStateListener *listener)
{
    if ((listener != nullptr) && (listener->clone != nullptr)) {
        listener_ = listener->clone(listener);
    }
}

ProfileEventCallback::~ProfileEventCallback()
{
    if ((listener_ != nullptr) && (listener_->destruct != nullptr)) {
        listener_->destruct(listener_);
    }
}

void ProfileEventCallback::OnSyncCompleted(const SyncResult &syncResults)
{
    std::for_each(syncResults.begin(), syncResults.end(), [](const auto &syncResult) {
        FI_HILOGD("Sync result:%{public}d", syncResult.second);
    });
}

void ProfileEventCallback::OnProfileChanged(const ProfileChangeNotification &changeNotification)
{
    CALL_INFO_TRACE;
    if ((listener_ != nullptr) && (listener_->onUpdate != nullptr)) {
        std::string deviceId = changeNotification.GetDeviceId();
        auto state = DelayedRefSingleton<FusionDeviceProfileAdapter>::GetInstance().GetCrossSwitchState(deviceId);
        listener_->onUpdate(listener_, deviceId.c_str(), state);
    }
}

bool ProfileEventCallback::SupportProfileEvent(ProfileEvent event) const
{
    return (profileEvents_.find(event) != profileEvents_.cend());
}

void ProfileEventCallback::AddProfileEvent(ProfileEvent event)
{
    auto ret = profileEvents_.insert(event);
    if (!ret.second) {
        FI_HILOGW("Profile event is duplicate");
    }
}

void ProfileEventCallback::RemoveProfileEvents(const std::list<ProfileEvent> &profileEvents)
{
    for (const auto &event : profileEvents) {
        profileEvents_.erase(event);
    }
}

FusionDeviceProfileAdapter::FusionDeviceProfileAdapter()
{}

FusionDeviceProfileAdapter::~FusionDeviceProfileAdapter()
{}

int32_t FusionDeviceProfileAdapter::UpdateCrossSwitchState(bool state)
{
    CALL_DEBUG_ENTER;
    const std::string SERVICE_TYPE = "deviceStatus";
    ServiceCharacteristicProfile profile;
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    cJSON *data = cJSON_CreateObject();
    cJSON_AddItemToObject(data, characteristicsName_.c_str(), cJSON_CreateNumber(state));
    char *smsg = cJSON_Print(data);
    cJSON_Delete(data);
    profile.SetCharacteristicProfileJson(smsg);
    cJSON_free(smsg);
    return DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
}

int32_t FusionDeviceProfileAdapter::SyncCrossSwitchState(bool state, const std::vector<std::string> &deviceIds)
{
    CALL_DEBUG_ENTER;
    const std::string SERVICE_TYPE = "deviceStatus";
    ServiceCharacteristicProfile profile;
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    cJSON *data = cJSON_CreateObject();
    cJSON_AddItemToObject(data, characteristicsName_.c_str(), cJSON_CreateNumber(state));
    char *smsg = cJSON_Print(data);
    cJSON_Delete(data);
    profile.SetCharacteristicProfileJson(smsg);
    cJSON_free(smsg);

    int32_t ret = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    if (ret != 0) {
        FI_HILOGE("Put device profile failed, ret:%{public}d", ret);
        return ret;
    }
    SyncOptions syncOptions;
    std::for_each(deviceIds.begin(), deviceIds.end(),
                  [&syncOptions](auto &deviceId) {
                      syncOptions.AddDevice(deviceId);
                      FI_HILOGD("Add device success");
                  });
    auto syncCallback = std::make_shared<ProfileEventCallback>(nullptr);
    ret = DistributedDeviceProfileClient::GetInstance().SyncDeviceProfile(syncOptions, syncCallback);
    if (ret != 0) {
        FI_HILOGE("Sync device profile failed");
    }
    return ret;
}

bool FusionDeviceProfileAdapter::GetCrossSwitchState(const std::string &deviceId)
{
    CALL_DEBUG_ENTER;
    ServiceCharacteristicProfile profile;

    DistributedDeviceProfileClient::GetInstance().GetDeviceProfile(deviceId, SERVICE_ID, profile);
    std::string jsonData = profile.GetCharacteristicProfileJson();
    JsonParser parser;
    parser.json = cJSON_Parse(jsonData.c_str());
    if (!cJSON_IsObject(parser.json)) {
        FI_HILOGE("Parser json is not object");
        return false;
    }
    cJSON* state = cJSON_GetObjectItemCaseSensitive(parser.json, characteristicsName_.c_str());
    if (!cJSON_IsNumber(state)) {
        FI_HILOGE("State is not number type");
        return false;
    }
    return (static_cast<bool>(state->valueint));
}

int32_t FusionDeviceProfileAdapter::RegisterCrossStateListener(const std::string &deviceId,
    const std::shared_ptr<ProfileEventCallback> &callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, RET_ERR);
    std::list<std::string> serviceIds;
    serviceIds.emplace_back(SERVICE_ID);

    ExtraInfo extraInfo;
    extraInfo["deviceId"] = deviceId;
    extraInfo["serviceIds"] = serviceIds;

    SubscribeInfo changeEventInfo;
    changeEventInfo.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    changeEventInfo.extraInfo = std::move(extraInfo);

    std::list<SubscribeInfo> subscribeInfos;
    subscribeInfos.emplace_back(changeEventInfo);

    SubscribeInfo syncEventInfo;
    syncEventInfo.profileEvent = ProfileEvent::EVENT_SYNC_COMPLETED;
    subscribeInfos.emplace_back(syncEventInfo);

    SaveSubscribeInfos(deviceId, callback, subscribeInfos);
  
    if (subscribeInfos.empty()) {
        FI_HILOGI("Profile events have been subscribed");
        return RET_ERR;
    }

    std::list<ProfileEvent> failedEvents;
    return DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(
        subscribeInfos, callback, failedEvents);
}

int32_t FusionDeviceProfileAdapter::UnregisterCrossStateListener(const std::string &deviceId)
{
    CALL_DEBUG_ENTER;
    auto cbIter = callbacks_.find(deviceId);
    if (cbIter == callbacks_.end()) {
        FI_HILOGW("This device has no callback");
        return RET_OK;
    }
    std::list<ProfileEvent> profileEvents;
    profileEvents.emplace_back(ProfileEvent::EVENT_PROFILE_CHANGED);
    std::list<ProfileEvent> failedEvents;
    int32_t ret = DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(profileEvents,
        cbIter->second, failedEvents);
    callbacks_.erase(cbIter);
    return ret;
}

void FusionDeviceProfileAdapter::SaveSubscribeInfos(const std::string &deviceId,
    const std::shared_ptr<ProfileEventCallback> &callback, std::list<SubscribeInfo> &subscribeInfos)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<ProfileEventCallback> profileEventCb;
    auto cbIter = callbacks_.find(deviceId);
    if ((cbIter == callbacks_.end()) || (cbIter->second == nullptr)) {
        if (callback == nullptr) {
            subscribeInfos.clear();
            return;
        }
        callbacks_.insert_or_assign(deviceId, callback);
        profileEventCb = callback;
    } else {
        profileEventCb = cbIter->second;
    }

    for (auto iter = subscribeInfos.begin(); iter != subscribeInfos.end();) {
        if (profileEventCb->SupportProfileEvent(iter->profileEvent)) {
            iter = subscribeInfos.erase(iter);
        } else {
            ++iter;
        }
    }
}

void FusionDeviceProfileAdapter::RemoveFailedSubscriptions(const std::string &deviceId,
    const std::list<ProfileEvent> &failedEvents)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<IProfileEventCallback> profileEventCb;
    auto cbIter = callbacks_.find(deviceId);
    if (cbIter == callbacks_.end()) {
        FI_HILOGE("Find %{public}s failed", deviceId.c_str());
        return;
    }
    if (cbIter->second == nullptr) {
        callbacks_.erase(cbIter);
        FI_HILOGE("This device has no callback");
        return;
    }

    cbIter->second->RemoveProfileEvents(failedEvents);
    if (!cbIter->second->HasProfileEvent()) {
        callbacks_.erase(deviceId);
    }
}

int32_t UpdateCrossSwitchState(size_t state)
{
    CALL_DEBUG_ENTER;
    return DelayedRefSingleton<FusionDeviceProfileAdapter>::GetInstance().UpdateCrossSwitchState(
        static_cast<bool>(state));
}

int32_t SyncCrossSwitchState(size_t state, CIStringVector *deviceIds)
{
    CALL_DEBUG_ENTER;
    CHKPR(deviceIds, RET_ERR);
    CHKPR(deviceIds->at, RET_ERR);
    CHKPR(deviceIds->size, RET_ERR);
    std::vector<std::string> deviceId;

    for (size_t i = 0; i < deviceIds->size(deviceIds); ++i) {
        const char *device_id = deviceIds->at(deviceIds, i);
        CHKPR(device_id, RET_ERR);
        deviceId.emplace_back(std::string(device_id));
    }
    return DelayedRefSingleton<FusionDeviceProfileAdapter>::GetInstance().SyncCrossSwitchState(
        static_cast<bool>(state), deviceId);
}

int32_t GetCrossSwitchState(const char *deviceId)
{
    CALL_DEBUG_ENTER;
    CHKPR(deviceId, RET_ERR);
    auto state =
        DelayedRefSingleton<FusionDeviceProfileAdapter>::GetInstance().GetCrossSwitchState(std::string(deviceId));
    return (static_cast<int32_t>(state));
}

int32_t RegisterCrossStateListener(const char *deviceId, CICrossStateListener *listener)
{
    CALL_DEBUG_ENTER;
    CHKPR(deviceId, RET_ERR);
    CHKPR(listener, RET_ERR);
    auto profileCallback = std::make_shared<ProfileEventCallback>(listener);
    return DelayedRefSingleton<FusionDeviceProfileAdapter>::GetInstance().RegisterCrossStateListener(
        std::string(deviceId), profileCallback);
}

int32_t UnregisterCrossStateListener(const char *deviceId)
{
    CALL_DEBUG_ENTER;
    CHKPR(deviceId, RET_ERR);
    return DelayedRefSingleton<FusionDeviceProfileAdapter>::GetInstance().UnregisterCrossStateListener(
        std::string(deviceId));
}
