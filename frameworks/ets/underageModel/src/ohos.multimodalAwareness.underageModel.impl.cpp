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
#include <stdexcept>

#include "ani_underage_model_event.h"
#include "fi_log.h"
#include "ohos.multimodalAwareness.underageModel.proj.hpp"
#include "ohos.multimodalAwareness.underageModel.impl.hpp"
#include "taihe/runtime.hpp"

#undef LOG_TAG
#define LOG_TAG "ANIUnderageModel"
namespace {
using namespace OHOS::Msdp;
using namespace ::ohos::multimodalAwareness::underageModel;
std::shared_ptr<AniUnderageModelEvent> g_underageModelObj = nullptr;

void OnUserAgeGroupDetectedInner(::taihe::callback_view<void(UserClassification_t const& info)> f, uintptr_t opq)
{
    FI_HILOGI("OnUserAgeGroupDetectedInner enter");
    g_underageModelObj = AniUnderageModelEvent::GetInstance();
    if (g_underageModelObj == nullptr) {
        FI_HILOGE("g_underageModelObj is null");
        taihe::set_business_error(SUBSCRIBE_EXCEPTION, "g_underageModelObj is null");
        return;
    }
    if (!g_underageModelObj->AddCallback(UNDERAGE_MODEL_TYPE_KID, opq)) {
        FI_HILOGE("AddCallback failed");
        taihe::set_business_error(SERVICE_EXCEPTION, "AddCallback failed");
        return;
    }
    if (!g_underageModelObj->SubscribeCallback(UNDERAGE_MODEL_TYPE_KID)) {
        FI_HILOGE("SubscribeCallback failed");
        if (!g_underageModelObj->RemoveAllCallback(UNDERAGE_MODEL_TYPE_KID)) {
            FI_HILOGE("RemoveCallback failed");
        }
        return;
    }
}

void OffUserAgeGroupDetectedInner(::taihe::optional_view<uintptr_t> opq)
{
    FI_HILOGI("OffUserAgeGroupDetectedInner enter");
    if (g_underageModelObj == nullptr) {
        FI_HILOGE("g_underageModelObj is null");
        taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "g_underageModelObj is null");
        return;
    }
    if (!opq.has_value()) {
        if (!g_underageModelObj->RemoveAllCallback(UNDERAGE_MODEL_TYPE_KID)) {
            FI_HILOGE("RemoveAllCallback failed");
            taihe::set_business_error(SERVICE_EXCEPTION, "RemoveAllCallback failed");
            return;
        }
    } else {
        if (!g_underageModelObj->RemoveCallback(UNDERAGE_MODEL_TYPE_KID,
            opq.value())) {
            FI_HILOGE("RemoveCallback failed");
            taihe::set_business_error(SERVICE_EXCEPTION, "RemoveCallback failed");
            return;
        }
    }
    if (!g_underageModelObj->UnSubscribeCallback(UNDERAGE_MODEL_TYPE_KID)) {
        FI_HILOGE("UnSubscribeCallback failed");
        return;
    }
}

int32_t SubscribeInner(UserStatusFeature featureId, taihe::callback_view<void(UserStatusData const &data)> callback,
    uintptr_t opq, taihe::optional_view<taihe::array<DeviceInfo>> deviceInfo)
{
    FI_HILOGI("Subscribe enter");
    g_underageModelObj = AniUnderageModelEvent::GetInstance();
    if (g_underageModelObj == nullptr) {
        FI_HILOGE("g_underageModelObj is null");
        taihe::set_business_error(SERVICE_EXCEPTION, "g_underageModelObj is null");
        return ANI_ERROR;
    }
    std::vector<UserStatusAwareness::DeviceInfo> deviceInfoList;
    if (deviceInfo.has_value()) {
        for (size_t i = 0; i < deviceInfo.value().size(); i++) {
            std::string deviceId(deviceInfo.value()[i].deviceId);
            std::string networkId(deviceInfo.value()[i].networkId);
            std::string deviceName(deviceInfo.value()[i].deviceName);
            std::uint32_t deviceType = static_cast<std::uint32_t>(deviceInfo.value()[i].deviceType);
            UserStatusAwareness::DeviceInfo deviceInfoItem(deviceId, deviceName, networkId, deviceType);
            deviceInfoList.emplace_back(deviceInfoItem);
        }
    }
    if (!g_underageModelObj->SubscribeUserStatus(featureId, deviceInfoList)) {
        FI_HILOGE("SubscribeCallback failed");
        return ANI_ERROR;
    }
    if (!g_underageModelObj->AddCallback(featureId, opq)) {
        FI_HILOGE("AddCallback failed");
        taihe::set_business_error(SERVICE_EXCEPTION, "AddCallback failed");
        return ANI_ERROR;
    }
    return ANI_OK;
}

int32_t UnsubscribeInner(UserStatusFeature featureId, ::taihe::optional_view<uintptr_t> opq)
{
    FI_HILOGI("UnsubscribeInner enter");
    if (g_underageModelObj == nullptr) {
        FI_HILOGE("g_underageModelObj is null");
        taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "g_underageModelObj is null");
        return ANI_ERROR;
    }
    if (!opq.has_value()) {
        if (!g_underageModelObj->RemoveAllCallback(featureId)) {
            FI_HILOGE("RemoveAllCallback failed");
            taihe::set_business_error(SERVICE_EXCEPTION, "RemoveAllCallback failed");
            return ANI_ERROR;
        }
    } else {
        if (!g_underageModelObj->RemoveCallback(featureId,
            opq.value())) {
            FI_HILOGE("RemoveCallback failed");
            taihe::set_business_error(SERVICE_EXCEPTION, "RemoveCallback failed");
            return ANI_ERROR;
        }
    }
    if (!g_underageModelObj->UnSubscribeCallback(featureId)) {
        FI_HILOGE("UnSubscribeCallback failed");
        return ANI_ERROR;
    }
    return ANI_OK;
}

int32_t Configure(UserStatusFeature featureId, taihe::string_view detail)
{
    FI_HILOGI("Configure enter");
    if (detail.empty()) {
        return ANI_ERROR;
    }
    g_underageModelObj = AniUnderageModelEvent::GetInstance();
    if (g_underageModelObj == nullptr) {
        FI_HILOGE("g_underageModelObj is null");
        taihe::set_business_error(SERVICE_EXCEPTION, "g_underageModelObj is null");
        return ANI_ERROR;
    }
    std::string detailStr(detail);
    return g_underageModelObj->ConfigParams(featureId, detailStr);
}

taihe::array<UserStatusAtomicCap> QueryCapabilities(taihe::array_view<UserStatusAtomicCap> capabilities)
{
    FI_HILOGI("QueryCapabilities enter");
    if (capabilities.empty()) {
        FI_HILOGE("capabilities is empty");
        return {};
    }
    std::vector<std::int32_t> caps;
    for (size_t i = 0; i < capabilities.size(); ++i) {
        caps.push_back(static_cast<std::int32_t>(capabilities[i]));
    }
    g_underageModelObj = AniUnderageModelEvent::GetInstance();
    if (g_underageModelObj == nullptr) {
        FI_HILOGE("g_underageModelObj is null");
        taihe::set_business_error(SERVICE_EXCEPTION, "g_underageModelObj is null");
        return {};
    }
    if (!g_underageModelObj->QueryCapabilities(caps)) {
        return {};
    }
    std::vector<UserStatusAtomicCap> res;
    for (size_t i = 0; i < caps.size(); ++i) {
        res.push_back(static_cast<UserStatusAtomicCap::key_t>(caps[i]));
    }
    return taihe::array<UserStatusAtomicCap>(res);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_OnUserAgeGroupDetectedInner(OnUserAgeGroupDetectedInner);
TH_EXPORT_CPP_API_OffUserAgeGroupDetectedInner(OffUserAgeGroupDetectedInner);

TH_EXPORT_CPP_API_SubscribeInner(SubscribeInner);
TH_EXPORT_CPP_API_UnsubscribeInner(UnsubscribeInner);
TH_EXPORT_CPP_API_Configure(Configure);
TH_EXPORT_CPP_API_QueryCapabilities(QueryCapabilities);
// NOLINTEND