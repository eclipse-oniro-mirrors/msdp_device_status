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

#include "ohos.multimodalAwareness.onScreen.impl.h"
#include "devicestatus_define.h"
#include "ani_onscreen_event.h"
#include "on_screen_manager.h"

namespace ANI::MultimodalAwareness {
using namespace OHOS;
using namespace OHOS::Msdp::DeviceStatus;
using namespace taihe;
using namespace ohos::multimodalAwareness::onScreen;
sptr<onScreenCallbackTaihe> callback_ = nullptr;
void RegisterAwarenessCallback(OnscreenAwarenessCap capability,
    callback_view<void(OnscreenAwarenessInfo const &)> callback,
    optional_view<OnscreenAwarenessOptions> options)
{
    OnScreen::AwarenessCap cap;
    for (string_view str : capability.capList) {
        cap.capList.push_back(str.c_str());
    }

    callback_ = new (std::nothrow) onScreenCallbackTaihe(
            std::make_shared<taihe::callback<void(OnscreenAwarenessInfo const &)>>(callback));

    OnScreen::AwarenessOptions option_o;
    if (options->parameters.has_value()) {
        for (const auto &item : options->parameters.value()) {
            OnScreen::ValueObj valueObj;
            AniOnscreenEvent::AniToValueObj(reinterpret_cast<ani_object>(item.second), valueObj);
            option_o.entityInfo.emplace(std::string(item.first), valueObj);
        }
    }
    int32_t errNum = OnScreen::OnScreenManager::GetInstance().RegisterAwarenessCallback(cap, callback_, option_o);
    if (errNum != RET_OK) {
        taihe::set_business_error(errNum, "RegisterAwarenessCallback failed");
    }
    return;
}

void UnregisterAwarenessCallback(OnscreenAwarenessCap capability,
    optional_view<callback<void(OnscreenAwarenessInfo const &)>> callback)
{
    OnScreen::AwarenessCap cap;
    for (string_view str : capability.capList) {
        cap.capList.push_back(str.c_str());
    }

    int32_t errNum = OnScreen::OnScreenManager::GetInstance().UnregisterAwarenessCallback(cap, callback_);
    if (errNum != RET_OK) {
        taihe::set_business_error(errNum, "UnregisterAwarenessCallback failed");
    }
    callback_ = nullptr;
    return;
}


OnscreenAwarenessInfo TriggerSync(OnscreenAwarenessCap capability, optional_view<OnscreenAwarenessOptions> options)
{
    OnScreen::AwarenessCap cap;
    for (string_view str : capability.capList) {
        cap.capList.push_back(str.c_str());
    }

    OnScreen::AwarenessOptions option_o;
    if (options->parameters.has_value()) {
        for (const auto &item : options->parameters.value()) {
            OnScreen::ValueObj valueObj;
            AniOnscreenEvent::AniToValueObj(reinterpret_cast<ani_object>(item.second), valueObj);
            option_o.entityInfo.emplace(std::string(item.first), valueObj);
        }
    }

    OnScreen::OnscreenAwarenessInfo info;
    int32_t errNum = OnScreen::OnScreenManager::GetInstance().Trigger(cap, option_o, info);
    if (errNum != RET_OK) {
        taihe::set_business_error(errNum, "Trigger failed");
        return OnscreenAwarenessInfo{};
    }

    std::vector<EntityInfo> taiheVector;
    for (const auto &entityInfo : info.entityInfo) {
        ::taihe::map<::taihe::string, uintptr_t> result(entityInfo.entityInfo.size());
        for (const auto &[key, value] : entityInfo.entityInfo) {
            ani_object jsValue;
            AniOnscreenEvent::ValueObjToAni(value, jsValue);
            result.emplace(key, reinterpret_cast<uintptr_t>(jsValue));
        }
        taiheVector.push_back(EntityInfo{ .entityName = entityInfo.entityName, .entityInfo = result, });
    };

    OnscreenAwarenessInfo cbInfo = {
        .resultCode = info.resultCode,
        .timestamp = info.timestamp,
        .bundleName = optional<string>(std::in_place_t {}, string(info.bundleName)),
        .appID = optional<string>(std::in_place_t {}, string(info.appID)),
        .appIndex = optional<int32_t>(std::in_place_t {}, info.appIndex),
        .pageId = optional<string>(std::in_place_t {}, string(info.pageId)),
        .sampleId = optional<string>(std::in_place_t {}, string(info.sampleId)),
        .collectStrategy = optional<int32_t>(std::in_place_t {}, info.collectStrategy),
        .displayId = optional<int64_t>(std::in_place_t{}, info.displayId),
        .windowId = optional<int32_t>(std::in_place_t {}, info.windowId),
        .entityInfo = optional<array<EntityInfo>>(std::in_place_t {},
            taihe::array<EntityInfo>(taihe::copy_data_t{}, taiheVector.data(), taiheVector.size())),
    };
    return cbInfo;
}
} // namespace ANI::MultimodalAwareness

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_RegisterAwarenessCallback(ANI::MultimodalAwareness::RegisterAwarenessCallback);
TH_EXPORT_CPP_API_UnregisterAwarenessCallback(ANI::MultimodalAwareness::UnregisterAwarenessCallback);
TH_EXPORT_CPP_API_TriggerSync(ANI::MultimodalAwareness::TriggerSync);
// NOLINTEND
