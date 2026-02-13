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

enum OnScreenErrCode {
    RET_NO_PERMISSION = 201,
    RET_NO_SYSTEM_CALLING = 202,
    RET_PARAM_ERR = 401,
    RET_NO_SUPPORT = 801,
    RET_SERVICE_EXCEPTION = 34000001,
    RET_NOT_IN_WHITELIST,
    RET_WINDOW_ID_ERR,
    RET_PAGE_NOT_READY,
    RET_TARGET_NOT_FOUND,
    RET_TIMEOUT,
};

std::map<int32_t, std::string> ERROR_MESSAGES = {
    { RET_NO_PERMISSION, "Permission check failed." },
    { RET_NO_SYSTEM_CALLING, "Permission check failed. A non-system application uses the system API." },
    { RET_PARAM_ERR, "Params check failed." },
    { RET_NO_SUPPORT, "The device does not support this API." },
    { RET_SERVICE_EXCEPTION, "Service exception." },
    { RET_NOT_IN_WHITELIST, "The application or page is not supported." },
    { RET_WINDOW_ID_ERR, "The window ID is invalid. Possible causes: 1. window id is not passes when"
                        "screen is splited. 2. passed window id is not on screen or floating." },
    { RET_PAGE_NOT_READY, "The page is not ready." },
    { RET_TARGET_NOT_FOUND, "The target is not found." },
    { RET_TIMEOUT, "The request timed out." },
};

std::string GetOnScreenErrMsg(int32_t errCode)
{
    auto iter = ERROR_MESSAGES.find(errCode);
    if (iter != ERROR_MESSAGES.end()) {
        return iter->second;
    }
    FI_HILOGE("Error messages not found");
    return "";
}

void ThrowOnScreenErr(int32_t errCode, const std::string &printMsg)
{
    errCode = errCode == ETASKS_WAIT_TIMEOUT ? RET_TIMEOUT : errCode;
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", printMsg.c_str(), errCode);
    auto msg = GetOnScreenErrMsg(errCode);
    if (msg.empty()) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        taihe::set_business_error(RET_SERVICE_EXCEPTION, "service exception");
        return;
    }
    taihe::set_business_error(errCode, msg.c_str());
}

ohos::multimodalAwareness::onScreen::PageContent ConvertPageContent(
    OHOS::Msdp::DeviceStatus::OnScreen::PageContent value)
{
    auto windowId = value.windowId;
    auto sessionId = value.sessionId;
    auto bundleName = ::taihe::string(value.bundleName);
    auto scenario = ::taihe::optional<ohos::multimodalAwareness::onScreen::Scenario>::make(
        ::ohos::multimodalAwareness::onScreen::Scenario::from_value(static_cast<int32_t>(value.scenario)));
    auto title = ::taihe::optional<::taihe::string>::make(::taihe::string(value.title));
    auto content = ::taihe::optional<::taihe::string>::make(::taihe::string(value.content));
    auto pageLink = ::taihe::optional<::taihe::string>::make(::taihe::string(value.pageLink));
    ::taihe::optional<::taihe::array<::ohos::multimodalAwareness::onScreen::Paragraph>> paragraphs;
    auto pageContentTaihe = ohos::multimodalAwareness::onScreen::PageContent {
        std::move(windowId),
        std::move(sessionId),
        std::move(bundleName),
        std::move(scenario),
        std::move(title),
        std::move(content),
        std::move(pageLink),
        std::move(paragraphs),
    };

    std::vector<::ohos::multimodalAwareness::onScreen::Paragraph> paragraphsArray;
    for (const auto &paragraph: value.paragraphs) {
        auto hookId = ::taihe::optional<int64_t>::make(paragraph.hookId);
        auto chapterId = ::taihe::optional<int32_t>::make(paragraph.chapterId);
        auto title = ::taihe::optional<::taihe::string>::make(::taihe::string(paragraph.title));
        auto text = ::taihe::optional<::taihe::string>::make(::taihe::string(paragraph.content));
        auto paragraphTaihe = ohos::multimodalAwareness::onScreen::Paragraph {
            std::move(hookId),
            std::move(chapterId),
            std::move(title),
            std::move(text),
        };
        paragraphsArray.emplace_back(paragraphTaihe);
    }
    taihe::array<::ohos::multimodalAwareness::onScreen::Paragraph> paragraphsTaihe{paragraphsArray};
    pageContentTaihe.paragraphs = ::taihe::optional<::taihe::array<::ohos::multimodalAwareness::onScreen::Paragraph>>
                                  ::make(paragraphsTaihe);
    return pageContentTaihe;
}

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

void SendControlEventSync(ohos::multimodalAwareness::onScreen::ControlEvent event)
{
    OHOS::Msdp::DeviceStatus::OnScreen::ControlEvent eventInner;
    eventInner.windowId = event.windowId;
    eventInner.sessionId = event.sessionId;
    if (event.hookId.has_value()) {
        eventInner.hookId = event.hookId.value();
    }
    if (event.eventType.get_key() ==
        ohos::multimodalAwareness::onScreen::EventType::key_t::SCROLL_TO_HOOK) {
        eventInner.eventType = OHOS::Msdp::DeviceStatus::OnScreen::EventType::SCROLL_TO_HOOK;
    }

    auto result = OnScreen::OnScreenManager::GetInstance().SendControlEvent(eventInner);
    if (result != RET_OK) {
        ThrowOnScreenErr(result, "SendControlEvent err.");
    }
    return;
}

ohos::multimodalAwareness::onScreen::PageContent GetPageContentSync(
    ::taihe::optional<ohos::multimodalAwareness::onScreen::ContentOptions> options)
{
    OHOS::Msdp::DeviceStatus::OnScreen::ContentOption optionsInner;
    OHOS::Msdp::DeviceStatus::OnScreen::PageContent pageContentInner;
    if (options.has_value()) {
        if (options.value().windowId.has_value()) {
            optionsInner.windowId = options.value().windowId.value();
        }
        if (options.value().contentUnderstand.has_value()) {
            optionsInner.contentUnderstand = options.value().contentUnderstand.value();
        }
        if (options.value().pageLink.has_value()) {
            optionsInner.pageLink = options.value().pageLink.value();
        }
        if (options.value().textOnly.has_value()) {
            optionsInner.textOnly = options.value().textOnly.value();
        }
    }
    auto result = OnScreen::OnScreenManager::GetInstance().GetPageContent(optionsInner, pageContentInner);
    if (result != RET_OK) {
        ThrowOnScreenErr(result, "GetPageContent err.");
    }
    return ConvertPageContent(pageContentInner);
}
} // namespace ANI::MultimodalAwareness

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_RegisterAwarenessCallback(ANI::MultimodalAwareness::RegisterAwarenessCallback);
TH_EXPORT_CPP_API_UnregisterAwarenessCallback(ANI::MultimodalAwareness::UnregisterAwarenessCallback);
TH_EXPORT_CPP_API_TriggerSync(ANI::MultimodalAwareness::TriggerSync);
TH_EXPORT_CPP_API_SendControlEventSync(ANI::MultimodalAwareness::SendControlEventSync);
TH_EXPORT_CPP_API_GetPageContentSync(ANI::MultimodalAwareness::GetPageContentSync);
// NOLINTEND
