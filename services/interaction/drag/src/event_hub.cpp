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

#include "event_hub.h"

#include <map>

#include "want.h"

#include "drag_manager.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "EventHub"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
static std::map<std::string, EventId> g_actionMap = {
    { EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON, EventId::EVENT_SCREEN_ON },
    { EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF, EventId::EVENT_SCREEN_OFF },
    { EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED, EventId::EVENT_SCREEN_LOCK },
    { EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED, EventId::EVENT_SCREEN_UNLOCK },
    { EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_LOW, EventId::EVENT_BATTERY_LOW },
    { EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_OKAY, EventId::EVENT_BATTERY_OKAY },
    { EventFwk::CommonEventSupport::COMMON_EVENT_LOCALE_CHANGED, EventId::EVENT_LOCALE_CHANGED },
};

std::shared_ptr<EventHub> EventHub::GetEventHub(IContext* context)
{
    CALL_DEBUG_ENTER;
    auto skill = std::make_shared<EventFwk::MatchingSkills>();
    for (auto &actionPair : g_actionMap) {
        skill->AddEvent(actionPair.first);
    }
    auto info = std::make_shared<EventFwk::CommonEventSubscribeInfo>(*skill);
    return std::make_shared<EventHub>(*info, context);
}

void EventHub::RegisterEvent(std::shared_ptr<EventHub> eventHub)
{
    CALL_DEBUG_ENTER;
    bool result = EventFwk::CommonEventManager::SubscribeCommonEvent(eventHub);
    if (!result) {
        FI_HILOGE("Failed to subscribe common event");
    }
}

void EventHub::UnRegisterEvent(std::shared_ptr<EventHub> eventHub)
{
    CALL_DEBUG_ENTER;
    bool result = EventFwk::CommonEventManager::UnSubscribeCommonEvent(eventHub);
    if (!result) {
        FI_HILOGE("Failed to unSubscribe common event");
    }
}

void EventHub::OnReceiveEvent(const EventFwk::CommonEventData &event)
{
    const auto want = event.GetWant();
    const auto action = want.GetAction();
    if (g_actionMap.find(action) == g_actionMap.end()) {
        return;
    }
    EventId eventId = g_actionMap[action];
    FI_HILOGD("Receive action:%{public}s, eventId:%{public}d", action.c_str(), static_cast<int32_t>(eventId));
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (eventId == EventId::EVENT_LOCALE_CHANGED) {
        CHKPV(context_);
        int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this] {
            CHKPR(this->context_, RET_ERR);
            if (auto dragState = this->context_->GetDragManager().GetDragState();
                dragState == DragState::START || dragState == DragState::MOTION_DRAGGING) {
                this->context_->GetDragManager().UpdateDragStylePositon();
            }
            return RET_OK;
        });
        if (ret != RET_OK) {
            FI_HILOGE("Post async task failed");
        }
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    if (eventId != EventId::EVENT_SCREEN_LOCK) {
        return;
    }
    CHKPV(context_);
    int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this] {
        CHKPR(this->context_, RET_ERR);
        if (this->context_->GetDragManager().GetDragState() == DragState::START) {
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
            this->context_->GetDragManager().SimulatePullCancelEvent();
#else
            DragDropResult dropResult { DragResult::DRAG_CANCEL, false, -1 };
            this->context_->GetDragManager().StopDrag(dropResult);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
        }
        return RET_OK;
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post async task failed");
    }
}

DragAbilityStatusChange::DragAbilityStatusChange(std::shared_ptr<EventHub> eventHub)
    : eventHub_(eventHub)
{}

void DragAbilityStatusChange::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    FI_HILOGI("OnAddSystemAbility,systemAbilityId:%{public}d", systemAbilityId);
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID) {
        FI_HILOGE("systemAbilityId is not COMMON_EVENT_SERVICE_ID");
        return;
    }
    if (eventHub_ == nullptr) {
        FI_HILOGE("OnAddSystemAbility eventHub_ is nullptr");
        return;
    }
    EventHub::RegisterEvent(eventHub_);
}

void DragAbilityStatusChange::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    FI_HILOGI("OnRemoveSystemAbility,systemAbilityId:%{public}d", systemAbilityId);
    return;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS