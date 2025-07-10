/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "accessibility_manager.h"

#include <ctime>
#include <mutex>
#include <regex>
#include <thread>

#include "devicestatus_define.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "AccessibilityManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
void AccessibilityManager::AccessibleAbilityListenerImpl::OnAbilityConnected()
{
    std::lock_guard<std::mutex> guard(mutex_);
    FI_HILOGI("Accessibility is OnAbilityConnected");
    isConnected = true;
    CHKPV(callback_);
    callback_(ON_ABILITY_CONNECTED);
}

void AccessibilityManager::AccessibleAbilityListenerImpl::OnAbilityDisconnected()
{
    std::lock_guard<std::mutex> guard(mutex_);
    FI_HILOGI("Accessibility is OnAbilityDisconnected");
    CHKPV(manager_);
    isConnected = false;
    CHKPV(callback_);
    callback_(ON_ABILITY_DISCONNECTED);
    callback_ = nullptr;
    manager_ = nullptr;
}

void AccessibilityManager::AccessibleAbilityListenerImpl::OnAccessibilityEvent
    (const Accessibility::AccessibilityEventInfo &eventInfo)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(callback_);
    if (eventInfo.GetEventType() == Accessibility::EventType::TYPE_VIEW_SCROLLED_EVENT) {
        FI_HILOGD("trigger view scrolled");
        callback_(ON_ABILITY_SCROLLED_EVENT);
    }
}

bool AccessibilityManager::AccessibleAbilityListenerImpl::OnKeyPressEvent
    (const std::shared_ptr<MMI::KeyEvent> &keyEvent)
{
    return true;
}

AccessibilityManager::AccessibilityManager() = default;

AccessibilityManager::~AccessibilityManager() = default;

void AccessibilityManager::AccessibilityConnect(AccessibilityCallback callback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    CALL_DEBUG_ENTER;
    CHKPV(callback);
    AccessibilityManager* manager = new (std::nothrow) AccessibilityManager();
    CHKPV(manager);
    auto listener = std::make_shared<AccessibleAbilityListenerImpl>(callback, manager);
    if (listener == nullptr) {
        FI_HILOGE("create accessible ability listener failed");
        delete manager;
        return;
    }
    auto ret = Accessibility::AccessibilityUITestAbility::GetInstance()->RegisterAbilityListener(listener);
    if (ret != 0) {
        FI_HILOGE("Accessibility register ablity listener failed");
        delete manager;
        return;
    }
    ret = Accessibility::AccessibilityUITestAbility::GetInstance()->Connect();
    if (ret != 0) {
        FI_HILOGE("Accessibility Connect failed");
        delete manager;
        return;
    }
}

void AccessibilityManager::AccessibilityDisconnect()
{
    std::lock_guard<std::mutex> guard(mutex_);
    auto ret = Accessibility::AccessibilityUITestAbility::GetInstance()->Disconnect();
    if (ret != 0) {
        FI_HILOGE("Accessibility disConnect failed");
        return;
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS