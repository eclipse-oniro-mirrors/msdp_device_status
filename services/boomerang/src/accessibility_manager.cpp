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

#include "accessibility_system_ability_client.h"
#include "accessibility_ui_test_ability.h"
#include "accessible_ability_listener.h"

#include "devicestatus_define.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "AccessibilityManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
    constexpr int32_t THREAD_SLEEP_TIME = 3000;
}

class AccessibleAbilityListenerImpl : public Accessibility::AccessibleAbilityListener {
public:
    explicit AccessibleAbilityListenerImpl(AccessibilityCallback callback)
    {
        callback_ = callback;
    }
    ~AccessibleAbilityListenerImpl() = default;

    void OnAbilityConnected() override;
    void OnAbilityDisconnected() override;
    void OnAccessibilityEvent(const Accessibility::AccessibilityEventInfo &eventInfo) override;
    bool OnKeyPressEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent) override;

private:
    AccessibilityCallback callback_;
};

void AccessibleAbilityListenerImpl::OnAbilityConnected()
{
    FI_HILOGE("Accessibility is connected");
    CHKPV(callback_);
    callback_(ON_ABILITY_CONNECTED);
}

void AccessibleAbilityListenerImpl::OnAbilityDisconnected()
{
    auto ret = Accessibility::AccessibilityUITestAbility::GetInstance()->Disconnect();
    if (ret != 0) {
        FI_HILOGE("AccessibilityManager Disconnect faild");
        return;
    }
    CHKPV(callback_);
    callback_(ON_ABILITY_DISCONNECTED);
}

void AccessibleAbilityListenerImpl::OnAccessibilityEvent(const Accessibility::AccessibilityEventInfo &eventInfo)
{
    CALL_DEBUG_ENTER;
    CHKPV(callback_);
    if (eventInfo.GetEventType() == Accessibility::EventType::TYPE_VIEW_SCROLLED_EVENT) {
        FI_HILOGD("trigger view scrolled");
        callback_(ON_ABILITY_SCROLLED_EVENT);
    }
}

bool AccessibleAbilityListenerImpl::OnKeyPressEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent)
{
    return true;
}

AccessibilityManager::AccessibilityManager() = default;

AccessibilityManager::~AccessibilityManager() = default;

void AccessibilityManager::AccessibilityConnect(AccessibilityCallback callback)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<Accessibility::AccessibleAbilityListener> listener =
        std::make_shared<AccessibleAbilityListenerImpl>(callback);
    auto ret = Accessibility::AccessibilityUITestAbility::GetInstance()->RegisterAbilityListener(listener);
    if (ret != 0) {
        FI_HILOGE("Accessibility register ablity listener failed");
        return;
    }
    ret = Accessibility::AccessibilityUITestAbility::GetInstance()->Connect();
    if (ret != 0) {
        FI_HILOGE("Accessibility Connect failed");
        return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(THREAD_SLEEP_TIME));
}

void AccessibilityManager::AccessibilityDisconnect()
{
    Accessibility::AccessibilityUITestAbility::GetInstance()->Disconnect();
}

int32_t AccessibilityManager::FindElementInfo(const int32_t windowId, DragElementInfo &info)
{
    CALL_DEBUG_ENTER;
    Accessibility::AccessibilityWindowInfo windowInfo;
    int32_t ret = Accessibility::AccessibilityUITestAbility::GetInstance()->GetWindow(windowId, windowInfo);
    if (ret != RET_OK) {
        FI_HILOGE("Accessibility::GetWindow failed,ret:%{public}d,windowId is:%{public}d", ret, windowId);
        return RET_ERR;
    }
    std::vector<Accessibility::AccessibilityElementInfo> elementInfos;
    ret = Accessibility::AccessibilityUITestAbility::GetInstance()->GetRootBatch(elementInfos);
    if (ret != RET_OK || elementInfos.empty()) {
        FI_HILOGE("GetRootByWindowBatch failed, ret:%{public}d, windowId is:%{public}d", ret, windowId);
        return RET_ERR;
    }

    size_t elementInfosSize = elementInfos.size();
    double maxArea = 0.0;
    Accessibility::AccessibilityElementInfo imageElementInfo;
    for (size_t i = 0; i < elementInfosSize; ++i) {
        std::string componentType = elementInfos[i].GetComponentType();
        if (componentType != "RenderNode" && componentType != "Image") {
            continue;
        }
        Accessibility::Rect screenRect = elementInfos[i].GetRectInScreen();
        int32_t leftTopX = screenRect.GetLeftTopXScreenPostion();
        int32_t leftTopY = screenRect.GetLeftTopYScreenPostion();
        int32_t rightBottomX = screenRect.GetRightBottomXScreenPostion();
        int32_t rightBottomY = screenRect.GetRightBottomYScreenPostion();
        double area = (rightBottomX - leftTopX) * (rightBottomY - leftTopY);
        if (area > maxArea) {
            FI_HILOGI("componentType:%{public}s, leftTopX:%{public}d, leftTopY:%{public}d",
                componentType.c_str(), leftTopX, leftTopY);
            maxArea = area;
            imageElementInfo = elementInfos[i];
        }
    }

    if (std::abs(maxArea) < std::numeric_limits<double>::epsilon()) {
        return RET_ERR;
    }
    info.componentType = imageElementInfo.GetComponentType();
    info.leftTopX = imageElementInfo.GetRectInScreen().GetLeftTopXScreenPostion();
    info.leftTopY = imageElementInfo.GetRectInScreen().GetLeftTopYScreenPostion();
    FI_HILOGD("find elementInfo success");
    return RET_OK;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS