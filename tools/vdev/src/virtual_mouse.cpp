/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include "virtual_mouse.h"

#include <cmath>

#include <linux/input.h>

#include "display_manager.h"
#include "input_manager.h"

#include "devicestatus_define.h"
#include "fi_log.h"
#include "virtual_device_defines.h"
#include "virtual_mouse_builder.h"

#undef LOG_TAG
#define LOG_TAG "VirtualMouse"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t REL_WHEEL_VALUE { 1 };
constexpr int32_t REL_WHEEL_HI_RES_VALUE { 120 };
constexpr int32_t MAX_SCROLL_LENGTH { 10 };
constexpr int32_t MINIMUM_INTERVAL { 8 };
constexpr double FAST_STEP { 5.0 };
constexpr double TWICE_FAST_STEP { 2.0 * FAST_STEP };
constexpr double MAXIMUM_STEP_LENGTH { 5000.0 };
constexpr double STEP_UNIT { 1.0 };
int32_t g_screenWidth { 720 };
int32_t g_screenHeight { 1280 };
} // namespace

class PointerPositionMonitor final : public MMI::IInputEventConsumer {
public:
    PointerPositionMonitor() = default;
    ~PointerPositionMonitor() = default;

    void OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const override {};
    void OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const override;
    void OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const override {};

    size_t GetCount() const
    {
        return count_;
    }

    int32_t GetX() const
    {
        return pos_.x;
    }

    int32_t GetY() const
    {
        return pos_.y;
    }

private:
    mutable size_t count_ { 0 };
    mutable Coordinate pos_ {};
};

void PointerPositionMonitor::OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
    CHKPV(pointerEvent);
    if (pointerEvent->GetSourceType() != MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        return;
    }
    MMI::PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem)) {
        FI_HILOGE("Pointer event is corrupt");
        return;
    }

    pos_.x = pointerItem.GetDisplayX();
    pos_.y = pointerItem.GetDisplayY();
    ++count_;
}

std::shared_ptr<VirtualMouse> VirtualMouse::device_ = nullptr;

std::shared_ptr<VirtualMouse> VirtualMouse::GetDevice()
{
    if (device_ == nullptr) {
        std::string node;
        if (VirtualDevice::FindDeviceNode(VirtualMouseBuilder::GetDeviceName(), node)) {
            auto vMouse = std::make_shared<VirtualMouse>(node);
            CHKPP(vMouse);
            if (vMouse->IsActive()) {
                device_ = vMouse;
            }
        }
    }
    return device_;
}

VirtualMouse::VirtualMouse(const std::string &name) : VirtualDevice(name)
{
    VirtualDevice::SetMinimumInterval(MINIMUM_INTERVAL);
}

int32_t VirtualMouse::DownButton(int32_t button)
{
    CALL_DEBUG_ENTER;
    if (button < BTN_MOUSE || button > BTN_SIDE) {
        FI_HILOGE("Not mouse button:%{public}d", button);
        return RET_ERR;
    }

    SendEvent(EV_MSC, MSC_SCAN, OBFUSCATED);
    SendEvent(EV_KEY, button, DOWN_VALUE);
    SendEvent(EV_SYN, SYN_REPORT, SYNC_VALUE);
    return RET_OK;
}

int32_t VirtualMouse::UpButton(int32_t button)
{
    CALL_DEBUG_ENTER;
    if (button < BTN_MOUSE || button > BTN_TASK) {
        FI_HILOGE("Not mouse button:%{public}d", button);
        return RET_ERR;
    }

    SendEvent(EV_MSC, MSC_SCAN, OBFUSCATED);
    SendEvent(EV_KEY, button, UP_VALUE);
    SendEvent(EV_SYN, SYN_REPORT, SYNC_VALUE);
    return RET_OK;
}

void VirtualMouse::Scroll(int32_t dy)
{
    CALL_DEBUG_ENTER;
    int32_t wheelValue = REL_WHEEL_VALUE;
    int32_t wheelHiResValue = REL_WHEEL_HI_RES_VALUE;

    if (dy < 0) {
        wheelValue = -wheelValue;
        wheelHiResValue = -wheelHiResValue;
        dy = -dy;
    }
    if (dy > MAX_SCROLL_LENGTH) {
        dy = MAX_SCROLL_LENGTH;
    }
    for (; dy >= REL_WHEEL_VALUE; dy -= REL_WHEEL_VALUE) {
        SendEvent(EV_REL, REL_WHEEL, wheelValue);
        SendEvent(EV_REL, REL_HWHEEL_HI_RES, wheelHiResValue);
        SendEvent(EV_SYN, SYN_REPORT, SYNC_VALUE);
    }
}

void VirtualMouse::Move(int32_t dx, int32_t dy)
{
    CALL_DEBUG_ENTER;
    double delta = ::hypot(dx, dy);
    if (std::abs(delta) < STEP_UNIT) {
        FI_HILOGE("Mouse not moving");
        return;
    }
    double total = std::min(delta, MAXIMUM_STEP_LENGTH);
    double step = FAST_STEP;
    int32_t count = static_cast<int32_t>(ceil(total / FAST_STEP));
    while (count-- > 0) {
        if (total < TWICE_FAST_STEP) {
            if (total > FAST_STEP) {
                step = total / HALF_VALUE;
            } else {
                step = total;
            }
        } else {
            step = FAST_STEP;
        }
        double tx = round(step * static_cast<double>(dx) / delta);
        double ty = round(step * static_cast<double>(dy) / delta);

        if ((std::abs(tx) >= STEP_UNIT) && (std::abs(tx) <= MAXIMUM_STEP_LENGTH)) {
            SendEvent(EV_REL, REL_X, static_cast<int32_t>(tx));
        }
        if ((std::abs(ty) >= STEP_UNIT) && (std::abs(ty) <= MAXIMUM_STEP_LENGTH)) {
            SendEvent(EV_REL, REL_Y, static_cast<int32_t>(ty));
        }
        if (((std::abs(tx) >= STEP_UNIT) && (std::abs(tx) <= MAXIMUM_STEP_LENGTH)) ||
            ((std::abs(ty) >= STEP_UNIT) && (std::abs(ty) <= MAXIMUM_STEP_LENGTH))) {
            SendEvent(EV_SYN, SYN_REPORT, SYNC_VALUE);
        }
        total -= step;
    }
}

int32_t VirtualMouse::MoveTo(int32_t x, int32_t y)
{
    CALL_DEBUG_ENTER;
    MMI::InputManager *inputMgr = MMI::InputManager::GetInstance();
    CHKPR(inputMgr, RET_ERR);
    auto monitor = std::make_shared<PointerPositionMonitor>();
    int32_t monitorId = inputMgr->AddMonitor(monitor);
    if (monitorId < 0) {
        return RET_ERR;
    }
    size_t count = monitor->GetCount();
    int32_t nLoops = 5;
    Move(MOVE_VALUE_X, MOVE_VALUE_Y);
    int32_t ret = RET_OK;
    while (nLoops-- > 0) {
        int32_t nTries = 125;
        for (;;) {
            if (monitor->GetCount() > count) {
                count = monitor->GetCount();
                break;
            }
            if (--nTries < 0) {
                FI_HILOGE("No pointer motion detected");
                ret = RET_ERR;
                goto CLEANUP;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(MINIMUM_INTERVAL));
        }
        FI_HILOGD("Current position: (%{private}d, %{private}d)", monitor->GetX(), monitor->GetY());
        if (x == monitor->GetX() && y == monitor->GetY()) {
            ret = RET_OK;
            goto CLEANUP;
        }
        Move(x - monitor->GetX(), y - monitor->GetY());
    }
CLEANUP:
    inputMgr->RemoveMonitor(monitorId);
    return ret;
}

void VirtualMouse::MoveProcess(int32_t dx, int32_t dy)
{
    CALL_DEBUG_ENTER;
#ifndef OHOS_BUILD_PC_PRODUCT
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
#else
    sptr<Rosen::DisplayInfo> display = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(0);
#endif // OHOS_BUILD_PC_PRODUCT
    CHKPV(display);
    g_screenWidth = display->GetWidth();
    g_screenHeight = display->GetHeight();
    MMI::InputManager *inputMgr = MMI::InputManager::GetInstance();
    CHKPV(inputMgr);
    auto monitor = std::make_shared<PointerPositionMonitor>();
    int32_t monitorId = inputMgr->AddMonitor(monitor);
    if (monitorId < 0) {
        FI_HILOGE("Failed to add mouse monitor");
        return;
    }
    Move(MOVE_VALUE_X, MOVE_VALUE_Y);
    Move(-MOVE_VALUE_Y, -MOVE_VALUE_X);
    int32_t currentX = monitor->GetX();
    int32_t currentY = monitor->GetY();
    int32_t targetX = currentX + dx;
    int32_t targetY = currentY + dy;
    FI_HILOGD("Expected coordinates, (targetX, targetY):(%{private}d, %{private}d)", targetX, targetY);
    Move(dx, dy);
    if ((targetX < g_screenWidth && targetX >= 0) && (targetY < g_screenHeight && targetY >= 0) &&
        (currentX < g_screenWidth && currentX > 0) && (currentY < g_screenHeight && currentY > 0)) {
        int32_t nLoops = 5;
        while (nLoops-- > 0) {
            currentX = monitor->GetX();
            currentY = monitor->GetY();
            if (targetX == currentX && targetY == currentY) {
                break;
            }
            Move(targetX - currentX, targetY - currentY);
        }
    }
    inputMgr->RemoveMonitor(monitorId);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS