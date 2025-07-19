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

#include "virtual_touchscreen.h"

#include <linux/input.h>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "virtual_touchscreen_builder.h"

#undef LOG_TAG
#define LOG_TAG "VirtualTouchScreen"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t MINIMUM_INTERVAL { 18 };
constexpr int32_t N_SLOTS_AVAILABLE { 10 };
constexpr int32_t STEP_LENGTH { 10 };
constexpr int32_t TWICE_STEP_LENGTH { 2 * STEP_LENGTH };
} // namespaces

std::shared_ptr<VirtualTouchScreen> VirtualTouchScreen::device_ = nullptr;

std::shared_ptr<VirtualTouchScreen> VirtualTouchScreen::GetDevice()
{
    if (device_ == nullptr) {
        std::string node;
        if (VirtualDevice::FindDeviceNode(VirtualTouchScreenBuilder::GetDeviceName(), node)) {
            auto vTouch = std::make_shared<VirtualTouchScreen>(node);
            CHKPP(vTouch);
            if (vTouch->IsActive()) {
                device_ = vTouch;
            }
        }
    }
    return device_;
}

VirtualTouchScreen::VirtualTouchScreen(const std::string &node) : VirtualDevice(node), slots_(N_SLOTS_AVAILABLE)
{
    VirtualDevice::SetMinimumInterval(MINIMUM_INTERVAL);
    QueryScreenSize();
}

void VirtualTouchScreen::QueryScreenSize()
{
    struct input_absinfo absInfo {};

    if (QueryAbsInfo(ABS_X, absInfo)) {
        screenWidth_ = (absInfo.maximum - absInfo.minimum + 1);
    }
    if (QueryAbsInfo(ABS_MT_POSITION_X, absInfo) &&
        ((screenWidth_ == std::numeric_limits<int32_t>::max()) ||
         ((absInfo.maximum - absInfo.minimum + 1) > screenWidth_))) {
        screenWidth_ = (absInfo.maximum - absInfo.minimum + 1);
    }

    if (QueryAbsInfo(ABS_Y, absInfo)) {
        screenHeight_ = (absInfo.maximum - absInfo.minimum + 1);
    }
    if (QueryAbsInfo(ABS_MT_POSITION_Y, absInfo) &&
        ((screenHeight_ == std::numeric_limits<int32_t>::max()) ||
         ((absInfo.maximum - absInfo.minimum + 1) > screenHeight_))) {
        screenHeight_ = (absInfo.maximum - absInfo.minimum + 1);
    }
}

void VirtualTouchScreen::SendTouchEvent()
{
    CALL_DEBUG_ENTER;
    for (int32_t s = 0; s < N_SLOTS_AVAILABLE; ++s) {
        if (!slots_[s].active) {
            continue;
        }
        SendEvent(EV_ABS, ABS_MT_POSITION_X, slots_[s].coord.x);
        SendEvent(EV_ABS, ABS_MT_POSITION_Y, slots_[s].coord.y);
        SendEvent(EV_ABS, ABS_MT_TRACKING_ID, s);
        SendEvent(EV_SYN, SYN_MT_REPORT, SYNC_VALUE);
        FI_HILOGD("Send event [%{public}d], (%{private}d, %{private}d)", s, slots_[s].coord.x, slots_[s].coord.y);
    }
}

int32_t VirtualTouchScreen::DownButton(int32_t slot, int32_t x, int32_t y)
{
    CALL_DEBUG_ENTER;
    if (slot < 0 || slot >= N_SLOTS_AVAILABLE) {
        FI_HILOGD("Slot out of range, slot:%{public}d", slot);
        slot = N_SLOTS_AVAILABLE - 1;
    }
    bool firstTouchDown = std::none_of(slots_.cbegin(), slots_.cend(), [](const auto &slot) { return slot.active; });
    if (slots_.size() <= static_cast<size_t>(slot)) {
        FI_HILOGE("The index is out of bounds");
        return RET_ERR;
    }
    slots_[slot].coord.x = std::min(std::max(x, 0), screenWidth_ - 1);
    slots_[slot].coord.y = std::min(std::max(y, 0), screenHeight_ - 1);
    slots_[slot].active = true;
    FI_HILOGD("Press down [%{public}d], (%{public}d, %{public}d)", slot, slots_[slot].coord.x, slots_[slot].coord.y);
    SendTouchEvent();
    if (firstTouchDown) {
        FI_HILOGD("First touch down, send button touch down event");
        SendEvent(EV_KEY, BTN_TOUCH, DOWN_VALUE);
    }
    SendEvent(EV_SYN, SYN_MT_REPORT, SYNC_VALUE);
    FI_HILOGD("Send sync event");
    SendEvent(EV_SYN, SYN_REPORT, SYNC_VALUE);
    return RET_OK;
}

int32_t VirtualTouchScreen::UpButton(int32_t slot)
{
    CALL_DEBUG_ENTER;
    if (slot < 0 || slot >= N_SLOTS_AVAILABLE) {
        FI_HILOGD("Slot out of range, slot:%{public}d", slot);
        slot = N_SLOTS_AVAILABLE - 1;
    }
    if (slots_.size() <= static_cast<size_t>(slot)) {
        FI_HILOGE("The index is out of bounds");
        return RET_ERR;
    }
    if (!slots_[slot].active) {
        FI_HILOGE("Slot [%{public}d] is not active", slot);
        return RET_ERR;
    }
    slots_[slot].active = false;
    FI_HILOGD("Release [%{public}d]", slot);
    SendTouchEvent();
    SendEvent(EV_SYN, SYN_MT_REPORT, SYNC_VALUE);
    FI_HILOGD("Send sync event");
    SendEvent(EV_SYN, SYN_REPORT, SYNC_VALUE);

    bool lastTouchUp = std::none_of(slots_.cbegin(), slots_.cend(), [](const auto &slot) { return slot.active; });
    if (lastTouchUp) {
        FI_HILOGD("Last touch up, send button touch up event");
        SendEvent(EV_KEY, BTN_TOUCH, UP_VALUE);
        SendEvent(EV_SYN, SYN_MT_REPORT, SYNC_VALUE);
        SendEvent(EV_SYN, SYN_REPORT, SYNC_VALUE);
    }
    return RET_OK;
}

int32_t VirtualTouchScreen::Move(int32_t slot, int32_t dx, int32_t dy)
{
    CALL_DEBUG_ENTER;
    if (slot < 0 || slot >= N_SLOTS_AVAILABLE) {
        slot = N_SLOTS_AVAILABLE - 1;
    }
    if (slots_.size() <= static_cast<size_t>(slot)) {
        FI_HILOGE("The index is out of bounds");
        return RET_ERR;
    }
    if (!slots_[slot].active) {
        FI_HILOGE("slot [%{public}d] is not active", slot);
        return RET_ERR;
    }
    Coordinate tcoord {
        .x = std::min(std::max(slots_[slot].coord.x + dx, 0), screenWidth_ - 1),
        .y = std::min(std::max(slots_[slot].coord.y + dy, 0), screenHeight_ - 1)
    };
    FI_HILOGD("Move [%{public}d] from (%{private}d, %{private}d) to (%{private}d, %{private}d)",
        slot, slots_[slot].coord.x, slots_[slot].coord.y, tcoord.x, tcoord.y);

    while ((tcoord.x != slots_[slot].coord.x) || (tcoord.y != slots_[slot].coord.y)) {
        double total = ::hypot(tcoord.x - slots_[slot].coord.x, tcoord.y - slots_[slot].coord.y);
        if (total <= STEP_LENGTH) {
            slots_[slot].coord.x = tcoord.x;
            slots_[slot].coord.y = tcoord.y;
        } else {
            double step { STEP_LENGTH };
            if (total < TWICE_STEP_LENGTH) {
                step = total / HALF_VALUE;
            }
            slots_[slot].coord.x += static_cast<int32_t>(round(step * (tcoord.x - slots_[slot].coord.x) / total));
            slots_[slot].coord.y += static_cast<int32_t>(round(step * (tcoord.y - slots_[slot].coord.y) / total));
        }
        SendTouchEvent();
        SendEvent(EV_SYN, SYN_MT_REPORT, SYNC_VALUE);
        SendEvent(EV_SYN, SYN_REPORT, SYNC_VALUE);
    }
    return RET_OK;
}

int32_t VirtualTouchScreen::MoveTo(int32_t slot, int32_t x, int32_t y)
{
    CALL_DEBUG_ENTER;
    if (slot < 0 || slot >= N_SLOTS_AVAILABLE) {
        slot = N_SLOTS_AVAILABLE - 1;
    }
    if (slots_.size() <= static_cast<size_t>(slot)) {
        FI_HILOGE("The index is out of bounds");
        return RET_ERR;
    }
    if (!slots_[slot].active) {
        FI_HILOGE("slot [%{public}d] is not active", slot);
        return RET_ERR;
    }
    return Move(slot, x - slots_[slot].coord.x, y - slots_[slot].coord.y);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS