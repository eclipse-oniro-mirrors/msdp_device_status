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

#include "virtual_keyboard.h"

#include <cmath>

#include <linux/input.h>

#include "input_manager.h"

#include "devicestatus_define.h"
#include "fi_log.h"
#include "virtual_keyboard_builder.h"

#undef LOG_TAG
#define LOG_TAG "VirtualKeyboard"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t MINIMUM_INTERVAL { 8 };
} // namespace

std::shared_ptr<VirtualKeyboard> VirtualKeyboard::device_ { nullptr };

std::shared_ptr<VirtualKeyboard>VirtualKeyboard::GetDevice()
{
    if (device_ == nullptr) {
        std::string node;
        if (VirtualDevice::FindDeviceNode(VirtualKeyboardBuilder::GetDeviceName(), node)) {
            auto vKeyboard = std::make_shared<VirtualKeyboard>(node);
            CHKPP(vKeyboard);
            if (vKeyboard->IsActive()) {
                device_ = vKeyboard;
            }
        }
    }
    return device_;
}

VirtualKeyboard::VirtualKeyboard(const std::string &name)
    : VirtualDevice(name)
{
    VirtualDevice::SetMinimumInterval(MINIMUM_INTERVAL);
}

int32_t VirtualKeyboard::Down(int32_t key)
{
    CALL_DEBUG_ENTER;
    if (!SupportKey(key)) {
        FI_HILOGE("Unsupported key code:%{private}d", key);
        return RET_ERR;
    }

    SendEvent(EV_MSC, MSC_SCAN, OBFUSCATED);
    SendEvent(EV_KEY, key, DOWN_VALUE);
    SendEvent(EV_SYN, SYN_REPORT, SYNC_VALUE);
    return RET_OK;
}

int32_t VirtualKeyboard::Up(int32_t key)
{
    CALL_DEBUG_ENTER;
    if (!SupportKey(key)) {
        FI_HILOGE("Unsupported key code:%{private}d", key);
        return RET_ERR;
    }

    SendEvent(EV_MSC, MSC_SCAN, OBFUSCATED);
    SendEvent(EV_KEY, key, UP_VALUE);
    SendEvent(EV_SYN, SYN_REPORT, SYNC_VALUE);
    return RET_OK;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS