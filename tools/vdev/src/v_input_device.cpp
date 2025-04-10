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

#include "v_input_device.h"

#include <fcntl.h>
#include <securec.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "fi_log.h"
#include "napi_constants.h"
#include "utility.h"
#include "virtual_device_defines.h"

#undef LOG_TAG
#define LOG_TAG "VInputDevice"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
struct Range {
    size_t start = 0;
    size_t end = 0;
};

namespace {
const struct Range KEY_BLOCKS[] { { KEY_ESC, BTN_MISC },
    { KEY_OK, BTN_DPAD_UP },
    { KEY_ALS_TOGGLE, BTN_TRIGGER_HAPPY } };
constexpr uint64_t DOMAIN_ID { 0xD002220 };
} // namespace

VInputDevice::VInputDevice(const std::string &node) : devPath_(node) {}

VInputDevice::~VInputDevice()
{
    Close();
}

int32_t VInputDevice::Open()
{
    CALL_DEBUG_ENTER;
    char buf[PATH_MAX] {};
    if (realpath(devPath_.c_str(), buf) == nullptr) {
        FI_HILOGE("Not real path:%{private}s", devPath_.c_str());
        return RET_ERR;
    }

    int32_t nRetries = 6;
    for (;;) {
        Utility::ShowUserAndGroup();
        Utility::ShowFileAttributes(buf);
        fd_ = open(buf, O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (fd_ < 0) {
            FI_HILOGE("Unable to open device \'%{public}s\':%{public}s", buf, strerror(errno));
            if (nRetries-- > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
                FI_HILOGI("Retry opening device \'%{public}s\'", buf);
            } else {
                return RET_ERR;
            }
        } else {
            FI_HILOGD("Opening \'%{public}s\' successfully", buf);
            break;
        }
        fdsan_exchange_owner_tag(fd_, 0, DOMAIN_ID);
    }
    QueryDeviceInfo();
    QuerySupportedEvents();
    UpdateCapability();
    return RET_OK;
}

void VInputDevice::Close()
{
    CALL_DEBUG_ENTER;
    if (fd_ >= 0) {
        fdsan_close_with_tag(fd_, DOMAIN_ID);
        fd_ = -1;
    }
}

bool VInputDevice::QueryAbsInfo(size_t abs, struct input_absinfo &absInfo)
{
    CALL_DEBUG_ENTER;
    errno_t ret = memset_s(&absInfo, sizeof(absInfo), 0, sizeof(absInfo));
    if (ret != EOK) {
        FI_HILOGE("Call memset_s failed");
        return false;
    }
    return (ioctl(fd_, EVIOCGABS(abs), &absInfo) >= 0);
}

int32_t VInputDevice::SendEvent(uint16_t type, uint16_t code, int32_t value)
{
    CALL_DEBUG_ENTER;
    if (!IsActive()) {
        FI_HILOGE("No active device");
        return RET_ERR;
    }
    struct input_event event {
        .type = type,
        .code = code,
        .value = value
    };
    struct timeval tv;
    if (gettimeofday(&tv, nullptr) != 0) {
        FI_HILOGE("Failed to get current time");
        return RET_ERR;
    }
    event.input_event_sec = tv.tv_sec;
    event.input_event_usec = tv.tv_usec;
    ssize_t ret = ::write(fd_, &event, sizeof(struct input_event));
    if (ret < 0) {
        FI_HILOGE("Failed to send event:%{public}s", strerror(errno));
        return RET_ERR;
    }
    return RET_OK;
}

void VInputDevice::QueryDeviceInfo()
{
    CALL_DEBUG_ENTER;
    char buffer[PATH_MAX] { 0 };

    int32_t rc = ioctl(fd_, EVIOCGNAME(sizeof(buffer) - 1), &buffer);
    if (rc < 0) {
        FI_HILOGE("Could not get device name:%{public}s", strerror(errno));
    } else {
        name_.assign(buffer);
    }

    rc = ioctl(fd_, EVIOCGID, &inputId_);
    if (rc < 0) {
        FI_HILOGE("Couldn't not get device input id:%{public}s", strerror(errno));
    }
    errno_t ret = memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    if (ret != EOK) {
        FI_HILOGE("Call memset_s was a failure");
        return;
    }
    rc = ioctl(fd_, EVIOCGPHYS(sizeof(buffer) - 1), &buffer);
    if (rc < 0) {
        FI_HILOGE("Couldn't get location:%{public}s", strerror(errno));
    } else {
        phys_.assign(buffer);
    }
    ret = memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    if (ret != EOK) {
        FI_HILOGE("Call memset_s was a failure");
        return;
    }
    rc = ioctl(fd_, EVIOCGUNIQ(sizeof(buffer) - 1), &buffer);
    if (rc < 0) {
        FI_HILOGE("Could not get uniq:%{public}s", strerror(errno));
    } else {
        uniq_.assign(buffer);
    }
}

void VInputDevice::GetEventMask(const std::string &eventName, uint32_t type,
    std::size_t arrayLength, uint8_t *whichBitMask) const
{
    int32_t rc = ioctl(fd_, EVIOCGBIT(type, arrayLength), whichBitMask);
    if (rc < 0) {
        FI_HILOGE("Could not get events %{public}s mask:%{public}s", eventName.c_str(), strerror(errno));
    }
}

void VInputDevice::GetPropMask(const std::string &eventName, std::size_t arrayLength, uint8_t *whichBitMask) const
{
    int32_t rc = ioctl(fd_, EVIOCGPROP(arrayLength), whichBitMask);
    if (rc < 0) {
        FI_HILOGE("Could not get %{public}s mask:%{public}s", eventName.c_str(), strerror(errno));
    }
}

void VInputDevice::QuerySupportedEvents()
{
    CALL_DEBUG_ENTER;
    // get events mask
    GetEventMask("", 0, sizeof(evBitmask_), evBitmask_);

    // get key events
    GetEventMask("key", EV_KEY, sizeof(keyBitmask_), keyBitmask_);

    // get abs events
    GetEventMask("abs", EV_ABS, sizeof(absBitmask_), absBitmask_);

    // get rel events
    GetEventMask("rel", EV_REL, sizeof(relBitmask_), relBitmask_);

    // get msc events
    GetEventMask("msc", EV_MSC, sizeof(mscBitmask_), mscBitmask_);

    // get led events
    GetEventMask("led", EV_LED, sizeof(ledBitmask_), ledBitmask_);

    // get rep events
    GetEventMask("rep", EV_REP, sizeof(repBitmask_), repBitmask_);

    // get properties mask
    GetPropMask("properties", sizeof(propBitmask_), propBitmask_);
}

void VInputDevice::UpdateCapability()
{
    CALL_DEBUG_ENTER;
    CheckPointers();
    CheckKeys();
}

bool VInputDevice::HasAxesOrButton(size_t start, size_t end, const uint8_t* whichBitMask) const
{
    for (size_t type = start; type < end; ++type) {
        if (TestBit(type, whichBitMask)) {
            return true;
        }
    }
    return false;
}

bool VInputDevice::HasJoystickAxesOrButtons() const
{
    if (!TestBit(BTN_JOYSTICK - 1, keyBitmask_)) {
        if (HasAxesOrButton(BTN_JOYSTICK, BTN_DIGI, keyBitmask_) ||
            // BTN_TRIGGER_HAPPY40 + 1 : Iteration limit
            HasAxesOrButton(BTN_TRIGGER_HAPPY1, BTN_TRIGGER_HAPPY40 + 1, keyBitmask_) ||
            HasAxesOrButton(BTN_DPAD_UP, BTN_DPAD_RIGHT + 1, keyBitmask_)) { // BTN_DPAD_RIGHT + 1 : Iteration limit
            return true;
        }
    }
    return HasAxesOrButton(ABS_RX, ABS_PRESSURE, absBitmask_);
}

void VInputDevice::PrintCapsDevice() const
{
    std::map<std::size_t, std::string> deviceComparisonTable {
        { DEVICE_CAP_KEYBOARD, "keyboard" },
        { DEVICE_CAP_TOUCH, "touch device" },
        { DEVICE_CAP_TABLET_TOOL, "tablet tool" },
        { DEVICE_CAP_POINTER, "pointer" },
        { DEVICE_CAP_TABLET_PAD, "pad" },
        { DEVICE_CAP_GESTURE, "gesture" },
        { DEVICE_CAP_SWITCH, "switch" },
        { DEVICE_CAP_JOYSTICK, "joystick" }
    };
    for (const auto& [cap, name] : deviceComparisonTable) {
        if (caps_.test(cap)) {
            FI_HILOGD("This is %{public}s", name.c_str());
        }
    }
}

bool VInputDevice::HasAbsCoord() const
{
    return HasAbs(ABS_X) && HasAbs(ABS_Y);
}

bool VInputDevice::HasMtCoord() const
{
    return HasAbs(ABS_MT_POSITION_X) && HasAbs(ABS_MT_POSITION_Y);
}

bool VInputDevice::HasRelCoord() const
{
    return HasRel(REL_X) && HasRel(REL_Y);
}

void VInputDevice::CheckAbs()
{
    if (HasKey(BTN_STYLUS) || HasKey(BTN_TOOL_PEN)) {
        caps_.set(DEVICE_CAP_TABLET_TOOL);
    } else if (HasKey(BTN_TOOL_FINGER) && !HasKey(BTN_TOOL_PEN) && !HasProperty(INPUT_PROP_DIRECT)) {
        caps_.set(DEVICE_CAP_POINTER);
    } else if (HasAxesOrButton(BTN_MOUSE, BTN_JOYSTICK, keyBitmask_)) {
        caps_.set(DEVICE_CAP_POINTER);
    } else if (HasKey(BTN_TOUCH) || HasProperty(INPUT_PROP_DIRECT)) {
        caps_.set(DEVICE_CAP_TOUCH);
    } else if (HasJoystickAxesOrButtons()) {
        caps_.set(DEVICE_CAP_JOYSTICK);
    }
}

void VInputDevice::CheckMt()
{
    if (HasKey(BTN_STYLUS) || HasKey(BTN_TOOL_PEN)) {
        caps_.set(DEVICE_CAP_TABLET_TOOL);
    } else if (HasKey(BTN_TOOL_FINGER) && !HasKey(BTN_TOOL_PEN) && !HasProperty(INPUT_PROP_DIRECT)) {
        caps_.set(DEVICE_CAP_POINTER);
    } else if (HasKey(BTN_TOUCH) || HasProperty(INPUT_PROP_DIRECT)) {
        caps_.set(DEVICE_CAP_TOUCH);
    }
}

void VInputDevice::CheckAdditional()
{
    if (!HasCapability(DEVICE_CAP_TABLET_TOOL) &&
        !HasCapability(DEVICE_CAP_POINTER) &&
        !HasCapability(DEVICE_CAP_JOYSTICK) &&
        HasAxesOrButton(BTN_MOUSE, BTN_JOYSTICK, keyBitmask_) && (HasRelCoord() || !HasAbsCoord())) {
        caps_.set(DEVICE_CAP_POINTER);
    }
}

void VInputDevice::CheckPointers()
{
    CALL_DEBUG_ENTER;
    if (HasAbsCoord()) {
        CheckAbs();
    } else if (HasJoystickAxesOrButtons()) {
        caps_.set(DEVICE_CAP_JOYSTICK);
    }
    if (HasMtCoord()) {
        CheckMt();
    }
    CheckAdditional();
    PrintCapsDevice();
}

void VInputDevice::CheckKeys()
{
    CALL_DEBUG_ENTER;
    if (!TestBit(EV_KEY, evBitmask_)) {
        FI_HILOGD("No EV_KEY capability");
        return;
    }
    for (size_t block = 0U; block < (sizeof(KEY_BLOCKS) / sizeof(struct Range)); ++block) {
        for (size_t key = KEY_BLOCKS[block].start; key < KEY_BLOCKS[block].end; ++key) {
            if (TestBit(key, keyBitmask_)) {
                FI_HILOGD("Found key %{public}zx", key);
                caps_.set(DEVICE_CAP_KEYBOARD);
                return;
            }
        }
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace