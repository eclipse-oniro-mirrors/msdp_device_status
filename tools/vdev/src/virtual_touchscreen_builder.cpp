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

#include "virtual_touchscreen_builder.h"

#include <fstream>
#include <iostream>
#include <unordered_map>

#include <getopt.h>
#include <linux/input.h>

#include "input_manager.h"

#include "devicestatus_define.h"
#include "display_manager.h"
#include "fi_log.h"
#include "utility.h"
#include "virtual_touchscreen.h"

#undef LOG_TAG
#define LOG_TAG "VirtualTouchScreenBuilder"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t MAXIMUM_LEVEL_ALLOWED { 3 };
int32_t g_absMaxWidth { 720 };
int32_t g_absMaxHeight { 1280 };
constexpr int32_t ABS_PRESSURE_MAX { 100 };
constexpr int32_t ABS_MT_ORIENTATION_MIN { -90 };
constexpr int32_t ABS_MT_ORIENTATION_MAX { 90 };
constexpr int32_t ABS_MT_BLOB_ID_MAX { 10 };
constexpr int32_t ABS_MT_TRACKING_ID_MAX { 9 };
constexpr int32_t ABS_TOOL_TYPE_MAX { 15 };
constexpr int32_t SY_OFFSET { 1 };
constexpr int32_t TX_OFFSET { 2 };
constexpr int32_t TY_OFFSET { 3 };
constexpr uint32_t IO_FLAG_WIDTH { 6 };
constexpr int32_t DEFAULT_VALUE_MINUS_ONE { -1 };
constexpr int32_t DEFAULT_VALUE_ZERO { 0 };
} // namespace

class PointerEventMonitor final : public MMI::IInputEventConsumer {
public:
    PointerEventMonitor() = default;
    ~PointerEventMonitor() = default;

    void OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const override {};
    void OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const override;
    void OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const override {};
};

void PointerEventMonitor::OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
    CHKPV(pointerEvent);
    if (pointerEvent->GetSourceType() != MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return;
    }
    MMI::PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem)) {
        return;
    }
    std::cout << "\rcurrent touch position - x: " << std::setw(IO_FLAG_WIDTH) << std::left
        << pointerItem.GetDisplayX() << "y: " << pointerItem.GetDisplayY() << "            ";
    std::cout.flush();
}

VirtualTouchScreenBuilder::VirtualTouchScreenBuilder() : VirtualDeviceBuilder(GetDeviceName(), BUS_USB, 0x6006, 0x6006)
{
#ifndef OHOS_BUILD_PC_PRODUCT
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
#else
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayById(0);
#endif // OHOS_BUILD_PC_PRODUCT
    CHKPV(display);
    g_absMaxWidth = display->GetWidth();
    g_absMaxHeight = display->GetHeight();
    AbsInfo absInfos[] { { ABS_X, 0, g_absMaxWidth, 0, 0 },
    { ABS_Y, 0, g_absMaxHeight, 0, 0 },
    { ABS_PRESSURE, 0, ABS_PRESSURE_MAX, 0, 0 },
    { ABS_MT_TOUCH_MAJOR, 0, 1, 0, 0 },
    { ABS_MT_TOUCH_MINOR, 0, 1, 0, 0 },
    { ABS_MT_ORIENTATION, ABS_MT_ORIENTATION_MIN, ABS_MT_ORIENTATION_MAX, 0, 0 },
    { ABS_MT_POSITION_X, 0, g_absMaxWidth, 0, 0 },
    { ABS_MT_POSITION_Y, 0, g_absMaxHeight, 0, 0 },
    { ABS_MT_BLOB_ID, 0, ABS_MT_BLOB_ID_MAX, 0, 0 },
    { ABS_MT_TRACKING_ID, 0, ABS_MT_TRACKING_ID_MAX, 0, 0 },
    { ABS_MT_PRESSURE, 0, ABS_PRESSURE_MAX, 0, 0 },
    { ABS_MT_TOOL_TYPE, 0, ABS_TOOL_TYPE_MAX, 0, 0 },
    { ABS_MT_WIDTH_MAJOR, 0, 1, 0, 0 },
    { ABS_MT_WIDTH_MINOR, 0, 1, 0, 0 },
    { ABS_MT_TOOL_X, 0, g_absMaxWidth, 0, 0 },
    { ABS_MT_TOOL_Y, 0, 1, 0, 0 } };

    eventTypes_ = { EV_ABS, EV_KEY };
    properties_ = { INPUT_PROP_DIRECT };
    keys_ = { BTN_TOUCH, BTN_TOOL_RUBBER, BTN_TOOL_BRUSH, BTN_TOOL_PENCIL, BTN_TOOL_AIRBRUSH,
            BTN_TOOL_FINGER, BTN_TOOL_MOUSE, BTN_TOOL_LENS };
    abs_ = { ABS_X, ABS_Y, ABS_PRESSURE, ABS_MT_TOUCH_MAJOR, ABS_MT_TOUCH_MINOR, ABS_MT_ORIENTATION,
            ABS_MT_POSITION_X, ABS_MT_POSITION_Y, ABS_MT_BLOB_ID, ABS_MT_TRACKING_ID, ABS_MT_PRESSURE,
            ABS_MT_WIDTH_MAJOR, ABS_MT_WIDTH_MINOR, ABS_MT_TOOL_X, ABS_MT_TOOL_Y, ABS_MT_TOOL_TYPE };
    for (const auto &item : absInfos) {
        SetAbsValue(item);
    }
}

std::string VirtualTouchScreenBuilder::GetDeviceName()
{
    return std::string("Virtual TouchScreen");
}

void VirtualTouchScreenBuilder::ShowUsage()
{
    std::cout << "Usage: vdevadm act -t T [-d<SLOT>  <x> <y>] [-u<SLOT>] [-m<SLOT> <dx> [<dy>]]" << std::endl;
    std::cout << "                        [-M<SLOT> <x> <y>] [-w <ms>] [-f <FILE>] [-r <FILE>] [-c]" << std::endl;
    std::cout << "      -d <SLOT> <x> <y>" << std::endl;
    std::cout << "                  Press donw on touch screen." << std::endl;
    std::cout << "                  The <SLOT> identify one touch and is in the range [0-9]." << std::endl;
    std::cout << "      -u <SLOT>   Lift up the touch <SLOT>." << std::endl;
    std::cout << "      -m <SLOT> <dx> [<dy>]" << std::endl;
    std::cout << "                  Move the touch <SLOT> along (dx, dy) for one step." << std::endl;
    std::cout << "      -M <SLOT> <x> <y>" << std::endl;
    std::cout << "                  Move the touch <SLOT> to (x, y)." << std::endl;
    std::cout << "      -D <SLOT> <sx> <sy> <tx> <ty> Drag the touch <SLOT> to (tx, ty)" << std::endl;
    std::cout << "      -w <ms>     Wait for <ms> milliseconds." << std::endl;
    std::cout << "      -f <FILE>   Read actions from <FILE>." << std::endl;
    std::cout << "      -r <FILE>   Read raw input data from <FILE>." << std::endl;
}

void VirtualTouchScreenBuilder::Mount()
{
    CALL_DEBUG_ENTER;
    std::cout << "Start to mount virtual touchscreen." << std::endl;
    if (VirtualTouchScreen::GetDevice() != nullptr) {
        std::cout << "Virtual touchscreen has been mounted." << std::endl;
        return;
    }
    VirtualTouchScreenBuilder vTouch;
    if (!vTouch.SetUp()) {
        std::cout << "Failed to mount virtual touchscreen." << std::endl;
        return;
    }

    int32_t nTries = 3;
    do {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    } while ((nTries-- > 0) && (VirtualTouchScreen::GetDevice() == nullptr));
    if (VirtualTouchScreen::GetDevice() == nullptr) {
        std::cout << "Failed to mount virtual touchscreen." << std::endl;
        return;
    }

    std::cout << "Mount virtual touchscreen successfully." << std::endl;
    VirtualDeviceBuilder::Daemonize();
    for (;;) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
    }
}

void VirtualTouchScreenBuilder::Unmount()
{
    CALL_DEBUG_ENTER;
    VirtualDeviceBuilder::Unmount("touchscreen", "T");
}

void VirtualTouchScreenBuilder::Clone()
{
    CALL_DEBUG_ENTER;
    if (VirtualTouchScreen::GetDevice() != nullptr) {
        std::cout << "Virtual touchscreen has been mounted" << std::endl;
        return;
    }

    std::vector<std::shared_ptr<VirtualDevice>> vDevs;
    int32_t ret = VirtualDeviceBuilder::ScanFor(
        [](std::shared_ptr<VirtualDevice> vDev) { return ((vDev != nullptr) && vDev->IsTouchscreen()); }, vDevs);
    if (ret != RET_OK) {
        std::cout << "Failed while scanning for touchscreen" << std::endl;
        return;
    }
    auto vDev = VirtualDeviceBuilder::Select(vDevs, "touchscreen");
    CHKPV(vDev);

    std::cout << "Cloning \'" << vDev->GetName() << "\'." << std::endl;
    VirtualDeviceBuilder vBuilder(GetDeviceName(), vDev);
    if (!vBuilder.SetUp()) {
        std::cout << "Failed to clone \' " << vDev->GetName() << " \'." << std::endl;
        return;
    }

    int32_t nTries = 3;
    do {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    } while ((nTries-- > 0) && (VirtualTouchScreen::GetDevice() == nullptr));
    if (VirtualTouchScreen::GetDevice() == nullptr) {
        std::cout << "Clone \' " << vDev->GetName() << " \' is unsuccessful." << std::endl;
        return;
    }

    std::cout << "Clone \'" << vDev->GetName() << "\' successfully" << std::endl;
    VirtualDeviceBuilder::Daemonize();
    for (;;) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
    }
}

void VirtualTouchScreenBuilder::Monitor()
{
    CALL_DEBUG_ENTER;
    MMI::InputManager* inputMgr = MMI::InputManager::GetInstance();
    CHKPV(inputMgr);
    auto monitor = std::make_shared<PointerEventMonitor>();
    int32_t monitorId = inputMgr->AddMonitor(monitor);
    if (monitorId < 0) {
        std::cout << "Failed to add monitor." << std::endl;
        return;
    }
    for (;;) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
    }
}

void VirtualTouchScreenBuilder::Act(int32_t argc, char *argv[])
{
    CALL_DEBUG_ENTER;
    int32_t opt = getopt(argc, argv, "d:u:m:M:f:r:w:D:");
    if (opt < 0) {
        std::cout << "Vdevadm act: required option is missing" << std::endl;
        ShowUsage();
        return;
    }
    if (VirtualTouchScreen::GetDevice() == nullptr) {
        std::cout << "No virtual touchscreen." << std::endl;
        return;
    }
    do {
        {
            auto action = ruleTscrnActions_.find(opt);
            if (action != ruleTscrnActions_.end()) {
                action->second();
                continue;
            }
        }
        {
            auto action = readTscrnActions_.find(opt);
            if (action != readTscrnActions_.end()) {
                action->second(optarg);
                continue;
            }
        }
        {
            auto action = moveTscrnActions_.find(opt);
            if (action != moveTscrnActions_.end()) {
                action->second(argc, argv);
                continue;
            }
        }
        if (opt == 'w') {
            VirtualDeviceBuilder::WaitFor(optarg, "touchscreen");
        } else {
            ShowUsage();
        }
    } while ((opt = getopt(argc, argv, "d:u:m:M:f:r:w:D:")) >= 0);
}

void VirtualTouchScreenBuilder::ReadDownAction(int32_t argc, char *argv[])
{
    CALL_DEBUG_ENTER;
    CHKPV(optarg);

    if (!Utility::IsInteger(optarg) || (optind < 0) || (optind + 1 >= argc) ||
        !Utility::IsInteger(argv[optind]) || !Utility::IsInteger(argv[optind + 1])) {
        std::cout << "Require arguments for Option \'-d\'." << std::endl;
        ShowUsage();
        return;
    }
    int32_t slot = std::atoi(optarg);
    int32_t x = std::atoi(argv[optind]);
    int32_t y = std::atoi(argv[optind + 1]);
    std::cout << "[touchscreen] down: [" << slot << ", (" << x << "," << y << ")]" << std::endl;
    VirtualTouchScreen::GetDevice()->DownButton(slot, x, y);
    while ((optind < argc) && Utility::IsInteger(argv[optind])) {
        optind++;
    }
}

void VirtualTouchScreenBuilder::ReadMoveAction(int32_t argc, char *argv[])
{
    CALL_DEBUG_ENTER;
    CHKPV(optarg);

    if (!Utility::IsInteger(optarg) || (optind < 0) || (optind + 1 >= argc) || !Utility::IsInteger(argv[optind])) {
        std::cout << "Invalid arguments for Option \'-m\'." << std::endl;
        ShowUsage();
        return;
    }
    int32_t slot = std::atoi(optarg);
    int32_t dx = std::atoi(argv[optind]);
    int32_t dy = 0;
    if ((optind + 1 < argc) && Utility::IsInteger(argv[optind + 1])) {
        dy = std::atoi(argv[optind + 1]);
    }
    std::cout << "[touchscreen] move: [" << slot << ", (" << dx << "," << dy << ")]" << std::endl;
    VirtualTouchScreen::GetDevice()->Move(slot, dx, dy);
    while ((optind < argc) && Utility::IsInteger(argv[optind])) {
        optind++;
    }
}

void VirtualTouchScreenBuilder::ReadUpAction()
{
    CALL_DEBUG_ENTER;
    CHKPV(optarg);
    if (!Utility::IsInteger(optarg)) {
        std::cout << "Invalid arguments for Option \'-u\'." << std::endl;
        ShowUsage();
        return;
    }
    int32_t slot = std::atoi(optarg);
    std::cout << "[touchscreen] release: [" << slot << "]" << std::endl;
    VirtualTouchScreen::GetDevice()->UpButton(slot);
}

void VirtualTouchScreenBuilder::ReadMoveToAction(int32_t argc, char *argv[])
{
    CALL_DEBUG_ENTER;
    CHKPV(optarg);

    if (!Utility::IsInteger(optarg) || (optind < 0) || (optind + 1 >= argc) || !Utility::IsInteger(argv[optind]) ||
        !Utility::IsInteger(argv[optind + 1])) {
        std::cout << "Invalid arguments for Option \'-M\'." << std::endl;
        ShowUsage();
        return;
    }
    int32_t slot = std::atoi(optarg);
    int32_t x = std::atoi(argv[optind]);
    int32_t y = std::atoi(argv[optind + 1]);
    std::cout << "[touchscreen] move-to: [" << slot << ", (" << x << "," << y << ")]" << std::endl;
    VirtualTouchScreen::GetDevice()->MoveTo(slot, x, y);
    while ((optind < argc) && Utility::IsInteger(argv[optind])) {
        optind++;
    }
}

void VirtualTouchScreenBuilder::ReadDragToAction(int32_t argc, char *argv[])
{
    CALL_DEBUG_ENTER;
    CHKPV(optarg);
    if (!Utility::IsInteger(optarg) || (optind < 0) || (optind + TY_OFFSET >= argc) ||
        !Utility::IsInteger(argv[optind]) || !Utility::IsInteger(argv[optind + SY_OFFSET]) ||
        !Utility::IsInteger(argv[optind + TX_OFFSET]) || !Utility::IsInteger(argv[optind + TY_OFFSET])) {
        std::cout << "Invalid arguments for Option \'-D\'." << std::endl;
        ShowUsage();
        return;
    }

    int32_t slot = std::atoi(optarg);
    int32_t sx = std::atoi(argv[optind]);
    int32_t sy = std::atoi(argv[optind + SY_OFFSET]);
    int32_t tx = std::atoi(argv[optind + TX_OFFSET]);
    int32_t ty = std::atoi(argv[optind + TY_OFFSET]);

    std::cout << "[touchscreen] drag-to: [" << slot << ", (" << tx << "," << ty << ")]" << std::endl;
    auto vTouch = VirtualTouchScreen::GetDevice();
    vTouch->DownButton(slot, sx, sy);
    VirtualDeviceBuilder::WaitFor("touchscreen", SLEEP_TIME);
    vTouch->MoveTo(slot, tx, ty);
    vTouch->UpButton(slot);
    while ((optind < argc) && Utility::IsInteger(argv[optind])) {
        optind++;
    }
}

void VirtualTouchScreenBuilder::ReadActions(const char *path)
{
    CALL_DEBUG_ENTER;
    json model;
    int32_t ret = VirtualDeviceBuilder::ReadFile(path, model);
    if (ret == RET_ERR) {
        FI_HILOGE("Failed to read touchscreen data from the files");
        return;
    }
    ReadModel(model, MAXIMUM_LEVEL_ALLOWED);
}

void VirtualTouchScreenBuilder::ReadModel(const nlohmann::json &model, int32_t level)
{
    CALL_DEBUG_ENTER;
    if (model.is_object()) {
        auto it = model.find("actions");
        if (it != model.cend() && it->is_array()) {
            std::for_each(it->cbegin(), it->cend(), [](const auto &item) { ReadAction(item); });
        }
    } else if (model.is_array() && level > 0) {
        for (const auto &m : model) {
            ReadModel(m, level - 1);
        }
    }
}

void VirtualTouchScreenBuilder::ReadAction(const nlohmann::json &model)
{
    CALL_DEBUG_ENTER;
    if (!model.is_object()) {
        FI_HILOGD("Not an object");
        return;
    }
    auto it = model.find("action");
    if (it != model.cend()) {
        static const std::unordered_map<std::string, std::function<void(const nlohmann::json &model)>> actions {
            { "down", &HandleDown },
            { "move", &HandleMove },
            { "up", &HandleUp },
            { "move-to", &HandleMoveTo },
            { "wait", &HandleWait }
        };
        auto actionItr = actions.find(it.value());
        if (actionItr != actions.cend()) {
            actionItr->second(model);
        }
    }
}

int32_t VirtualTouchScreenBuilder::GetModelValue(const nlohmann::json &model, const std::string &targetName,
    int32_t defaultValue)
{
    auto it = model.find(targetName);
    if (it != model.cend() && it->is_number_integer()) {
        return it.value();
    }
    return defaultValue;
}

void VirtualTouchScreenBuilder::HandleDown(const nlohmann::json &model)
{
    int32_t slot = VirtualTouchScreenBuilder::GetModelValue(model, "slot", DEFAULT_VALUE_MINUS_ONE);

    int32_t x = VirtualTouchScreenBuilder::GetModelValue(model, "x", DEFAULT_VALUE_MINUS_ONE);

    int32_t y = VirtualTouchScreenBuilder::GetModelValue(model, "y", DEFAULT_VALUE_MINUS_ONE);

    std::cout << "[touchscreen] down: [" << slot << ", (" << x << "," << y << ")]" << std::endl;
    VirtualTouchScreen::GetDevice()->DownButton(slot, x, y);
}

void VirtualTouchScreenBuilder::HandleMove(const nlohmann::json &model)
{
    int32_t slot = VirtualTouchScreenBuilder::GetModelValue(model, "slot", DEFAULT_VALUE_MINUS_ONE);

    int32_t dx = VirtualTouchScreenBuilder::GetModelValue(model, "dx", DEFAULT_VALUE_ZERO);

    int32_t dy = VirtualTouchScreenBuilder::GetModelValue(model, "dy", DEFAULT_VALUE_ZERO);

    std::cout << "[touchscreen] move: [" << slot << ", (" << dx << "," << dy << ")]" << std::endl;
    VirtualTouchScreen::GetDevice()->Move(slot, dx, dy);
}

void VirtualTouchScreenBuilder::HandleUp(const nlohmann::json &model)
{
    int32_t slot = VirtualTouchScreenBuilder::GetModelValue(model, "slot", DEFAULT_VALUE_MINUS_ONE);

    std::cout << "[touchscreen] release: [" << slot << "]" << std::endl;
    VirtualTouchScreen::GetDevice()->UpButton(slot);
}

void VirtualTouchScreenBuilder::HandleMoveTo(const nlohmann::json &model)
{
    int32_t slot = VirtualTouchScreenBuilder::GetModelValue(model, "slot", DEFAULT_VALUE_MINUS_ONE);

    int32_t x = VirtualTouchScreenBuilder::GetModelValue(model, "x", DEFAULT_VALUE_MINUS_ONE);

    int32_t y = VirtualTouchScreenBuilder::GetModelValue(model, "y", DEFAULT_VALUE_MINUS_ONE);

    std::cout << "[touchscreen] move-to: [" << slot << ", (" << x << "," << y << ")]" << std::endl;
    VirtualTouchScreen::GetDevice()->MoveTo(slot, x, y);
}

void VirtualTouchScreenBuilder::HandleWait(const nlohmann::json &model)
{
    CALL_DEBUG_ENTER;
    auto it = model.find("duration");
    if (it != model.cend() && it->is_number_integer()) {
        int32_t waitTime = it.value();
        VirtualDeviceBuilder::WaitFor("touchscreen", waitTime);
    }
}

void VirtualTouchScreenBuilder::ReadRawInput(const char *path)
{
    CALL_DEBUG_ENTER;
    json model;
    int32_t ret = VirtualDeviceBuilder::ReadFile(path, model);
    if (ret == RET_ERR) {
        FI_HILOGE("Failed to read the raw touchscreen data");
        return;
    }
    ReadRawModel(model, MAXIMUM_LEVEL_ALLOWED);
}

void VirtualTouchScreenBuilder::ReadRawModel(const nlohmann::json &model, int32_t level)
{
    CALL_DEBUG_ENTER;
    if (model.is_object()) {
        auto it = model.find("type");
        if (it == model.cend() || !it->is_string() || (std::string(it.value()).compare("raw") != 0)) {
            std::cout << "Expect raw input data." << std::endl;
            return;
        }
        it = model.find("actions");
        if (it != model.cend() && it->is_array()) {
            std::for_each(it->cbegin(), it->cend(), [](const auto &item) { ReadRawData(item); });
        }
    } else if (model.is_array() && level > 0) {
        for (const auto &m : model) {
            ReadRawModel(m, level - 1);
        }
    }
}

void VirtualTouchScreenBuilder::ReadRawData(const nlohmann::json &model)
{
    CALL_DEBUG_ENTER;
    if (!model.is_object()) {
        FI_HILOGD("Not an object");
        return;
    }
    auto typeIter = model.find("type");
    if (typeIter == model.cend() || !typeIter->is_number_integer()) {
        return;
    }
    auto codeIter = model.find("code");
    if (codeIter == model.cend() || !codeIter->is_number_integer()) {
        return;
    }
    auto valueIter = model.find("value");
    if (valueIter == model.cend() || !valueIter->is_number_integer()) {
        return;
    }
    std::cout << "[touchscreen] raw input: [" << typeIter.value() << ", " << codeIter.value() << ", " <<
        valueIter.value() << "]" << std::endl;
    VirtualTouchScreen::GetDevice()->SendEvent(typeIter.value(), codeIter.value(), valueIter.value());
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS