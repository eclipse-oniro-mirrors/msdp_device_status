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

#ifndef INTERACTION_MANAGER_TEST_H
#define INTERACTION_MANAGER_TEST_H

#include <gtest/gtest.h>

#include "devicestatus_define.h"
#include "interaction_manager.h"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class MockHapToken {
public:
    explicit MockHapToken(
        const std::string& bundle, const std::vector<std::string>& reqPerm, bool isSystemApp = true);
    ~MockHapToken();
private:
    uint64_t selfToken_;
    uint32_t mockToken_;
};

class MockNativeToken {
public:
    explicit MockNativeToken(const std::string& process);
    ~MockNativeToken();
private:
    uint64_t selfToken_;
};

class InteractionManagerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static std::vector<int32_t> GetInputDeviceIds();
    static std::shared_ptr<MMI::InputDevice> GetDevice(int32_t deviceId);
    static std::pair<int32_t, int32_t> GetMouseAndTouch();
    static std::shared_ptr<Media::PixelMap> CreatePixelMap(int32_t width, int32_t height);
    static std::optional<DragData> CreateDragData(const std::pair<int32_t, int32_t> &pixelMapSize, int32_t sourceType,
        int32_t pointerId, int32_t displayId, const std::pair<int32_t, int32_t> &location);
    static MMI::PointerEvent::PointerItem CreatePointerItem(int32_t pointerId,
        int32_t deviceId, const std::pair<int32_t, int32_t> &displayLocation, bool isPressed);
    static std::shared_ptr<MMI::PointerEvent> SetupPointerEvent(const std::pair<int32_t, int32_t> &displayLocation,
        int32_t action, int32_t sourceType, int32_t pointerId, bool isPressed);
    static void SimulateDownPointerEvent(
        const std::pair<int32_t, int32_t> &location, int32_t sourceType, int32_t pointerId);
    static void SimulateUpPointerEvent(
        const std::pair<int32_t, int32_t> &location, int32_t sourceType, int32_t pointerId);
    static void SimulateMovePointerEvent(const std::pair<int32_t, int32_t> &srcLocation,
        const std::pair<int32_t, int32_t> &dstLocation, int32_t sourceType, int32_t pointerId, bool isPressed);
    static int32_t TestAddMonitor(std::shared_ptr<MMI::IInputEventConsumer> consumer);
    static void TestRemoveMonitor(int32_t monitorId);
    static void PrintDragData(const DragData &dragData);
    static void SetupKeyEvent(int32_t action, int32_t key, bool isPressed);
    static void ClearUpKeyEvent();
    static void SimulateDownKeyEvent(int32_t key);
    static void SimulateUpKeyEvent(int32_t key);
    static void PrintDragAction(DragAction dragAction);
    static void AssignToAnimation(PreviewAnimation &animation);
    static void EnableCooperate();
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INTERACTION_MANAGER_TEST_H