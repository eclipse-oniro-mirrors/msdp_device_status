/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef DRAG_TEST_COMMON_H
#define DRAG_TEST_COMMON_H

#include <gtest/gtest.h>
#include <functional>
#include <memory>
#include <future>
#include <map>
#include <string>
#include <thread>
#include <chrono>

#include "ddm_adapter.h"
#include "drag_client.h"
#include "drag_data_manager.h"
#include "drag_data_util.h"
#include "drag_manager.h"
#include "i_context.h"
#include "test_context.h"
#include "timer_manager.h"
#include "drag_security_manager.h"
#include "interaction_manager.h"
#include "pointer_event.h"
#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "message_parcel.h"
#include "securec.h"
#include "stationary_data.h"

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#include "parameters.h"
#endif // OHOS_BUILD_ENABLE_ARKUI_X

#define BUFF_SIZE 100

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;

namespace {
#ifdef OHOS_BUILD_INTERNAL_DROP_ANIMATION
constexpr int32_t TIME_WAIT_FOR_INTERNAL_DROP_ANIMATION { 500 };
#endif // OHOS_BUILD_INTERNAL_DROP_ANIMATION
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
constexpr int32_t PIXEL_MAP_HEIGHT { 3 };
constexpr int32_t PIXEL_MAP_WIDTH { 3 };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr int32_t POINTER_ID { 0 };
constexpr int32_t DISPLAY_X { 50 };
constexpr int32_t DISPLAY_ID { 0 };
constexpr int32_t DISPLAY_Y { 50 };
constexpr int32_t DRAG_NUM_ONE { 1 };
constexpr int32_t INT32_BYTE { 4 };
constexpr int32_t PROMISE_WAIT_SPAN_MS { 2000 };
constexpr int32_t FOREGROUND_COLOR_IN { 0x33FF0000 };
constexpr int32_t FOREGROUND_COLOR_OUT { 0x00000000 };
int32_t g_shadowinfo_x { 0 };
int32_t g_shadowinfo_y { 0 };
constexpr int32_t ANIMATION_DURATION { 500 };
const std::string CURVE_NAME { "cubic-bezier" };
constexpr bool HAS_CUSTOM_ANIMATION { true };
constexpr int32_t TARGET_MAIN_WINDOW { 0 };
constexpr bool HAS_CANCELED_ANIMATION { true };
const std::string UD_KEY { "Unified data key" };
const std::string FILTER_INFO { "Undefined filter info" };
const std::string EXTRA_INFO { "Undefined extra info" };
constexpr int32_t SHADOW_NUM_ONE { 1 };
uint64_t g_timestamp { 10000000 };
double g_coordinateX { 1.11 };
double g_coordinateY { 1.11 };
const std::string SIGNATURE { "signature" };
constexpr int32_t SECURITY_PID { 1 };
DragManager g_dragMgr;
IContext *g_context { nullptr };
} // namespace

class DragTestHelper {
public:
    static std::shared_ptr<Media::PixelMap> CreatePixelMap(int32_t width, int32_t height);
    static std::optional<DragData> CreateDragData(int32_t sourceType,
        int32_t pointerId, int32_t dragNum, bool hasCoordinateCorrected, int32_t shadowNum);
    static void AssignToAnimation(PreviewAnimation &animation);
};

class TestStartDragListener : public IStartDragListener {
public:
    explicit TestStartDragListener(std::function<void(const DragNotifyMsg&)> function) : function_(function) { }
    void OnDragEndMessage(const DragNotifyMsg &msg) override;
    void OnHideIconMessage() override;
private:
    std::function<void(const DragNotifyMsg&)> function_;
};

class DragListenerTest : public IDragListener {
public:
    DragListenerTest() {}
    explicit DragListenerTest(const std::string& name) : moduleName_(name) {}
    void OnDragMessage(DragState state) override;
private:
    std::string PrintDragMessage(DragState state);
    std::string moduleName_;
};

class SubscriptListenerTest : public ISubscriptListener {
public:
    SubscriptListenerTest() {}
    explicit SubscriptListenerTest(const std::string& name) : moduleName_(name) {}
    void OnMessage(DragCursorStyle style) override;
    DragCursorStyle GetDragStyle();
private:
    void SetDragSyle(DragCursorStyle style);
    std::string PrintStyleMessage(DragCursorStyle style);
    DragCursorStyle dragStyle_ { DragCursorStyle::DEFAULT };
    std::string moduleName_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DRAG_TEST_COMMON_H