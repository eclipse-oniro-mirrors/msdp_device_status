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

#include <future>
#include <memory>
#include <optional>
#include <utility>
#include <vector>
#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <cstdint>

#include "devicestatus_define.h"
#include "input_event_interceptor.h"
#include "input_event_sampler.h"

#undef LOG_TAG
#define LOG_TAG "InputEventSamplerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
constexpr int32_t MOVE_INCREMENT = 5;
} // namespace

class InputEventSamplerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase();
    static std::shared_ptr<MMI::PointerEvent> CreateTouchPadEvent();
    static std::shared_ptr<MMI::PointerEvent> CreateMouseMoveEvent(int32_t rawDx = 0, int32_t rawDy = 0);
    static std::shared_ptr<MMI::PointerEvent> CreateMouseButtonEvent(uint32_t buttonId, int32_t action);
};

void InputEventSamplerTest::SetUpTestCase() {}

void InputEventSamplerTest::TearDownTestCase() {}

void InputEventSamplerTest::SetUp() {}

void InputEventSamplerTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

std::shared_ptr<MMI::PointerEvent> InputEventSamplerTest::CreateTouchPadEvent()
{
    auto pointerEvent = MMI::PointerEvent::Create();
    if (pointerEvent == nullptr) {
        return nullptr;
    }
    
    MMI::PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(pointerEvent->GetPointerId());
    pointerItem.SetToolType(MMI::PointerEvent::TOOL_TYPE_TOUCHPAD);
    pointerItem.SetRawDx(MOVE_INCREMENT);
    pointerItem.SetRawDy(MOVE_INCREMENT);
    pointerEvent->AddPointerItem(pointerItem);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    
    return pointerEvent;
}

std::shared_ptr<MMI::PointerEvent> InputEventSamplerTest::CreateMouseMoveEvent(int32_t rawDx, int32_t rawDy)
{
    auto pointerEvent = MMI::PointerEvent::Create();
    if (pointerEvent == nullptr) {
        return nullptr;
    }
    
    MMI::PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(pointerEvent->GetPointerId());
    pointerItem.SetToolType(MMI::PointerEvent::TOOL_TYPE_MOUSE);
    pointerItem.SetRawDx(rawDx);
    pointerItem.SetRawDy(rawDy);
    pointerEvent->AddPointerItem(pointerItem);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    
    return pointerEvent;
}

std::shared_ptr<MMI::PointerEvent> InputEventSamplerTest::CreateMouseButtonEvent(uint32_t buttonId, int32_t action)
{
    auto pointerEvent = MMI::PointerEvent::Create();
    if (pointerEvent == nullptr) {
        return nullptr;
    }
    
    MMI::PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(pointerEvent->GetPointerId());
    pointerItem.SetToolType(MMI::PointerEvent::TOOL_TYPE_MOUSE);
    pointerItem.SetPressed(false);
    
    pointerEvent->AddPointerItem(pointerItem);
    pointerEvent->SetPointerAction(action);
    pointerEvent->SetButtonId(buttonId);
    
    return pointerEvent;
}

/**
 * @tc.name: TestIsTouchPadEvent_03
 * @tc.desc: Test IsTouchPadEvent with touchpad tool type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsTouchPadEvent_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = CreateTouchPadEvent();
    ASSERT_NE(pointerEvent, nullptr);
    Cooperate::InputEventSampler sampler;
    bool ret = sampler.IsTouchPadEvent(pointerEvent);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: TestIsDurationMatched_02
 * @tc.desc: Test IsDurationMatched basic call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsDurationMatched_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    bool ret = sampler.IsDurationMatched();
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsOffsetMatched_05
 * @tc.desc: Test IsOffsetMatched with horizontal movement
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsOffsetMatched_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto event = CreateMouseMoveEvent(5, 0);
    ASSERT_NE(event, nullptr);
    bool ret = sampler.IsOffsetMatched(event);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsOffsetMatched_06
 * @tc.desc: Test IsOffsetMatched with vertical movement
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsOffsetMatched_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto event = CreateMouseMoveEvent(0, 5);
    ASSERT_NE(event, nullptr);
    bool ret = sampler.IsOffsetMatched(event);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsRawEventsExpired_03
 * @tc.desc: Test IsRawEventsExpired method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsRawEventsExpired_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto event = CreateMouseMoveEvent(1, 1);
    ASSERT_NE(event, nullptr);
    sampler.OnPointerEvent(event);
    bool ret = sampler.IsRawEventsExpired();
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestSetPointerEventHandler_01
 * @tc.desc: Test SetPointerEventHandler callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestSetPointerEventHandler_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    std::atomic<bool> callbackCalled{false};
    std::shared_ptr<MMI::PointerEvent> receivedEvent = nullptr;
    
    sampler.SetPointerEventHandler([&callbackCalled, &receivedEvent](std::shared_ptr<MMI::PointerEvent> event) {
        callbackCalled.store(true);
        receivedEvent = event;
        FI_HILOGD("PointerEventHandler called");
    });
    
    auto pointerEvent = CreateMouseButtonEvent(1, MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ASSERT_NE(pointerEvent, nullptr);
    sampler.OnPointerEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ASSERT_TRUE(callbackCalled.load());
    ASSERT_NE(receivedEvent, nullptr);
    ASSERT_EQ(receivedEvent->GetButtonId(), 1);
    ASSERT_EQ(receivedEvent->GetPointerAction(), MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
}

/**
 * @tc.name: TestClearRawEvents_01
 * @tc.desc: Test ClearRawEvents function indirectly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestClearRawEvents_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    
    for (int32_t i = 0; i < 3; ++i) {
        auto pointerEvent = CreateMouseMoveEvent(i, i);
        ASSERT_NE(pointerEvent, nullptr);
        sampler.OnPointerEvent(pointerEvent);
    }
    bool expired = sampler.IsRawEventsExpired();
    ASSERT_EQ(expired, false);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto newEvent = CreateMouseMoveEvent(10, 10);
    ASSERT_NE(newEvent, nullptr);
    sampler.OnPointerEvent(newEvent);
    expired = sampler.IsRawEventsExpired();
    ASSERT_EQ(expired, false);
}

/**
 * @tc.name: TestOnPointerEventWithExpiredEvents_01
 * @tc.desc: Test OnPointerEvent when raw events are expired
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestOnPointerEventWithExpiredEvents_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    std::atomic<int> callbackCount{0};
    
    sampler.SetPointerEventHandler([&callbackCount](std::shared_ptr<MMI::PointerEvent> event) {
        callbackCount++;
        FI_HILOGD("Event processed, count: %d", callbackCount.load());
    });
    
    auto pointerEvent = CreateMouseMoveEvent(1, 1);
    ASSERT_NE(pointerEvent, nullptr);
    sampler.OnPointerEvent(pointerEvent);
    ASSERT_GT(callbackCount.load(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto newPointerEvent = CreateMouseMoveEvent(2, 2);
    ASSERT_NE(newPointerEvent, nullptr);
    sampler.OnPointerEvent(newPointerEvent);
    ASSERT_GT(callbackCount.load(), 1);
}

/**
 * @tc.name: TestHandleMouseEventWithOffsetMatched_01
 * @tc.desc: Test HandleMouseEvent when offset is matched
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestHandleMouseEventWithOffsetMatched_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    std::atomic<int> callbackCount{0};
    
    sampler.SetPointerEventHandler([&callbackCount](std::shared_ptr<MMI::PointerEvent> event) {
        callbackCount++;
        FI_HILOGD("Aggregated event dispatched, count: %d", callbackCount.load());
    });

    for (int32_t i = 0; i < 10; ++i) {
        auto pointerEvent = CreateMouseMoveEvent(2, 2);
        ASSERT_NE(pointerEvent, nullptr);
        sampler.OnPointerEvent(pointerEvent);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    int count = callbackCount.load();
    ASSERT_GT(count, 0);
    ASSERT_LE(count, 5);
}

/**
 * @tc.name: TestIsAggregationIntervalMatched_02
 * @tc.desc: Test IsAggregationIntervalMatched when interval is matched
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsAggregationIntervalMatched_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    bool ret = sampler.IsAggregationIntervalMatched();
    ASSERT_EQ(ret, true);
    auto pointerEvent = CreateMouseMoveEvent(1, 1);
    ASSERT_NE(pointerEvent, nullptr);
    sampler.OnPointerEvent(pointerEvent);
    ret = sampler.IsAggregationIntervalMatched();
    ASSERT_EQ(ret, false);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ret = sampler.IsAggregationIntervalMatched();
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: TestAggregateRawEventsWithValidItem_01
 * @tc.desc: Test event aggregation functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestAggregateRawEventsWithValidItem_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    std::atomic<bool> callbackCalled{false};
    
    sampler.SetPointerEventHandler([&callbackCalled](std::shared_ptr<MMI::PointerEvent> event) {
        callbackCalled.store(true);
        FI_HILOGD("Aggregated event dispatched");
    });
    
    for (int32_t i = 0; i < 10; ++i) {
        auto pointerEvent = CreateMouseMoveEvent(2, 2);
        ASSERT_NE(pointerEvent, nullptr);
        sampler.OnPointerEvent(pointerEvent);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT_TRUE(callbackCalled.load());
}

/**
 * @tc.name: TestIsSpecialEvent_01
 * @tc.desc: Test IsSpecialEvent with button events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsSpecialEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    std::atomic<int> callbackCount{0};
    sampler.SetPointerEventHandler([&callbackCount](std::shared_ptr<MMI::PointerEvent> event) {
        callbackCount++;
        FI_HILOGD("Special event processed, count: %d", callbackCount.load());
    });
    auto buttonDownEvent = CreateMouseButtonEvent(1, MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ASSERT_NE(buttonDownEvent, nullptr);
    sampler.OnPointerEvent(buttonDownEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ASSERT_GT(callbackCount.load(), 0);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
