/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
constexpr int32_t TEMP_RAW { 10 };
constexpr int32_t TEMP_MIN_RAW { 0 };

// NetPacket pkt(MessageId::INVALID);
} // namespace

class InputEventSamplerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void InputEventSamplerTest::SetUpTestCase() {}

void InputEventSamplerTest::TearDownTestCase() {}

void InputEventSamplerTest::SetUp() {}

void InputEventSamplerTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: TestIsTouchPadEvent_01
 * @tc.desc: Test IsTouchPadEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsTouchPadEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    Cooperate::InputEventSampler sampler;
    int32_t ret = sampler.IsTouchPadEvent(pointerEvent);
    ASSERT_EQ(ret, false);
    pointerEvent = nullptr;
    ret = sampler.IsTouchPadEvent(pointerEvent);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsTouchPadEvent_02
 * @tc.desc: Test IsTouchPadEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsTouchPadEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    Cooperate::InputEventSampler sampler;
    int32_t ret = sampler.IsTouchPadEvent(pointerEvent);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsSpecialEvent_01
 * @tc.desc: Test IsSpecialEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsSpecialEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    Cooperate::InputEventSampler sampler;
    int32_t ret = sampler.IsSpecialEvent(pointerEvent);
    ASSERT_EQ(ret, true);
    pointerEvent = nullptr;
    ret = sampler.IsSpecialEvent(pointerEvent);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsSpecialEvent_02
 * @tc.desc: Test IsSpecialEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsSpecialEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    Cooperate::InputEventSampler sampler;
    int32_t ret = sampler.IsSpecialEvent(pointerEvent);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsDurationMatched_01
 * @tc.desc: Test IsDurationMatched
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsDurationMatched_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    int32_t ret = sampler.IsDurationMatched();
    ASSERT_EQ(ret, false);
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    sampler.rawEvents_.push({pointerEvent, std::chrono::steady_clock::now()});
    ret = sampler.IsDurationMatched();
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsOffsetMatched_01
 * @tc.desc: Test IsOffsetMatched
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsOffsetMatched_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    sampler.prefixRawDxSum_ = TEMP_RAW;
    sampler.prefixRawDySum_ = TEMP_RAW;
    sampler.rawDxThreshold_ = TEMP_MIN_RAW;
    sampler.rawDyThreshold_ = TEMP_MIN_RAW;
    int32_t ret = sampler.IsOffsetMatched(pointerEvent);
    ASSERT_EQ(ret, false);
    pointerEvent = nullptr;
    ret = sampler.IsOffsetMatched(pointerEvent);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsOffsetMatched_02
 * @tc.desc: Test IsOffsetMatched
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsOffsetMatched_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    sampler.prefixRawDxSum_ = TEMP_MIN_RAW;
    sampler.prefixRawDySum_ = TEMP_MIN_RAW;
    sampler.rawDxThreshold_ = TEMP_RAW;
    sampler.rawDyThreshold_ = TEMP_RAW;
    int32_t ret = sampler.IsOffsetMatched(pointerEvent);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsOffsetMatched_03
 * @tc.desc: Test IsOffsetMatched
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsOffsetMatched_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    sampler.prefixRawDxSum_ = TEMP_RAW;
    sampler.prefixRawDySum_ = TEMP_MIN_RAW;
    sampler.rawDxThreshold_ = TEMP_MIN_RAW;
    sampler.rawDyThreshold_ = TEMP_RAW;
    int32_t ret = sampler.IsOffsetMatched(pointerEvent);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsOffsetMatched_04
 * @tc.desc: Test IsOffsetMatched
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsOffsetMatched_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    sampler.prefixRawDxSum_ = TEMP_MIN_RAW;
    sampler.prefixRawDySum_ = TEMP_RAW;
    sampler.rawDxThreshold_ = TEMP_RAW;
    sampler.rawDyThreshold_ = TEMP_MIN_RAW;
    int32_t ret = sampler.IsOffsetMatched(pointerEvent);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsRawEventsExpired_01
 * @tc.desc: Test IsRawEventsExpired
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsRawEventsExpired_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    int32_t ret = sampler.IsRawEventsExpired();
    ASSERT_EQ(ret, false);
    auto pointerEvent = MMI::PointerEvent::Create();
    pointerEvent = nullptr;
    sampler.rawEvents_.push({pointerEvent, std::chrono::steady_clock::now()});
    ret = sampler.IsRawEventsExpired();
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsRawEventsExpired_02
 * @tc.desc: Test IsRawEventsExpired
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsRawEventsExpired_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    sampler.rawEvents_.push({pointerEvent, std::chrono::steady_clock::now()});
    int32_t ret = sampler.IsRawEventsExpired();
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestIsSkipNeeded_01
 * @tc.desc: Test IsSkipNeeded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsSkipNeeded_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_ENTER_WINDOW);
    int32_t ret = sampler.IsSkipNeeded(pointerEvent);
    ASSERT_EQ(ret, true);
    pointerEvent = nullptr;
    ret = sampler.IsSkipNeeded(pointerEvent);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: TestIsSkipNeeded_02
 * @tc.desc: Test IsSkipNeeded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestIsSkipNeeded_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    int32_t ret = sampler.IsSkipNeeded(pointerEvent);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TestAggregateRawEvents_01
 * @tc.desc: Test AggregateRawEvents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestAggregateRawEvents_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(sampler.AggregateRawEvents(pointerEvent));
}

/**
 * @tc.name: TestHandleMouseEvent_01
 * @tc.desc: Test HandleMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestHandleMouseEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    sampler.rawEvents_.push({pointerEvent, std::chrono::steady_clock::now()});
    ASSERT_NO_FATAL_FAILURE(sampler.HandleMouseEvent(pointerEvent));
}

/**
 * @tc.name: TestHandleMouseEvent_02
 * @tc.desc: Test HandleMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventSamplerTest, TestHandleMouseEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::InputEventSampler sampler;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_ENTER_WINDOW);
    sampler.rawEvents_.push({pointerEvent, std::chrono::steady_clock::now()});
    ASSERT_NO_FATAL_FAILURE(sampler.HandleMouseEvent(pointerEvent));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS