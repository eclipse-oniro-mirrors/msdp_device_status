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

#include "drag_smooth_processor_test.h"

#include "drag_smooth_processor.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;

/**
 * @tc.name: SmoothMoveEventBothEmpty
 * @tc.desc: Verify SmoothMoveEvent returns default event when both moveEvents_ and historyEvents_ are empty.
 *           This covers the fix for the crash at currentEvents.back() on empty vector.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSmoothProcessorTest, SmoothMoveEventBothEmpty, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent result = processor.SmoothMoveEvent(17000000, 16666667);
    EXPECT_EQ(result.displayX, 0.0f);
    EXPECT_EQ(result.displayY, 0.0f);
    EXPECT_EQ(result.displayId, -1);
    EXPECT_EQ(result.timestamp, 0);
}

/**
 * @tc.name: SmoothMoveEventWithEvents
 * @tc.desc: Verify SmoothMoveEvent returns the latest event when events are inserted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSmoothProcessorTest, SmoothMoveEventWithEvents, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent event1 { .displayX = 10.0f, .displayY = 20.0f, .displayId = 0, .timestamp = 17000000 };
    DragMoveEvent event2 { .displayX = 30.0f, .displayY = 40.0f, .displayId = 0, .timestamp = 35000000 };
    processor.InsertEvent(event1);
    processor.InsertEvent(event2);

    DragMoveEvent result = processor.SmoothMoveEvent(50000000, 16666667);
    EXPECT_EQ(result.displayId, 0);
}

/**
 * @tc.name: SmoothMoveEventEmptyMoveNonEmptyHistory
 * @tc.desc: Verify SmoothMoveEvent falls back to historyEvents_ when moveEvents_ is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSmoothProcessorTest, SmoothMoveEventEmptyMoveNonEmptyHistory, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent event1 { .displayX = 10.0f, .displayY = 20.0f, .displayId = 0, .timestamp = 17000000 };
    DragMoveEvent event2 { .displayX = 30.0f, .displayY = 40.0f, .displayId = 0, .timestamp = 35000000 };
    processor.InsertEvent(event1);
    processor.InsertEvent(event2);

    DragMoveEvent first = processor.SmoothMoveEvent(50000000, 16666667);
    EXPECT_EQ(first.displayId, 0);

    DragMoveEvent second = processor.SmoothMoveEvent(70000000, 16666667);
    EXPECT_EQ(second.displayId, 0);
}

/**
 * @tc.name: SmoothMoveEventAfterReset
 * @tc.desc: Verify SmoothMoveEvent returns default event after ResetParameters clears all data.
 *           This covers the race condition scenario where ResetParameters runs before SmoothMoveEvent.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSmoothProcessorTest, SmoothMoveEventAfterReset, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent event { .displayX = 10.0f, .displayY = 20.0f, .displayId = 0, .timestamp = 17000000 };
    processor.InsertEvent(event);
    processor.SmoothMoveEvent(35000000, 16666667);
    processor.ResetParameters();

    DragMoveEvent result = processor.SmoothMoveEvent(50000000, 16666667);
    EXPECT_EQ(result.displayX, 0.0f);
    EXPECT_EQ(result.displayY, 0.0f);
    EXPECT_EQ(result.displayId, -1);
    EXPECT_EQ(result.timestamp, 0);
}

/**
 * @tc.name: ResetParametersClearsAll
 * @tc.desc: Verify ResetParameters clears both events and history.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSmoothProcessorTest, ResetParametersClearsAll, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent event { .displayX = 10.0f, .displayY = 20.0f, .displayId = 0, .timestamp = 17000000 };
    processor.InsertEvent(event);
    processor.ResetParameters();

    DragMoveEvent result = processor.SmoothMoveEvent(35000000, 16666667);
    EXPECT_EQ(result.displayId, -1);
}

/**
* @tc.name: GetInterpolatedEvent1
* @tc.desc: Verify GetInterpolatedEvent returns nullopt when nanoTimestamp <= historyAvgEvent.timestamp.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragSmoothProcessorTest, GetInterpolatedEvent1, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent historyAvgEvent { .displayX = 100.0f, .displayY = 200.0f, .displayId = 0, .timestamp = 50000000 };
    DragMoveEvent currentAvgEvent { .displayX = 300.0f, .displayY = 400.0f, .displayId = 0, .timestamp = 60000000 };

    auto result = processor.GetInterpolatedEvent(historyAvgEvent, currentAvgEvent, 50000000);
    EXPECT_FALSE(result.has_value());

    auto result2 = processor.GetInterpolatedEvent(historyAvgEvent, currentAvgEvent, 30000000);
    EXPECT_FALSE(result2.has_value());
}

/**
* @tc.name: GetInterpolatedEvent2
* @tc.desc: Verify GetInterpolatedEvent returns nullopt when nanoTimestamp == currentAvgEvent.timestamp.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragSmoothProcessorTest, GetInterpolatedEvent2, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent historyAvgEvent { .displayX = 10.0f, .displayY = 20.0f, .displayId = 0, .timestamp = 10000000 };
    DragMoveEvent currentAvgEvent { .displayX = 30.0f, .displayY = 40.0f, .displayId = 0, .timestamp = 20000000 };

    auto result = processor.GetInterpolatedEvent(historyAvgEvent, currentAvgEvent, 20000000);
    EXPECT_FALSE(result.has_value());
}

/**
* @tc.name: GetInterpolatedEvent3
* @tc.desc: Verify GetInterpolatedEvent returns nullopt when currentAvgEvent.timestamp <= historyAvgEvent.timestamp.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragSmoothProcessorTest, GetInterpolatedEvent3, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent historyAvgEvent { .displayX = 100.0f, .displayY = 200.0f, .displayId = 0, .timestamp = 50000000 };
    DragMoveEvent currentAvgEvent { .displayX = 150.0f, .displayY = 250.0f, .displayId = 0, .timestamp = 30000000 };

    auto result = processor.GetInterpolatedEvent(historyAvgEvent, currentAvgEvent, 40000000);
    EXPECT_FALSE(result.has_value());
}

/**
* @tc.name: GetInterpolatedEvent4
* @tc.desc: Verify GetInterpolatedEvent returns nullopt when
*           (currentAvgEvent.timestamp - historyAvgEvent.timestamp) > INTERPOLATION_THRESHOLD (100ms).
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragSmoothProcessorTest, GetInterpolatedEvent4, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent historyAvgEvent { .displayX = 10.0f, .displayY = 20.0f, .displayId = 0, .timestamp = 10000000 };
    DragMoveEvent currentAvgEvent { .displayX = 50.0f, .displayY = 60.0f, .displayId = 0, .timestamp = 120000000 };

    auto result = processor.GetInterpolatedEvent(historyAvgEvent, currentAvgEvent, 60000000);
    EXPECT_FALSE(result.has_value());
}

/**
* @tc.name: GetInterpolatedEvent5
* @tc.desc: Verify GetInterpolatedEvent performs normal interpolation when
*           historyAvgEvent.timestamp < nanoTimestamp < currentAvgEvent.timestamp (alpha <= 1.5).
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragSmoothProcessorTest, GetInterpolatedEvent5, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent historyAvgEvent { .displayX = 0.0f, .displayY = 0.0f, .displayId = 0, .timestamp = 10000000 };
    DragMoveEvent currentAvgEvent { .displayX = 100.0f, .displayY = 100.0f, .displayId = 1, .timestamp = 20000000 };

    auto result = processor.GetInterpolatedEvent(historyAvgEvent, currentAvgEvent, 15000000);
    ASSERT_TRUE(result.has_value());
    EXPECT_FLOAT_EQ(result->displayX, 50.0f);
    EXPECT_FLOAT_EQ(result->displayY, 50.0f);
    EXPECT_EQ(result->timestamp, 15000000);
    EXPECT_EQ(result->displayId, 1);
}

/**
* @tc.name: GetInterpolatedEvent6
* @tc.desc: Verify GetInterpolatedEvent performs normal extrapolation when
*           nanoTimestamp > currentAvgEvent.timestamp and alpha <= 1.5f.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragSmoothProcessorTest, GetInterpolatedEvent6, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent historyAvgEvent { .displayX = 10.0f, .displayY = 20.0f, .displayId = 0, .timestamp = 10000000 };
    DragMoveEvent currentAvgEvent { .displayX = 30.0f, .displayY = 40.0f, .displayId = 1, .timestamp = 20000000 };

    auto result = processor.GetInterpolatedEvent(historyAvgEvent, currentAvgEvent, 25000000);
    ASSERT_TRUE(result.has_value());
    EXPECT_FLOAT_EQ(result->displayX, 40.0f);
    EXPECT_FLOAT_EQ(result->displayY, 50.0f);
    EXPECT_EQ(result->timestamp, 25000000);
    EXPECT_EQ(result->displayId, 1);
}

/**
* @tc.name: GetInterpolatedEvent7
* @tc.desc: Verify GetInterpolatedEvent clamps alpha to 1.5f during extrapolation when
*           nanoTimestamp is far beyond currentAvgEvent.timestamp (alpha > 1.5f).
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragSmoothProcessorTest, GetInterpolatedEvent7, TestSize.Level0)
{
    DragSmoothProcessor processor;
    DragMoveEvent historyAvgEvent { .displayX = 10.0f, .displayY = 20.0f, .displayId = 0, .timestamp = 10000000 };
    DragMoveEvent currentAvgEvent { .displayX = 30.0f, .displayY = 40.0f, .displayId = 1, .timestamp = 20000000 };

    auto result = processor.GetInterpolatedEvent(historyAvgEvent, currentAvgEvent, 50000000);
    ASSERT_TRUE(result.has_value());
    EXPECT_FLOAT_EQ(result->displayX, 40.0f);
    EXPECT_FLOAT_EQ(result->displayY, 50.0f);
    EXPECT_EQ(result->timestamp, 50000000);
    EXPECT_EQ(result->displayId, 1);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
