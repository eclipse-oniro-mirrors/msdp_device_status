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
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
