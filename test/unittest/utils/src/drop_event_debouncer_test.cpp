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

#include <chrono>

#include <gtest/gtest.h>

#include "drop_event_debouncer.h"

namespace OHOS {
namespace Msdp {
namespace {
using namespace testing::ext;

class DropEventDebouncerTest : public testing::Test {};

HWTEST_F(DropEventDebouncerTest, FirstEventIsDispatchedImmediately, TestSize.Level1)
{
    DropEventDebouncer debouncer;
    EXPECT_TRUE(debouncer.ShouldDispatch(std::chrono::steady_clock::time_point {}));
}

HWTEST_F(DropEventDebouncerTest, TwoSecondBoundaryAndFollowingWindow, TestSize.Level1)
{
    DropEventDebouncer debouncer;
    const auto start = std::chrono::steady_clock::time_point {};
    const auto interval = std::chrono::seconds(2);
    const auto tick = std::chrono::nanoseconds(1);
    EXPECT_TRUE(debouncer.ShouldDispatch(start));
    debouncer.MarkDispatched(start);
    EXPECT_FALSE(debouncer.ShouldDispatch(start));
    EXPECT_FALSE(debouncer.ShouldDispatch(start + interval - tick));
    EXPECT_TRUE(debouncer.ShouldDispatch(start + interval));
    debouncer.MarkDispatched(start + interval);
    EXPECT_FALSE(debouncer.ShouldDispatch(start + interval + tick));
    EXPECT_TRUE(debouncer.ShouldDispatch(start + interval + interval));
}

HWTEST_F(DropEventDebouncerTest, CallbackRegistrationsHaveIndependentWindows, TestSize.Level1)
{
    DropEventDebouncer first;
    DropEventDebouncer second;
    const auto start = std::chrono::steady_clock::time_point {};
    EXPECT_TRUE(first.ShouldDispatch(start));
    first.MarkDispatched(start);
    EXPECT_TRUE(second.ShouldDispatch(start));
    second.MarkDispatched(start);
    EXPECT_FALSE(first.ShouldDispatch(start));
    EXPECT_FALSE(second.ShouldDispatch(start));

    DropEventDebouncer resubscribed;
    EXPECT_TRUE(resubscribed.ShouldDispatch(start));
}

HWTEST_F(DropEventDebouncerTest, FailedDispatchCanBeRetriedImmediately, TestSize.Level1)
{
    DropEventDebouncer debouncer;
    const auto start = std::chrono::steady_clock::time_point {};
    EXPECT_TRUE(debouncer.ShouldDispatch(start));
    // A failed dispatch does not mark the event as dispatched.
    EXPECT_TRUE(debouncer.ShouldDispatch(start));
    debouncer.MarkDispatched(start);
    EXPECT_FALSE(debouncer.ShouldDispatch(start));
}

HWTEST_F(DropEventDebouncerTest, WindowStartsWhenDispatchSucceeds, TestSize.Level1)
{
    DropEventDebouncer debouncer;
    const auto start = std::chrono::steady_clock::time_point {};
    const auto completed = start + std::chrono::milliseconds(500);
    const auto interval = std::chrono::seconds(2);
    EXPECT_TRUE(debouncer.ShouldDispatch(start));
    debouncer.MarkDispatched(completed);
    EXPECT_FALSE(debouncer.ShouldDispatch(start + interval));
    EXPECT_TRUE(debouncer.ShouldDispatch(completed + interval));
}
} // namespace
} // namespace Msdp
} // namespace OHOS
