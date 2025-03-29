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

#include <vector>
#include <memory>

#include <unistd.h>

#include "device_manager.h"
#include <gtest/gtest.h>
#include "intention_dumper.h"

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "stationary_server.h"

#undef LOG_TAG
#define LOG_TAG "IntentionDumperTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
int32_t g_fd { 1 };
StationaryServer stationary;
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
const std::string TEST_DEV_NODE {"TestDeviceNode"};
} // namespace

class IntentionDumperTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase(void);
};
void IntentionDumperTest::SetUpTestCase() {}

void IntentionDumperTest::TearDownTestCase() {}

void IntentionDumperTest::SetUp() {}

void IntentionDumperTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: IntentionDumperTest001
 * @tc.desc: test Intention Dumper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionDumperTest, IntentionDumperTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    IContext *env { nullptr };
    IntentionDumper dumper = IntentionDumper(env, stationary);
    std::vector<std::string> argList;
    ASSERT_NO_FATAL_FAILURE(dumper.Dump(g_fd, argList));
}

/**
 * @tc.name: IntentionDumperTest002
 * @tc.desc: test Intention Dumper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionDumperTest, IntentionDumperTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    IContext *env { nullptr };
    IntentionDumper dumper = IntentionDumper(env, stationary);
    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, std::atof("s")));
}

/**
 * @tc.name: IntentionDumperTest003
 * @tc.desc: test Intention Dumper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionDumperTest, IntentionDumperTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    IContext *env { nullptr };
    IntentionDumper dumper = IntentionDumper(env, stationary);
    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, std::atof("l")));
}

/**
 * @tc.name: IntentionDumperTest004
 * @tc.desc: test Intention Dumper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionDumperTest, IntentionDumperTest004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    IContext *env { nullptr };
    IntentionDumper dumper = IntentionDumper(env, stationary);
    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, std::atof("c")));
}

/**
 * @tc.name: IntentionDumperTest005
 * @tc.desc: test Intention Dumper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionDumperTest, IntentionDumperTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    IContext *env { nullptr };
    IntentionDumper dumper = IntentionDumper(env, stationary);
    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, std::atof("d")));
}

/**
 * @tc.name: IntentionDumperTest006
 * @tc.desc: test Intention Dumper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionDumperTest, IntentionDumperTest006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    IContext *env { nullptr };
    IntentionDumper dumper = IntentionDumper(env, stationary);
    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, std::atof("m")));
}

/**
 * @tc.name: IntentionDumperTest007
 * @tc.desc: test Intention Dumper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionDumperTest, IntentionDumperTest007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    IContext *env { nullptr };
    IntentionDumper dumper = IntentionDumper(env, stationary);

    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, std::atof("y")));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS