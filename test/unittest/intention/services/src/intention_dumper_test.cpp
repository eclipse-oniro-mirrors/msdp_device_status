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
#include "intention_service_test.h"
#include "ddm_adapter.h"
#include "dsoftbus_adapter.h"
#include "fi_log.h"
#include "input_adapter.h"
#include "intention_service.h"
#include "interaction_manager.h"
#include "ipc_skeleton.h"
#include "plugin_manager.h"

#undef LOG_TAG
#define LOG_TAG "IntentionDumperTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
std::shared_ptr<ContextService> g_context { nullptr };
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

int32_t MockDelegateTasks::PostSyncTask(DTaskCallback callback)
{
    return callback();
}

int32_t MockDelegateTasks::PostAsyncTask(DTaskCallback callback)
{
    return callback();
}

ContextService* ContextService::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        g_context = std::make_shared<ContextService>();
    });
    return g_context.get();
}

ContextService::ContextService()
{
    ddm_ = std::make_unique<DDMAdapter>();
    input_ = std::make_unique<InputAdapter>();
    pluginMgr_ = std::make_unique<PluginManager>(this);
    dsoftbus_ = std::make_unique<DSoftbusAdapter>();
}

IDelegateTasks& ContextService::GetDelegateTasks()
{
    return delegateTasks_;
}

IDeviceManager& ContextService::GetDeviceManager()
{
    return devMgr_;
}

ITimerManager& ContextService::GetTimerManager()
{
    return timerMgr_;
}

IDragManager& ContextService::GetDragManager()
{
    return dragMgr_;
}

ISocketSessionManager& ContextService::GetSocketSessionManager()
{
    return socketSessionMgr_;
}

IDDMAdapter& ContextService::GetDDM()
{
    return *ddm_;
}

IPluginManager& ContextService::GetPluginManager()
{
    return *pluginMgr_;
}

IInputAdapter& ContextService::GetInput()
{
    return *input_;
}

IDSoftbusAdapter& ContextService::GetDSoftbus()
{
    return *dsoftbus_;
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
    std::vector<std::string> argList = {"s", "h", "l", "c", "d"};
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
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    IntentionDumper dumper = IntentionDumper(env, stationary);
    int32_t value = 's';
    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, value));
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
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    IntentionDumper dumper = IntentionDumper(env, stationary);
    int32_t value = 'l';
    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, value));
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
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    IntentionDumper dumper = IntentionDumper(env, stationary);
    int32_t value = 'c';
    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, value));
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
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    IntentionDumper dumper = IntentionDumper(env, stationary);
    int32_t value = 'd';
    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, value));
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
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    IntentionDumper dumper = IntentionDumper(env, stationary);
    int32_t value = 'm';
    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, value));
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
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    IntentionDumper dumper = IntentionDumper(env, stationary);

    int32_t value = 'y';
    ASSERT_NO_FATAL_FAILURE(dumper.DumpOnce(g_fd, value));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS