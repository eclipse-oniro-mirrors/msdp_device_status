/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <dlfcn.h>
#include <gtest/gtest.h>

#include <sys/epoll.h>
#include <sys/timerfd.h>

#include "accesstoken_kit.h"
#include "devicestatus_data_define.h"
#include "devicestatus_define.h"
#define private public
#include "devicestatus_data_parse.h"
#include "devicestatus_msdp_mock.h"
#undef private
#include "devicestatus_msdp_interface.h"
#include "devicestatus_msdp_mock.h"
#include "devicestatus_msdp_client_impl.h"
#include "sensor_data_callback.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusMsdpMocKTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
std::shared_ptr<DeviceStatusMsdpMock> g_testMock;
constexpr int32_t INVAILD_TIMER_INTERVAL { -1 };
constexpr int32_t ERR_INVALID_FD { -1 };
constexpr int32_t ZERO_TIMER_INTERVAL { 0 };
constexpr int32_t TIMER_INTERVAL { 3 };
#ifdef __aarch64__
const std::string DEVICESTATUS_MOCK_LIB_PATH { "/system/lib64/libdevicestatus_mock.z.so" };
#else
const std::string DEVICESTATUS_MOCK_LIB_PATH { "/system/lib/libdevicestatus_mock.z.so" };
#endif
} // namespace

class DeviceStatusMsdpMocKTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int32_t LoadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler);
    int32_t UnloadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler);
protected:
    DeviceStatusMsdpMock deviceStatusMsdpMock;
};

void DeviceStatusMsdpMocKTest::SetUpTestCase()
{
    g_testMock = std::make_shared<DeviceStatusMsdpMock>();
}

void DeviceStatusMsdpMocKTest::TearDownTestCase()
{
    g_testMock = nullptr;
}

void DeviceStatusMsdpMocKTest::SetUp() {}

void DeviceStatusMsdpMocKTest::TearDown() {}

int32_t DeviceStatusMsdpMocKTest::LoadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler)
{
    FI_HILOGI("Enter");
    if (mockHandler == nullptr) {
        FI_HILOGE("mockHandler is nullptr");
        return RET_ERR;
    }
    if (mockHandler->handle != nullptr) {
        FI_HILOGE("handle has exists");
        return RET_OK;
    }

    std::string dlName = DEVICESTATUS_MOCK_LIB_PATH;
    char libRealPath[PATH_MAX] = { 0 };
    if (realpath(dlName.c_str(), libRealPath) == nullptr) {
        FI_HILOGE("Get absolute algoPath is error, errno:%{public}d", errno);
        return RET_ERR;
    }

    mockHandler->handle = dlopen(libRealPath, RTLD_LAZY);
    if (mockHandler->handle == nullptr) {
        FI_HILOGE("Cannot load library error:%{public}s", dlerror());
        return RET_ERR;
    }

    mockHandler->create = reinterpret_cast<IMsdp* (*)()>(dlsym(mockHandler->handle, "Create"));
    mockHandler->destroy = reinterpret_cast<void *(*)(IMsdp*)>(dlsym(mockHandler->handle, "Destroy"));
    if (mockHandler->create == nullptr || mockHandler->destroy == nullptr) {
        FI_HILOGE("%{public}s dlsym create or destroy failed", dlName.c_str());
        dlclose(mockHandler->handle);
        mockHandler->Clear();
        return RET_ERR;
    }
    return RET_OK;
}

int32_t DeviceStatusMsdpMocKTest::UnloadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler)
{
    FI_HILOGI("Enter");
    if (mockHandler == nullptr) {
        FI_HILOGE("mockHandler is nullptr");
        return RET_ERR;
    }
    if (mockHandler->handle == nullptr) {
        FI_HILOGE("handle is nullptr");
        return RET_ERR;
    }

    if (mockHandler->pAlgorithm != nullptr) {
        mockHandler->destroy(mockHandler->pAlgorithm);
        mockHandler->pAlgorithm = nullptr;
    }
    dlclose(mockHandler->handle);
    mockHandler->Clear();
    return RET_OK;
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest001
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest002
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_INVALID) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_INVALID) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest003
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_ABSOLUTE_STILL) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_ABSOLUTE_STILL) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest004
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest005
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_VERTICAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_VERTICAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest006
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_LID_OPEN) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_LID_OPEN) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest007
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_MAX) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_MAX) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest008
 * @tc.desc: test devicestatus DisableCount
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
    EXPECT_TRUE(g_testMock->DisableCount(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest009
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(g_testMock->NotifyMsdpImpl({}) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest010
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = g_testMock->SetTimerInterval(TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest011
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = g_testMock->SetTimerInterval(INVAILD_TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest012
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = g_testMock->SetTimerInterval(ZERO_TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest013
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = g_testMock->SetTimerInterval(ZERO_TIMER_INTERVAL);
    EXPECT_TRUE(ret == ERR_OK);
    g_testMock->TimerCallback();
    ret = g_testMock->GetDeviceStatusData();
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest014
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->GetCallbackImpl() = nullptr;
    EXPECT_FALSE(g_testMock->NotifyMsdpImpl({}) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest015
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_FALSE(g_testMock->NotifyMsdpImpl({TYPE_INVALID, VALUE_INVALID}) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest016
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->dataParse_ = nullptr;
    int32_t ret = g_testMock->GetDeviceStatusData();
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest017
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest017, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_testMock->SetTimerInterval(ZERO_TIMER_INTERVAL);
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest019
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->TimerCallback();
    FI_HILOGI("Test the abnormal branch.");
    int32_t ret = g_testMock->SetTimerInterval(ZERO_TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest020
 * @tc.desc: first test devicestatus Mock in Disable
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest020, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = deviceStatusMsdpMock.Disable(Type::TYPE_MAX);
    EXPECT_TRUE(ret == RET_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest021
 * @tc.desc: second test devicestatus Mock in Disable
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest021, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.InitTimer();
    deviceStatusMsdpMock.StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = deviceStatusMsdpMock.Disable(Type::TYPE_MAX);
    EXPECT_TRUE(ret == RET_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest022
 * @tc.desc: test devicestatus Mock in GetDeviceStatusData
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest022, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.dataParse_ = std::make_unique<DeviceStatusDataParse>();
    int32_t ret = deviceStatusMsdpMock.GetDeviceStatusData();
    EXPECT_TRUE(ret == RET_OK);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest023
 * @tc.desc: first test devicestatus Mock in SetTimerInterval
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest023, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.timerFd_ = ERR_INVALID_FD;
    int32_t ret = deviceStatusMsdpMock.SetTimerInterval(INVAILD_TIMER_INTERVAL);
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest024
 * @tc.desc: second test devicestatus Mock in SetTimerInterval
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest024, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.InitTimer();
    deviceStatusMsdpMock.StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = deviceStatusMsdpMock.SetTimerInterval(INVAILD_TIMER_INTERVAL);
    deviceStatusMsdpMock.CloseTimer();
    EXPECT_TRUE(ret == RET_ERR);
    EXPECT_TRUE(deviceStatusMsdpMock.timerFd_ == ERR_INVALID_FD);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest025
 * @tc.desc: third test devicestatus Mock in SetTimerInterval
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest025, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.InitTimer();
    deviceStatusMsdpMock.StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = deviceStatusMsdpMock.SetTimerInterval(INT_MAX);
    deviceStatusMsdpMock.CloseTimer();
    EXPECT_TRUE(ret == RET_OK);
    EXPECT_TRUE(deviceStatusMsdpMock.timerFd_ == ERR_INVALID_FD);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest026
 * @tc.desc: test devicestatus Mock in CloseTimer
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest026, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.timerFd_ = ERR_INVALID_FD;
    deviceStatusMsdpMock.CloseTimer();
    EXPECT_TRUE(deviceStatusMsdpMock.timerFd_ == ERR_INVALID_FD);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest027
 * @tc.desc: test devicestatus Mock in RegisterTimerCallback
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest027, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.epFd_ = ERR_INVALID_FD;
    int32_t ret = deviceStatusMsdpMock.RegisterTimerCallback(ERR_INVALID_FD, DeviceStatusMsdpMock::EVENT_TIMER_FD);
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest028
 * @tc.desc: test devicestatus Mock in TimerCallback
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest028, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.timerFd_ = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    fcntl(deviceStatusMsdpMock.timerFd_, F_SETFL, O_NONBLOCK);
    deviceStatusMsdpMock.TimerCallback();
    deviceStatusMsdpMock.CloseTimer();
    EXPECT_TRUE(deviceStatusMsdpMock.timerFd_ == ERR_INVALID_FD);
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest029
 * @tc.desc: first test devicestatus Mock in LoopingThreadEntry
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest029, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.callbacks_.clear();
    deviceStatusMsdpMock.LoopingThreadEntry();
    EXPECT_TRUE(deviceStatusMsdpMock.callbacks_.empty());
}

/**
 * @tc.name: DeviceStatusMsdpMocKTest030
 * @tc.desc: second test devicestatus Mock in LoopingThreadEntry
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpMocKTest, DeviceStatusMsdpMocKTest030, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.StartThread();
    deviceStatusMsdpMock.epFd_ = ERR_INVALID_FD;
    deviceStatusMsdpMock.callbacks_.insert(std::make_pair(1, &DeviceStatusMsdpMock::TimerCallback));
    deviceStatusMsdpMock.LoopingThreadEntry();
    deviceStatusMsdpMock.callbacks_.clear();
    EXPECT_TRUE(deviceStatusMsdpMock.alive_);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
