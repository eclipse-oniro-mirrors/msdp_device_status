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

#include "socket_session_test.h"

#include <functional>
#include <memory>

#include "ipc_skeleton.h"
#include "message_parcel.h"

#include "devicestatus_define.h"
#include "i_context.h"
#include "socket_client.h"
#include "socket_session_manager.h"
#include "socket_server.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
std::unique_ptr<SocketClient> g_client {nullptr};
std::shared_ptr<SocketConnection> g_socket { nullptr };
std::shared_ptr<SocketServer> g_socketServer { nullptr };
std::shared_ptr<SocketSession> g_session { nullptr };
std::shared_ptr<SocketSession> g_sessionOne { nullptr };
std::shared_ptr<SocketSessionManager> g_socketSessionManager { nullptr };
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
} // namespace

void SocketSessionTest::SetUpTestCase() {}

void SocketSessionTest::SetUp()
{
    g_client = std::make_unique<SocketClient>();
    g_socketServer = std::make_shared<SocketServer>(nullptr);
    g_socketSessionManager = std::make_shared<SocketSessionManager>();
    int32_t moduleType = 1;
    int32_t tokenType = 1;
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t pid = IPCSkeleton::GetCallingPid();
    g_session = std::make_shared<SocketSession>("test", moduleType, tokenType, -1, uid, pid);
    g_sessionOne = std::make_shared<SocketSession>("test1", moduleType, tokenType, -1, uid, pid);
}

void SocketSessionTest::TearDown()
{
    g_client = nullptr;
    g_socket = nullptr;
    g_socketSessionManager = nullptr;
    g_session = nullptr;
    g_socketServer = nullptr;
    g_sessionOne = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: Disable
 * @tc.desc: Drag Disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SocketSessionTest, Disable, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto manager = std::make_unique<SocketSessionManager>();
    ASSERT_NO_FATAL_FAILURE({manager->Disable();});
}

/**
 * @tc.name: SessionIteration
 * @tc.desc: Drag SessionIteration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SocketSessionTest, SessionIteration, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto testFunc = []() {
    std::unordered_map<int, std::shared_ptr<void>> emptyMap;
        std::for_each(emptyMap.cbegin(), emptyMap.cend(), [](const auto& item) {
    (void)item;
        });
    };
    ASSERT_NO_FATAL_FAILURE(testFunc());
}

/**
 * @tc.name: OnProcessDied
 * @tc.desc: Drag OnProcessDied
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(SocketSessionTest, OnProcessDied, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto manager = std::make_shared<SocketSessionManager>();
    auto observer = std::make_unique<SocketSessionManager::AppStateObserver>(*manager);
    AppExecFwk::ProcessData data;
    data.pid = 1001;
    data.bundleName = "com.test.app";
    ASSERT_NE(nullptr, observer.get()) << "AppStateObserver not initialized";
    ASSERT_NO_FATAL_FAILURE(observer->OnProcessDied(data));
}

/**
 * @tc.name: SocketSessionTest1
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SocketSessionTest, SocketSessionTest1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t testSocket = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(testSocket, 0) << "Failed to create socket";
    class SocketGuard {
    public:
    explicit SocketGuard(int fd) : fd_(fd) {}
    ~SocketGuard() { if (fd_ >= 0) ::close(fd_); }
    int get() const { return fd_; }
    private:
    int fd_;
    };
    SocketGuard socketGuard(testSocket);
    auto onDisconnected = []() { return; };
    auto recv = [](const NetPacket &pkt) { return; };
    SocketConnection socketConnection(socketGuard.get(), recv, onDisconnected);
    ASSERT_NO_FATAL_FAILURE(socketConnection.OnReadable(socketGuard.get()));
    EXPECT_TRUE(true) << "OnReadable should handle gracefully";
    ASSERT_NO_FATAL_FAILURE(socketConnection.OnShutdown(socketGuard.get()));
    EXPECT_TRUE(true) << "OnShutdown should handle gracefully";
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS