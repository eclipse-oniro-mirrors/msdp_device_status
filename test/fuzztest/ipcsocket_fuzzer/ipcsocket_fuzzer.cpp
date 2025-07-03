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

#include "ipcsocket_fuzzer.h"

#include "singleton.h"

#include "devicestatus_define.h"
#include "socket_client.h"
#include "socket_session_manager.h"
#include "socket_session.h"
#include "socket_connection.h"
#include "stream_client.h"

#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "IpcSocketFuzzTest"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
const std::u16string FORMMGR_INTERFACE_TOKEN { u"ohos.msdp.Idevicestatus" };
inline constexpr int32_t MAX_EVENT_SIZE { 100 };
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos = 0;

namespace OHOS {

template <class T> T GetData()
{
    T objetct{};
    size_t objetctSize = sizeof(objetct);
    if (g_baseFuzzData == nullptr || objetctSize > g_baseFuzzSize - g_baseFuzzPos) {
        return objetct;
    }
    errno_t ret = memcpy_s(&objetct, objetctSize, g_baseFuzzData + g_baseFuzzPos, objetctSize);
    if (ret != EOK) {
        return {};
    }
    g_baseFuzzPos += objetctSize;
    return objetct;
}

bool SocketConnectionFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return false;
    }

    auto recv = [](const NetPacket &pkt) {
        return;
    };
    auto onDisconnected = []() {
        return;
    };
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    int32_t fd = GetData<int32_t>();
    SocketConnection socketConnection(1, recv, onDisconnected);
    
    auto socket = []() {
        return 0;
    };
    NetPacket packet(MessageId::COORDINATION_ADD_LISTENER);
    struct epoll_event ev{};
    auto client = std::make_unique<SocketClient>();
    client->Connect();
    client->Socket();
    MessageId msgId { MessageId::INVALID };
    NetPacket pkt(msgId);
    client->OnPacket(pkt);
    client->Reconnect();
    client->Stop();
    client->OnDisconnected();
    SocketSession socketSession("testProgramName", 1, 1, 1, 1, 1);
    socketSession.SendMsg(packet);
    socketSession.ToString();
    socketSession.Dispatch(ev);
    socketConnection.OnReadable(fd);
    socketConnection.OnShutdown(fd);
    socketConnection.OnException(fd);
    Msdp::DeviceStatus::SocketConnection::Connect(socket, recv, onDisconnected);
    client = nullptr;
    return true;
}

} // namespace OHOS
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::SocketConnectionFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS