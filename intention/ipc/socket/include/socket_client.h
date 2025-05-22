/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef SOCKET_CLIENT_H
#define SOCKET_CLIENT_H

#include <map>
#include <mutex>

#include "net_packet.h"
#include "devicestatus_proto.h"
#include "socket_connection.h"
#include "stream_client.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
typedef std::function<void()> ConnectCallback;
class SocketClient final : public StreamClient {
public:
    SocketClient();
    DISALLOW_COPY_AND_MOVE(SocketClient);
    ~SocketClient() = default;

    bool RegisterEvent(MessageId id, std::function<int32_t(const StreamClient&, NetPacket&)> callback);
    void Start();
    void Stop() override;
    void RegisterConnectedFunction(ConnectCallback funConnected);
    void RegisterDisconnectedFunction(ConnectCallback funDisconnected);

private:
    bool Connect();
    int32_t Socket() override;
    void OnPacket(NetPacket &pkt);
    void OnDisconnected() override;
    void Reconnect();
    void OnMsgHandler(const StreamClient &client, NetPacket &pkt);

    mutable std::mutex lock_;
    std::map<MessageId, std::function<int32_t(const StreamClient&, NetPacket&)>> callbacks_;
    std::shared_ptr<SocketConnection> socket_ { nullptr };
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_ { nullptr };
    ConnectCallback funConnected_ { nullptr };
    ConnectCallback funDisconnected_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SOCKET_CLIENT_H