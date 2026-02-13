/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#ifndef STREAM_SERVER_H
#define STREAM_SERVER_H

#include <functional>
#include <list>
#include <map>
#include <mutex>

#include "nocopyable.h"

#include "circle_stream_buffer.h"
#include "i_stream_server.h"
#include "stream_socket.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum EpollEventType {
    EPOLL_EVENT_BEGIN = 0,
    EPOLL_EVENT_INPUT = EPOLL_EVENT_BEGIN,
    EPOLL_EVENT_SOCKET,
    EPOLL_EVENT_ETASK,
    EPOLL_EVENT_TIMER,
    EPOLL_EVENT_DEVICE_MGR,
    EPOLL_EVENT_END
};

using MsgServerFunCallback = std::function<void(SessionPtr, NetPacket&)>;
class StreamServer : public StreamSocket, public IStreamServer {
public:
    StreamServer() = default;
    DISALLOW_COPY_AND_MOVE(StreamServer);
    virtual ~StreamServer();
    void UdsStop();
    bool SendMsg(int32_t fd, NetPacket &pkt);
    void Multicast(const std::vector<int32_t> &fdList, NetPacket &pkt);
    int32_t GetClientFd(int32_t pid) const;
    int32_t GetClientPid(int32_t fd) const;
    void AddSessionDeletedCallback(int32_t pid, std::function<void(SessionPtr)> callback);
    int32_t AddSocketPairInfo(const std::string &programName, int32_t moduleType, int32_t uid, int32_t pid,
        int32_t &serverFd, int32_t &toReturnClientFd, int32_t &tokenType) override;

    SessionPtr GetSession(int32_t fd) const;
    SessionPtr GetSessionByPid(int32_t pid) const override;

private:
    int32_t SetSockOpt(int32_t &serverFd, int32_t &toReturnClientFd, int32_t &tokenType);
    int32_t CloseFd(int32_t &serverFd, int32_t &toReturnClientFd);

protected:
    virtual void OnConnected(SessionPtr s) = 0;
    virtual void OnDisconnected(SessionPtr s) = 0;
    virtual int32_t AddEpoll(EpollEventType type, int32_t fd) = 0;

    void SetRecvFun(MsgServerFunCallback fun);
    void ReleaseSession(int32_t fd, epoll_event &ev);
    void OnPacket(int32_t fd, NetPacket &pkt);
    void OnEpollRecv(int32_t fd, epoll_event &ev);
    void OnEpollEvent(epoll_event &ev);
    bool AddSession(SessionPtr ses);
    void DelSession(int32_t fd);
    void DumpSession(const std::string &title);
    void NotifySessionDeleted(SessionPtr ses);

protected:
    MsgServerFunCallback recvFun_ { nullptr };
    std::map<int32_t, SessionPtr> sessions_;
    std::map<int32_t, int32_t> idxPids_;
    std::map<int32_t, CircleStreamBuffer> circleBufs_;
    std::map<int32_t, std::function<void(SessionPtr)>> callbacks_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // STREAM_SERVER_H