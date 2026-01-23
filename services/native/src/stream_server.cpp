/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "stream_server.h"

#include <cinttypes>
#include <list>

#include <sys/socket.h>

#include "devicestatus_service.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "StreamServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

StreamServer::~StreamServer()
{
    CALL_DEBUG_ENTER;
    UdsStop();
}

void StreamServer::UdsStop()
{
    if (epollFd_ != -1) {
        if (close(epollFd_) < 0) {
            FI_HILOGE("Close epoll fd failed, error:%{public}s, epollFd_:%{public}d", strerror(errno), epollFd_);
        }
        epollFd_ = -1;
    }

    for (const auto &item : sessionss_) {
        item.second->Close();
    }
    sessionss_.clear();
}

int32_t StreamServer::GetClientFd(int32_t pid) const
{
    auto it = idxPids_.find(pid);
    if (it == idxPids_.end()) {
        return INVALID_FD;
    }
    return it->second;
}

int32_t StreamServer::GetClientPid(int32_t fd) const
{
    auto it = sessionss_.find(fd);
    if (it == sessionss_.end()) {
        return INVALID_PID;
    }
    return it->second->GetPid();
}

bool StreamServer::SendMsg(int32_t fd, NetPacket &pkt)
{
    if (fd < 0) {
        FI_HILOGE("The fd is less than 0");
        return false;
    }
    auto ses = GetSession(fd);
    if (ses == nullptr) {
        FI_HILOGE("The fd:%{public}d not found, The message was discarded, errCode:%{public}d",
            fd, SESSION_NOT_FOUND);
        return false;
    }
    return ses->SendMsg(pkt);
}

void StreamServer::Multicast(const std::vector<int32_t> &fdList, NetPacket &pkt)
{
    for (const auto &item : fdList) {
        SendMsg(item, pkt);
    }
}

int32_t StreamServer::AddSocketPairInfo(const std::string &programName, int32_t moduleType, int32_t uid, int32_t pid,
    int32_t &serverFd, int32_t &toReturnClientFd, int32_t &tokenType)
{
    CALL_DEBUG_ENTER;
    int32_t sockFds[2] = { -1 };

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockFds) != 0) {
        FI_HILOGE("Call socketpair failed, errno:%{public}d", errno);
        return RET_ERR;
    }
    serverFd = sockFds[0];
    toReturnClientFd = sockFds[1];
    if (serverFd < 0 || toReturnClientFd < 0) {
        FI_HILOGE("Call fcntl failed, errno:%{public}d", errno);
        return RET_ERR;
    }
    int32_t setSockOptResult = SetSockOpt(serverFd, toReturnClientFd, tokenType);
    if (RET_OK != setSockOptResult) {
        return setSockOptResult;
    }
    SessionPtr sess = nullptr;
    sess = std::make_shared<StreamSession>(programName, moduleType, serverFd, uid, pid);
    sess->SetTokenType(tokenType);
    if (!AddSession(sess)) {
        FI_HILOGE("AddSession fail errCode:%{public}d", ADD_SESSION_FAIL);
        return CloseFd(serverFd, toReturnClientFd);
    }
    if (AddEpoll(EPOLL_EVENT_SOCKET, serverFd) != RET_OK) {
        FI_HILOGE("epoll_ctl EPOLL_CTL_ADD failed, errCode:%{public}d", EPOLL_MODIFY_FAIL);
        return CloseFd(serverFd, toReturnClientFd);
    }
    OnConnected(sess);
    return RET_OK;
}

int32_t StreamServer::SetSockOpt(int32_t &serverFd, int32_t &toReturnClientFd, int32_t &tokenType)
{
    CALL_DEBUG_ENTER;
    static constexpr size_t bufferSize = 32 * 1024;
    static constexpr size_t nativeBufferSize = 64 * 1024;

    if (setsockopt(serverFd, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize)) != 0) {
        FI_HILOGE("setsockopt serverFd failed, errno:%{public}d", errno);
        return CloseFd(serverFd, toReturnClientFd);
    }
    if (setsockopt(serverFd, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize)) != 0) {
        FI_HILOGE("setsockopt serverFd failed, errno:%{public}d", errno);
        return CloseFd(serverFd, toReturnClientFd);
    }
    if (tokenType == TokenType::TOKEN_NATIVE) {
        if (setsockopt(toReturnClientFd, SOL_SOCKET, SO_SNDBUF, &nativeBufferSize, sizeof(nativeBufferSize)) != 0) {
            FI_HILOGE("setsockopt toReturnClientFd failed, parameter is SO_SNDBUF and nativeBufferSize, errno:%{public}d", errno);
            return CloseFd(serverFd, toReturnClientFd);
        }
        if (setsockopt(toReturnClientFd, SOL_SOCKET, SO_RCVBUF, &nativeBufferSize, sizeof(nativeBufferSize)) != 0) {
            FI_HILOGE("setsockopt toReturnClientFd failed, parameter is SO_RCVBUF and nativeBufferSize, errno:%{public}d", errno);
            return CloseFd(serverFd, toReturnClientFd);
        }
    } else {
        if (setsockopt(toReturnClientFd, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize)) != 0) {
            FI_HILOGE("setsockopt toReturnClientFd failed, parameter is SO_SNDBUF and bufferSize, errno:%{public}d", errno);
            return CloseFd(serverFd, toReturnClientFd);
        }
        if (setsockopt(toReturnClientFd, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize)) != 0) {
            FI_HILOGE("setsockopt toReturnClientFd failed, parameter is SO_RCVBUF and bufferSize, errno:%{public}d", errno);
            return CloseFd(serverFd, toReturnClientFd);
        }
    }
    return RET_OK;
}

int32_t StreamServer::CloseFd(int32_t &serverFd, int32_t &toReturnClientFd)
{
    if (close(serverFd) < 0) {
        FI_HILOGE("Close server fd failed, error:%{public}s, serverFd:%{public}d", strerror(errno), serverFd);
    }
    serverFd = -1;
    if (close(toReturnClientFd) < 0) {
        FI_HILOGE("Close fd failed, error:%{public}s, toReturnClientFd:%{public}d", strerror(errno), toReturnClientFd);
    }
    toReturnClientFd = -1;
    return RET_ERR;
}

void StreamServer::SetRecvFun(MsgServerFunCallback fun)
{
    recvFun_ = fun;
}

void StreamServer::ReleaseSession(int32_t fd, epoll_event &ev)
{
    auto secPtr = GetSession(fd);
    if (secPtr != nullptr) {
        OnDisconnected(secPtr);
        DelSession(fd);
    }
    if (ev.data.ptr) {
        free(ev.data.ptr);
        ev.data.ptr = nullptr;
    }
    if (auto it = circleBufs_.find(fd); it != circleBufs_.end()) {
        circleBufs_.erase(it);
    }
    auto DeviceStatusService = DeviceStatus::DelayedSpSingleton<DeviceStatus::DeviceStatusService>::GetInstance();
    DeviceStatusService->DelEpoll(EPOLL_EVENT_SOCKET, fd);
    if (close(fd) < 0) {
        FI_HILOGE("Close fd failed, error:%{public}s, fd:%{public}d", strerror(errno), fd);
    }
}

void StreamServer::OnPacket(int32_t fd, NetPacket &pkt)
{
    auto sess = GetSession(fd);
    CHKPV(sess);
    recvFun_(sess, pkt);
}

void StreamServer::OnEpollRecv(int32_t fd, epoll_event &ev)
{
    if (fd < 0) {
        FI_HILOGE("Invalid fd:%{public}d", fd);
        return;
    }
    auto& buf = circleBufs_[fd];
    char szBuf[MAX_PACKET_BUF_SIZE] = { 0 };
    for (int32_t i = 0; i < MAX_RECV_LIMIT; i++) {
        ssize_t size = recv(fd, szBuf, MAX_PACKET_BUF_SIZE, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (size > 0) {
            if (!buf.Write(szBuf, size)) {
                FI_HILOGW("Write data failed, size:%{public}zd", size);
            }
            OnReadPackets(buf, [this, fd](NetPacket &pkt) { this->OnPacket(fd, pkt); });
        } else if (size < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                FI_HILOGD("Continue for errno EAGAIN|EINTR|EWOULDBLOCK size:%{public}zd errno:%{public}d",
                    size, errno);
                continue;
            }
            FI_HILOGE("Recv return %{public}zd, errno:%{public}d", size, errno);
            break;
        } else {
            FI_HILOGE("The client side disconnect with the server, size:0, errno:%{public}d", errno);
            ReleaseSession(fd, ev);
            break;
        }
        if (static_cast<size_t>(size) < MAX_PACKET_BUF_SIZE) {
            break;
        }
    }
}

void StreamServer::OnEpollEvent(epoll_event &ev)
{
    CHKPV(ev.data.ptr);
    int32_t fd = *static_cast<int32_t*>(ev.data.ptr);
    if (fd < 0) {
        FI_HILOGE("The fd less than 0, errCode:%{public}d", PARAM_INPUT_INVALID);
        return;
    }
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        FI_HILOGI("EPOLLERR or EPOLLHUP, fd:%{public}d, ev.events:0x%{public}x", fd, ev.events);
        ReleaseSession(fd, ev);
    } else if (ev.events & EPOLLIN) {
        OnEpollRecv(fd, ev);
    }
}

void StreamServer::DumpSession(const std::string &title)
{
    FI_HILOGD("in %{public}s:%{public}s", __func__, title.c_str());
    int32_t i = 0;
    for (auto &[key, value] : sessionss_) {
        CHKPV(value);
        i++;
    }
}

SessionPtr StreamServer::GetSession(int32_t fd) const
{
    auto it = sessionss_.find(fd);
    if (it == sessionss_.end()) {
        FI_HILOGE("Session not found, fd:%{public}d", fd);
        return nullptr;
    }
    CHKPP(it->second);
    return it->second->GetSharedPtr();
}

SessionPtr StreamServer::GetSessionByPid(int32_t pid) const
{
    int32_t fd = GetClientFd(pid);
    if (fd <= 0) {
        FI_HILOGE("Session not found, pid:%{public}d", pid);
        return nullptr;
    }
    return GetSession(fd);
}

bool StreamServer::AddSession(SessionPtr ses)
{
    CHKPF(ses);
    FI_HILOGI("pid:%{public}d, fd:%{public}d", ses->GetPid(), ses->GetFd());
    int32_t fd = ses->GetFd();
    if (fd < 0) {
        FI_HILOGE("The fd is less than 0");
        return false;
    }
    int32_t pid = ses->GetPid();
    if (pid <= 0) {
        FI_HILOGE("Get process failed");
        return false;
    }
    if (sessionss_.size() > MAX_SESSION_ALARM) {
        FI_HILOGE("Too many clients, Warning Value:%{public}zu, Current Value:%{public}zu",
            MAX_SESSION_ALARM, sessionss_.size());
        return false;
    }
    DumpSession("AddSession");
    idxPids_[pid] = fd;
    sessionss_[fd] = ses;
    FI_HILOGI("Add session end");
    return true;
}

void StreamServer::DelSession(int32_t fd)
{
    CALL_DEBUG_ENTER;
    FI_HILOGI("fd:%{public}d", fd);
    if (fd < 0) {
        FI_HILOGE("The fd less than 0, errCode:%{public}d", PARAM_INPUT_INVALID);
        return;
    }
    int32_t pid = GetClientPid(fd);
    if (pid > 0) {
        idxPids_.erase(pid);
    }
    auto it = sessionss_.find(fd);
    if (it != sessionss_.end()) {
        NotifySessionDeleted(it->second);
        sessionss_.erase(it);
    }
    DumpSession("DelSession");
}

void StreamServer::AddSessionDeletedCallback(int32_t pid, std::function<void(SessionPtr)> callback)
{
    CALL_DEBUG_ENTER;
    auto it = callbacks_.find(pid);
    if (it != callbacks_.end()) {
        FI_HILOGW("Deleted session already exists");
        return;
    }
    callbacks_[pid] = callback;
}

void StreamServer::NotifySessionDeleted(SessionPtr ses)
{
    CALL_DEBUG_ENTER;
    auto it = callbacks_.find(ses->GetPid());
    if (it != callbacks_.end()) {
        it->second(ses);
        callbacks_.erase(it);
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
