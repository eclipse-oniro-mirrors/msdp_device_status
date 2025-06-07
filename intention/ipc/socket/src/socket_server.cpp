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

#include "socket_server.h"

#include "accesstoken_kit.h"

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "SocketServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

SocketServer::SocketServer(IContext *context) : context_(context) { }

int32_t SocketServer::Socket(CallingContext &context, const std::string& programName, int32_t moduleType,
    int& socketFd, int32_t& tokenType)
{
    CALL_INFO_TRACE;
    FI_HILOGI("programName:%{public}s, moduleType:%{public}d, socketFd:%{private}d, tokenType:%{private}d",
        programName.c_str(), moduleType, socketFd, tokenType);
    int32_t clientTokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    int32_t clientFd { -1 };
    CHKPR(context_, RET_ERR);
    int32_t ret = context_->GetSocketSessionManager().AllocSocketFd(
        programName, moduleType, clientTokenType, context.uid, context.pid, clientFd);
    if (ret != RET_OK) {
        FI_HILOGE("AllocSocketFd failed");
        if (clientFd >= 0 && close(clientFd) < 0) {
            FI_HILOGE("Close client fd failed, error:%{public}s, clientFd:%{private}d", strerror(errno), clientFd);
        }
        return RET_ERR;
    }
    socketFd = clientFd;
    tokenType = clientTokenType;
    return RET_OK;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
