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

#ifndef SOCKET_SERVER_H
#define SOCKET_SERVER_H

#include "nocopyable.h"

#include "i_context.h"
#include "i_plugin.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SocketServer final {
public:
    SocketServer(IContext *context);
    ~SocketServer() = default;
    DISALLOW_COPY_AND_MOVE(SocketServer);
    int32_t Socket(CallingContext &context, const std::string &programName, int32_t moduleType,
        int &socketFd, int32_t &tokenType);
private:
    IContext *context_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SOCKET_SERVER_H
