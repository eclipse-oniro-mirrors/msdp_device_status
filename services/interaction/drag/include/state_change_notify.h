/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#ifndef STATE_CHANGE_NOTIFY_H
#define STATE_CHANGE_NOTIFY_H

#include <list>
#include <memory>
#include <mutex>

#include "drag_data.h"
#include "i_socket_session.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum class MessageType : int32_t {
    NOTIFY_STATE,
    NOTIFY_STYLE,
    NOTIFY_NONE
};
class StateChangeNotify final {
public:
    StateChangeNotify() = default;
    ~StateChangeNotify() = default;
    struct MessageInfo {
        MessageType msgType { MessageType::NOTIFY_NONE };
        MessageId msgId { MessageId::INVALID };
        SocketSessionPtr session { nullptr };
        DragState state { DragState::ERROR };
        DragCursorStyle style { DragCursorStyle::DEFAULT };
        bool operator==(std::shared_ptr<MessageInfo> info)
        {
            if (info == nullptr || info->session == nullptr) {
                return false;
            }
            return session->GetPid() == info->session->GetPid();
        }
    };
    void RemoveNotifyMsg(std::shared_ptr<MessageInfo> info);
    void AddNotifyMsg(std::shared_ptr<MessageInfo> info);
    int32_t StateChangedNotify(DragState state);
    int32_t StyleChangedNotify(DragCursorStyle style);

private:
    template <typename T>
    void OnDragInfoNotify(SocketSessionPtr session, MessageId msgId, T t);

private:
    std::list<std::shared_ptr<MessageInfo>> msgStateInfos_;
    std::list<std::shared_ptr<MessageInfo>> msgStyleInfos_;
    std::map<MessageType, std::list<std::shared_ptr<MessageInfo>>> msgInfos_ = {
        { MessageType::NOTIFY_STATE, msgStateInfos_ },
        { MessageType::NOTIFY_STYLE, msgStyleInfos_ }
    };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // STATE_CHANGE_NOTIFY_H