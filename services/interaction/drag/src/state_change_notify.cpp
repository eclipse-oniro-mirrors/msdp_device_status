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

#include "state_change_notify.h"

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "StateChangeNotify"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
void StateChangeNotify::AddNotifyMsg(std::shared_ptr<MessageInfo> info)
{
    CHKPV(info);
    auto it = std::find_if(msgInfos_[info->msgType].begin(), msgInfos_[info->msgType].end(),
        [info] (auto msgInfo) {
            return *msgInfo == info;
        });
    if (it != msgInfos_[info->msgType].end()) {
        FI_HILOGW("info msgType:%{public}d, it:%{public}s, info:%{public}s",
            info->msgType, (*it)->session->ToString().c_str(), info->session->ToString().c_str());
        *it = info;
        return;
    }
    msgInfos_[info->msgType].emplace_back(info);
}

void StateChangeNotify::RemoveNotifyMsg(std::shared_ptr<MessageInfo> info)
{
    if (info == nullptr || msgInfos_.empty() || msgInfos_[info->msgType].empty()) {
        FI_HILOGE("Remove listener failed");
        return;
    }
    auto it = std::find_if(msgInfos_[info->msgType].begin(), msgInfos_[info->msgType].end(),
        [info] (auto msgInfo) {
            return *msgInfo == info;
        });
    if (it != msgInfos_[info->msgType].end()) {
        msgInfos_[info->msgType].erase(it);
        FI_HILOGI("Remove listener success");
    }
}

int32_t StateChangeNotify::StyleChangedNotify(DragCursorStyle style)
{
    if (msgInfos_[MessageType::NOTIFY_STYLE].empty()) {
        FI_HILOGD("No listener, send message failed");
        return RET_ERR;
    }
    for (auto it = msgInfos_[MessageType::NOTIFY_STYLE].begin();
        it != msgInfos_[MessageType::NOTIFY_STYLE].end(); ++it) {
        auto info = *it;
        CHKPC(info);
        OnDragInfoNotify(info->session, info->msgId, style);
    }
    return RET_OK;
}

int32_t StateChangeNotify::StateChangedNotify(DragState state)
{
    CALL_DEBUG_ENTER;
    if (msgInfos_[MessageType::NOTIFY_STATE].empty()) {
        FI_HILOGW("No listener, send message failed");
        return RET_ERR;
    }
    for (auto it = msgInfos_[MessageType::NOTIFY_STATE].begin();
        it != msgInfos_[MessageType::NOTIFY_STATE].end(); ++it) {
        auto info = *it;
        CHKPC(info);
        OnDragInfoNotify(info->session, info->msgId, state);
    }
    return RET_OK;
}

template <typename T>
void StateChangeNotify::OnDragInfoNotify(SocketSessionPtr session, MessageId msgId, T t)
{
    CALL_DEBUG_ENTER;
    CHKPV(session);
    NetPacket pkt(msgId);
    pkt << static_cast<int32_t>(t);
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet write data failed");
        return;
    }
    if (!session->SendMsg(pkt)) {
        FI_HILOGE("Sending failed");
        return;
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
