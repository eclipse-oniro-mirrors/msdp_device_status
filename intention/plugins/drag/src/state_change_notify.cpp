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

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL { LOG_CORE, MSDP_DOMAIN_ID, "StateChangeNotify" };
} // namespace

void StateChangeNotify::AddNotifyMsg(std::shared_ptr<MessageInfo> info)
{
    CALL_DEBUG_ENTER;
    CHKPV(info);
    auto it = std::find_if(msgInfos_.begin(), msgInfos_.end(),
        [info] (std::shared_ptr<MessageInfo> msgInfo) {
            return *msgInfo == info;
        });
    if (it != msgInfos_.end()) {
        return;
    }
    msgInfos_.emplace_back(info);
}

void StateChangeNotify::RemoveNotifyMsg(std::shared_ptr<MessageInfo> info)
{
    CALL_DEBUG_ENTER;
    if (msgInfos_.empty() || info == nullptr) {
        FI_HILOGE("Remove listener failed");
        return;
    }
    auto it = std::find_if(msgInfos_.begin(), msgInfos_.end(),
        [info] (std::shared_ptr<MessageInfo> msgInfo) {
            return *msgInfo == info;
        });
    if (it != msgInfos_.end()) {
        msgInfos_.erase(it);
    }
}

int32_t StateChangeNotify::StateChangedNotify(DragState state)
{
    CALL_DEBUG_ENTER;
    if (msgInfos_.empty()) {
        FI_HILOGW("No listener, send message failed");
        return RET_ERR;
    }
    for (auto it = msgInfos_.begin(); it != msgInfos_.end(); ++it) {
        auto info = *it;
        CHKPC(info);
        OnStateChangedNotify(info->session, info->msgId, state);
    }
    return RET_OK;
}

void StateChangeNotify::OnStateChangedNotify(SessionPtr session, MessageId msgId, DragState state)
{
    CALL_DEBUG_ENTER;
    CHKPV(session);
    NetPacket pkt(msgId);
    pkt << static_cast<int32_t>(state);
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet write data failed");
        return;
    }
    if (!session->SendMsg(pkt)) {
        FI_HILOGE("Sending failed");
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS