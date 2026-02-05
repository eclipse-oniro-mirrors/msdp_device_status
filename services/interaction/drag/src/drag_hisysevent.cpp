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
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#include "drag_hisysevent.h"

#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DragHiSysEvent"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

std::map<DragState, std::string> DragDFX::dragState_ = {
    { DragState::ERROR, "ERROR" },
    { DragState::START, "START" },
    { DragState::STOP, "STOP" },
    { DragState::CANCEL, "CANCEL" },
    { DragState::MOTION_DRAGGING, "MOTION_DRAGGING" }
};

std::map<DragCursorStyle, std::string> DragDFX::dragStyle_ = {
    { DragCursorStyle::DEFAULT, "DEFAULT" },
    { DragCursorStyle::FORBIDDEN, "FORBIDDEN" },
    { DragCursorStyle::COPY, "COPY" },
    { DragCursorStyle::MOVE, "MOVE" }
};

std::map<DragResult, std::string> DragDFX::dragResult_ = {
    { DragResult::DRAG_SUCCESS, "DRAG_SUCCESS" },
    { DragResult::DRAG_FAIL, "DRAG_FAIL" },
    { DragResult::DRAG_CANCEL, "DRAG_CANCEL" },
    { DragResult::DRAG_EXCEPTION, "DRAG_EXCEPTION" }
};

std::map<DragType, std::pair<std::string, std::string>> DragDFX::serialStr_ = {
    { DragType::STA_DRAG_SUCC, { "START_DRAG_SUCCESS", "Start drag successfully" } },
    { DragType::STA_DRAG_FAIL, { "START_DRAG_FAILED", "Start drag failed" } },
    { DragType::SET_DRAG_WINDOW_SUCC, { "SET_DRAG_WINDOW_VISIBLE_SUCCESS", "Set drag window visible successfully" } },
    { DragType::SET_DRAG_WINDOW_FAIL, { "SET_DRAG_WINDOW_VISIBLE_FAILED", "Set drag window visible failed" } },
    { DragType::UPDATE_DRAG_STYLE_SUCC, { "UPDATE_DRAG_STYLE_SUCCESS", "Update drag style successfully" } },
    { DragType::UPDATE_DRAG_STYLE_FAIL, { "UPDATE_DRAG_STYLE_FAILED", "Update drag style failed"} },
    { DragType::SEND_TOKENID, { "SEND_TOKENID", "Send token id failed" } },
    { DragType::STOP_DRAG_SUCC, { "STOP_DRAG_SUCCESS", "Stop drag successfully" } },
    { DragType::STOP_DRAG_FAIL, { "STOP_DRAG_FAILED", "Stop drag failed"} },
    { DragType::NOTIFY_DRAG_RESULT_SUCC, { "NOTIFY_DRAG_RESULT_SUCCESS", "Notify drag result successfully" } },
    { DragType::NOTIFY_DRAG_RESULT_FAIL, { "NOTIFY_DRAG_RESULT_FAILED", "Notify drag result failed"} }
};

template<typename... Types>
int32_t DragDFX::WriteModel(const DragType &dragType, Types... paras)
{
    if (serialStr_.find(dragType) == serialStr_.end()) {
        FI_HILOGE("serialStr_ can't find the drag hisysevent type:%{public}d", static_cast<int32_t>(dragType));
        return RET_ERR;
    }
    auto &[label, dec] = serialStr_[dragType];
    OHOS::HiviewDFX::HiSysEvent::EventType eventType = (static_cast<uint32_t>(dragType) & 1) != 0 ?
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT : OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR;
    int32_t ret = HiSysEventWrite( OHOS::HiviewDFX::HiSysEvent::Domain::MSDP, label, eventType, "MSG", dec, paras...);
    if (ret == RET_ERR) {
        FI_HILOGE("HiviewDFX write failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DragDFX::WriteStartDrag(const DragState &dragState, OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (dragState_.find(dragState) == dragState_.end()) {
        FI_HILOGE("dragState_ can't find the drag state");
        return RET_ERR;
    }
    std::string curDragState = dragState_[dragState];
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteModel(DragType::STA_DRAG_SUCC, "dragState", curDragState);
    }
    return WriteModel(DragType::STA_DRAG_FAIL, "dragState", curDragState);
}

int32_t DragDFX::WriteDragWindowVisible(const DragState &dragState, bool visible,
    OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (dragState_.find(dragState) == dragState_.end()) {
        FI_HILOGE("dragState_ can't find the drag state");
        return RET_ERR;
    }
    std::string curDragState = dragState_[dragState];
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteModel(DragType::SET_DRAG_WINDOW_SUCC, "IsVisible", visible, "dragState", curDragState);
    }
    return WriteModel(DragType::SET_DRAG_WINDOW_FAIL, "IsVisible", visible, "dragState", curDragState);
}

int32_t DragDFX::WriteUpdateDragStyle(const DragCursorStyle &style, OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (dragStyle_.find(style) == dragStyle_.end()) {
        FI_HILOGE("dragStyle_ can't find the drag style");
        return RET_ERR;
    }
    std::string dragStyle = dragStyle_[style];
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteModel(DragType::UPDATE_DRAG_STYLE_SUCC, "dragStyle", dragStyle);
    }
    return WriteModel(DragType::UPDATE_DRAG_STYLE_FAIL, "dragStyle", dragStyle);
}

int32_t DragDFX::WriteSendTokenid(int32_t targetTid, const std::string &udKey)
{
    return WriteModel(DragType::SEND_TOKENID, "targetTid", targetTid, "udKey", udKey);
}

int32_t DragDFX::WriteStopDrag(const DragState &dragState, const DragDropResult &dropResult,
    OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (dragState_.find(dragState) == dragState_.end()) {
        FI_HILOGE("dragState_ can't find the drag state");
        return RET_ERR;
    }
    std::string curDragState = dragState_[dragState];
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteModel(DragType::STOP_DRAG_SUCC, "dragState", curDragState, "animate",
            dropResult.hasCustomAnimation);
    }
    return WriteModel(DragType::STOP_DRAG_FAIL, "dragState", curDragState, "animate", dropResult.hasCustomAnimation);
}

int32_t DragDFX::WriteNotifyDragResult(const DragResult &result, OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (dragResult_.find(result) == dragResult_.end()) {
        FI_HILOGE("dragResult_ can't find the drag result");
        return RET_ERR;
    }
    std::string dragResult = dragResult_[result];
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteModel(DragType::NOTIFY_DRAG_RESULT_SUCC, "DragResult", dragResult);
    }
    return WriteModel(DragType::NOTIFY_DRAG_RESULT_FAIL, "DragResult", dragResult);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE