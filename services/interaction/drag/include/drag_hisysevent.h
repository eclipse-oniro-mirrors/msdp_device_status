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

#ifndef DRAG_HISYSEVENT_H
#define DRAG_HISYSEVENT_H
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#include <map>
#include <string>

#include "devicestatus_define.h"
#include "drag_data.h"
#include "hisysevent.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

enum DragType : int32_t {
    STA_DRAG_SUCC = 0,
    STA_DRAG_FAIL = 1,
    SET_DRAG_WINDOW_SUCC = 2,
    SET_DRAG_WINDOW_FAIL = 3,
    UPDATE_DRAG_STYLE_SUCC = 4,
    UPDATE_DRAG_STYLE_FAIL = 5,
    SEND_TOKENID = 7,
    STOP_DRAG_SUCC = 8,
    STOP_DRAG_FAIL = 9,
    NOTIFY_DRAG_RESULT_SUCC = 10,
    NOTIFY_DRAG_RESULT_FAIL = 11
};

class DragDFX {
public:
    static int32_t WriteStartDrag(const DragState &dragState, OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteDragWindowVisible(const DragState &dragState, bool visible,
        OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteUpdateDragStyle(const DragCursorStyle &style, OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteSendTokenid(int32_t targetTid, const std::string &udKey);
    static int32_t WriteStopDrag(const DragState &dragState, const DragDropResult &dropResult,
        OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteNotifyDragResult(const DragResult &result, OHOS::HiviewDFX::HiSysEvent::EventType type);
    
    template<typename... Types>
    static int32_t WriteModel(const DragType &dragType, Types... paras);

private:
    static std::map<DragState, std::string> dragState_;
    static std::map<DragCursorStyle, std::string> dragStyle_;
    static std::map<DragResult, std::string> dragResult_;
    static std::map<DragType, std::pair<std::string, std::string>> serialStr_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#endif // DRAG_HISYSEVENT_H
