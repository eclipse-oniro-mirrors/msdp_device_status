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

#ifndef DRAG_MANAGER_H
#define DRAG_MANAGER_H

#include <functional>
#include <memory>
#include <vector>

#include "input_manager.h"
#include "i_input_event_consumer.h"
#include "pixel_map.h"

#include "devicestatus_define.h"
#include "drag_data.h"
#include "drag_drawing.h"
#include "stream_session.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DragManager {
public:
    DragManager() : monitorConsumer_(std::make_shared<MonitorConsumer>(nullptr))
    {
    }
    ~DragManager() = default;

    int32_t StartDrag(const DragData &dragData, SessionPtr sess);
    int32_t StopDrag(int32_t result);
    int32_t UpdateDragStyle(int32_t style);
    int32_t UpdateDragMessage(const std::u16string &message);
    int32_t GetDragTargetPid();
    class MonitorConsumer : public MMI::IInputEventConsumer {
    public:
        explicit MonitorConsumer(std::function<void (std::shared_ptr<MMI::PointerEvent>)> cb) : callback_(cb) {}
        void OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const override;
        void OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const override;
        void OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const override;
    private:
        std::function<void (std::shared_ptr<MMI::PointerEvent>)> callback_ { nullptr };
    };
private:
    DragState dragState_ { DragState::FREE };
    int32_t monitorId_ { -1 };
    SessionPtr dragOutSession_;
    int32_t dragTargetPid_ { -1 };
    std::shared_ptr<MonitorConsumer> monitorConsumer_;
    DragDrawing dragDrawing_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DRAG_MANAGER_H