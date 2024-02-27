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

#ifndef INPUT_EVENT_BUILDER_H
#define INPUT_EVENT_BUILDER_H

#include "display_manager.h"
#include "key_event.h"
#include "nocopyable.h"
#include "pointer_event.h"

#include "cooperate_events.h"
#include "i_context.h"
#include "i_dsoftbus_adapter.h"
#include "net_packet.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
class Context;

class InputEventBuilder final {
    class DSoftbusObserver final : public IDSoftbusObserver {
    public:
        DSoftbusObserver(InputEventBuilder &parent) : parent_(parent) {}
        ~DSoftbusObserver() = default;

        void OnBind(const std::string &networkId) override {}
        void OnShutdown(const std::string &networkId) override {}

        bool OnPacket(const std::string &networkId, Msdp::NetPacket &packet) override
        {
            return parent_.OnPacket(networkId, packet);
        }

    private:
        InputEventBuilder &parent_;
    };

    struct CursorPosition {
        Rosen::DisplayId displayId { Rosen::DISPLAY_ID_INVALID };
        Coordinate pos {};
    };

public:
    InputEventBuilder(IContext *env);
    ~InputEventBuilder() = default;
    DISALLOW_COPY_AND_MOVE(InputEventBuilder);

    void Enable(Context &context);
    void Disable();
    void Update(Context &context);

    static bool IsLocalEvent(const InputPointerEvent &event);

private:
    bool OnPacket(const std::string &networkId, Msdp::NetPacket &packet);
    void OnPointerEvent(Msdp::NetPacket &packet);
    void OnKeyEvent(Msdp::NetPacket &packet);
    bool AccumulateMotion(std::shared_ptr<MMI::PointerEvent> pointerEvent);
    bool IsInDisplay(sptr<Rosen::Display> display) const;
    bool UpdatePointerEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent);
    void ResetKeyEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const;

    IContext *env_ { nullptr };
    CursorPosition cursorPos_ {};
    std::string remoteNetworkId_;
    std::shared_ptr<DSoftbusObserver> observer_;
    std::shared_ptr<MMI::PointerEvent> pointerEvent_;
    std::shared_ptr<MMI::KeyEvent> keyEvent_;
};

inline bool InputEventBuilder::IsLocalEvent(const InputPointerEvent &event)
{
    return (event.deviceId >= 0);
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INPUT_EVENT_BUILDER_H