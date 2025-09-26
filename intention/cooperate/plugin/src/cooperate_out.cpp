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

#include "cooperate_out.h"
#include "cooperate_hisysevent.h"

#include "devicestatus_define.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "CooperateOut"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {

CooperateOut::CooperateOut(IStateMachine &parent, IContext *env)
    : ICooperateState(parent), env_(env)
{
    initial_ = std::make_shared<Initial>(*this);
    Initial::BuildChains(initial_, *this);
    current_ = initial_;
}

CooperateOut::~CooperateOut()
{
    Initial::RemoveChains(initial_);
}

void CooperateOut::OnEvent(Context &context, const CooperateEvent &event)
{
    current_->OnEvent(context, event);
}

void CooperateOut::OnEnterState(Context &context)
{
    CALL_INFO_TRACE;
    int32_t ret = env_->GetInput().SetPointerVisibility(false);
    if (ret != RET_OK) {
        CooperateRadarInfo radarInfo {
            .funcName = __FUNCTION__,
            .bizState = static_cast<int32_t> (BizState::STATE_IDLE),
            .bizStage = static_cast<int32_t> (BizCooperateStage::STAGE_SET_CURSOR_VISIBILITY),
            .stageRes = static_cast<int32_t> (BizCooperateStageRes::RES_FAIL),
            .bizScene = static_cast<int32_t> (BizCooperateScene::SCENE_ACTIVE),
            .errCode = static_cast<int32_t> (CooperateRadarErrCode::SET_CURSOR_VISIBILITY_FAILED),
            .hostName = "",
            .localNetId = "",
            .peerNetId = ""
        };
        CooperateRadar::ReportCooperateRadarInfo(radarInfo);
    }
}

void CooperateOut::OnLeaveState(Context &context)
{
    CALL_INFO_TRACE;
    SetPointerVisible(context);
}

void CooperateOut::SetPointerVisible(Context &context)
{
    CHKPV(env_);
    bool hasLocalPointerDevice =  env_->GetDeviceManager().HasLocalPointerDevice() ||
        env_->GetInput().HasLocalPointerDevice() ||
        env_->GetDeviceManager().HasPencilAirMouse();
    bool visible = !context.NeedHideCursor() && hasLocalPointerDevice;
    FI_HILOGI("Set pointer visible:%{public}s, HasLocalPointerDevice:%{public}s",
        visible ? "true" : "false", hasLocalPointerDevice ? "true" : "false");
    env_->GetInput().SetPointerVisibility(visible, PRIORITY);
}

void CooperateOut::SimulateShowPointerEvent()
{
    CALL_INFO_TRACE;
    CHKPV(env_);
    auto pointerEvent = OHOS::MMI::PointerEvent::Create();
    OHOS::MMI::PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetRawDx(0);
    item.SetRawDy(0);
    CHKPV(pointerEvent);
    pointerEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(OHOS::MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddPointerItem(item);
    if (!pressedButtons_.empty()) {
        FI_HILOGI("Has pressed buttons");
        for (auto buttonId : pressedButtons_) {
            pointerEvent->SetButtonPressed(buttonId);
        }
    }
    env_->GetInput().SimulateInputEvent(pointerEvent);
}

void CooperateOut::Initial::BuildChains(std::shared_ptr<Initial> self, CooperateOut &parent)
{}

void CooperateOut::Initial::RemoveChains(std::shared_ptr<Initial> self)
{}

CooperateOut::Initial::Initial(CooperateOut &parent)
    : ICooperateStep(parent, nullptr), parent_(parent)
{
    AddHandler(CooperateEventType::DISABLE, [this](Context &context, const CooperateEvent &event) {
        this->OnDisable(context, event);
    });
    AddHandler(CooperateEventType::START, [this](Context &context, const CooperateEvent &event) {
        this->OnStart(context, event);
    });
    AddHandler(CooperateEventType::WITH_OPTIONS_START, [this](Context &context, const CooperateEvent &event) {
        this->OnStartWithOptions(context, event);
    });
    AddHandler(CooperateEventType::STOP, [this](Context &context, const CooperateEvent &event) {
        this->OnStop(context, event);
    });
    AddHandler(CooperateEventType::APP_CLOSED, [this](Context &context, const CooperateEvent &event) {
        this->OnAppClosed(context, event);
    });
    AddHandler(CooperateEventType::INPUT_HOTPLUG_EVENT, [this](Context &context, const CooperateEvent &event) {
        this->OnHotplug(context, event);
    });
    AddHandler(CooperateEventType::DDM_BOARD_OFFLINE, [this](Context &context, const CooperateEvent &event) {
        this->OnBoardOffline(context, event);
    });
    AddHandler(CooperateEventType::DDP_COOPERATE_SWITCH_CHANGED,
        [this](Context &context, const CooperateEvent &event) {
            this->OnSwitchChanged(context, event);
    });
    AddHandler(CooperateEventType::DSOFTBUS_SESSION_CLOSED,
        [this](Context &context, const CooperateEvent &event) {
            this->OnSoftbusSessionClosed(context, event);
    });
    AddHandler(CooperateEventType::DSOFTBUS_COME_BACK,
        [this](Context &context, const CooperateEvent &event) {
            this->OnComeBack(context, event);
    });
    AddHandler(CooperateEventType::DSOFTBUS_START_COOPERATE,
        [this](Context &context, const CooperateEvent &event) {
            this->OnRemoteStart(context, event);
    });
    AddHandler(CooperateEventType::DSOFTBUS_STOP_COOPERATE,
        [this](Context &context, const CooperateEvent &event) {
            this->OnRemoteStop(context, event);
    });
    AddHandler(CooperateEventType::DSOFTBUS_RELAY_COOPERATE,
        [this](Context &context, const CooperateEvent &event) {
            this->OnRelay(context, event);
    });
    AddHandler(CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        [this](Context &context, const CooperateEvent &event) {
            this->OnRemoteStartWithOptions(context, event);
    });
    AddHandler(CooperateEventType::DSOFTBUS_COME_BACK_WITH_OPTIONS,
        [this](Context &context, const CooperateEvent &event) {
            this->OnComeBackWithOptions(context, event);
    });
    AddHandler(CooperateEventType::DSOFTBUS_RELAY_COOPERATE_WITHOPTIONS,
        [this](Context &context, const CooperateEvent &event) {
            this->OnRelayWithOptions(context, event);
    });
    AddHandler(CooperateEventType::STOP_ABOUT_VIRTUALTRACKPAD,
        [this](Context &context, const CooperateEvent &event) {
            this->OnStopAboutVirtualTrackpad(context, event);
    });
    AddHandler(CooperateEventType::INPUT_POINTER_EVENT,
        [this](Context &context, const CooperateEvent &event) {
            this->OnPointerEvent(context, event);
    });
}

void CooperateOut::Initial::OnPointerEvent(Context &context, const CooperateEvent &event)
{
    CALL_DEBUG_ENTER;
    InputPointerEvent notice = std::get<InputPointerEvent>(event.event);
    parent_.pressedButtons_ = notice.pressedButtons;
}

void CooperateOut::Initial::OnDisable(Context &context, const CooperateEvent &event)
{
    FI_HILOGI("[disable cooperation] Stop cooperation");
    parent_.StopCooperate(context, event);
}

void CooperateOut::Initial::OnStart(Context &context, const CooperateEvent &event)
{
    StartCooperateEvent param = std::get<StartCooperateEvent>(event.event);
    CHKPV(parent_.env_);
    if (parent_.env_->GetDragManager().GetDragState() == DragState::MOTION_DRAGGING) {
        FI_HILOGE("Not allow cooperate");
        NotAollowCooperateWhenMotionDragging result {
            .pid = param.pid,
            .userData = param.userData,
            .networkId = param.remoteNetworkId,
            .success = false,
            .errCode = static_cast<int32_t>(CoordinationErrCode::NOT_AOLLOW_COOPERATE_WHEN_MOTION_DRAGGING)
        };
        context.eventMgr_.ErrorNotAollowCooperateWhenMotionDragging(result);
        return;
    }
    context.eventMgr_.StartCooperate(param);
    FI_HILOGI("[start] Start cooperation with \'%{public}s\', report success when out",
        Utility::Anonymize(context.Peer()).c_str());
    DSoftbusStartCooperateFinished failNotice {
        .success = false,
        .errCode = static_cast<int32_t>(CoordinationErrCode::UNEXPECTED_START_CALL)
    };
    context.eventMgr_.StartCooperateFinish(failNotice);
}

void CooperateOut::Initial::OnStartWithOptions(Context &context, const CooperateEvent &event)
{
    StartWithOptionsEvent param = std::get<StartWithOptionsEvent>(event.event);
    CHKPV(parent_.env_);
    if (parent_.env_->GetDragManager().GetDragState() == DragState::MOTION_DRAGGING) {
        FI_HILOGE("Not allow cooperate");
        NotAollowCooperateWhenMotionDragging result {
            .pid = param.pid,
            .userData = param.userData,
            .networkId = param.remoteNetworkId,
            .success = false,
            .errCode = static_cast<int32_t>(CoordinationErrCode::NOT_AOLLOW_COOPERATE_WHEN_MOTION_DRAGGING)
        };
        context.eventMgr_.ErrorNotAollowCooperateWhenMotionDragging(result);
        return;
    }
    context.eventMgr_.StartCooperateWithOptions(param);
    FI_HILOGI("[start] Start cooperation with Options\'%{public}s\', report success when out",
        Utility::Anonymize(context.Peer()).c_str());
    DSoftbusCooperateOptions failNotice {
        .success = false,
        .errCode = static_cast<int32_t>(CoordinationErrCode::UNEXPECTED_START_CALL)
    };
    context.eventMgr_.StartCooperateWithOptionsFinish(failNotice);
}

void CooperateOut::Initial::OnStop(Context &context, const CooperateEvent &event)
{
    StopCooperateEvent param = std::get<StopCooperateEvent>(event.event);

    context.eventMgr_.StopCooperate(param);
    FI_HILOGI("[stop] Stop cooperation with \'%{public}s\', unchain:%{public}d",
        Utility::Anonymize(context.Peer()).c_str(), param.isUnchained);
    parent_.StopCooperate(context, event);

    param.networkId = context.Peer();
    DSoftbusStopCooperateFinished notice {
        .networkId = context.Peer(),
        .normal = true,
    };
    context.eventMgr_.StopCooperateFinish(notice);

    parent_.UnchainConnections(context, param);
}

void CooperateOut::Initial::OnComeBack(Context &context, const CooperateEvent &event)
{
    CALL_INFO_TRACE;
    DSoftbusComeBack notice = std::get<DSoftbusComeBack>(event.event);

    if (!context.IsPeer(notice.networkId)) {
        return;
    }
    FI_HILOGI("[come back] From \'%{public}s\'", Utility::Anonymize(notice.networkId).c_str());
    context.OnRemoteStartCooperate(notice.extra);
    DSoftbusStartCooperate startEvent {
        .networkId = notice.networkId,
    };
    context.eventMgr_.RemoteStart(startEvent);
    context.inputEventInterceptor_.Disable();

    context.RemoteStartSuccess(notice);
    context.eventMgr_.RemoteStartFinish(notice);
    TransiteTo(context, CooperateState::COOPERATE_STATE_FREE);
    context.OnBack();
    if (!context.NeedHideCursor()) {
        parent_.SimulateShowPointerEvent();
    }
}

void CooperateOut::Initial::OnComeBackWithOptions(Context &context, const CooperateEvent &event)
{
    CALL_INFO_TRACE;
    DSoftbusCooperateOptions notice = std::get<DSoftbusCooperateOptions>(event.event);

    if (!context.IsPeer(notice.networkId)) {
        return;
    }
    FI_HILOGI("[come back cooperate with options] From \'%{public}s\'", Utility::Anonymize(notice.networkId).c_str());
    context.OnRemoteStartCooperate(notice.extra);
    DSoftbusStartCooperate startEvent{
        .networkId = notice.networkId,
    };
    context.eventMgr_.RemoteStart(startEvent);
    context.inputEventInterceptor_.Disable();

    context.OnRemoteStart(notice);
    context.eventMgr_.RemoteStartWithOptionsFinish(notice);
    TransiteTo(context, CooperateState::COOPERATE_STATE_FREE);
    context.OnBack();
    if (!context.NeedHideCursor()) {
        parent_.SimulateShowPointerEvent();
    }
}

void CooperateOut::Initial::OnRemoteStart(Context &context, const CooperateEvent &event)
{
    DSoftbusStartCooperate notice = std::get<DSoftbusStartCooperate>(event.event);

    if (context.IsLocal(notice.networkId)) {
        return;
    }
    FI_HILOGI("[remote start] Request from \'%{public}s\'", Utility::Anonymize(notice.networkId).c_str());
    if (context.IsPeer(notice.networkId)) {
        FI_HILOGI("[remote start] Reset on request from peer");
        parent_.StopCooperate(context, event);
        return;
    }
    context.OnResetCooperation();
    context.OnRemoteStartCooperate(notice.extra);
    context.eventMgr_.RemoteStart(notice);
    context.inputEventInterceptor_.Disable();

    DSoftbusStopCooperate stopNotice {};
    context.dsoftbus_.StopCooperate(context.Peer(), stopNotice);

    context.RemoteStartSuccess(notice);
    context.inputEventBuilder_.Enable(context);
    context.eventMgr_.RemoteStartFinish(notice);
    FI_HILOGI("[remote start] Cooperation with \'%{public}s\' established", Utility::Anonymize(context.Peer()).c_str());
    TransiteTo(context, CooperateState::COOPERATE_STATE_IN);
    context.OnTransitionIn();
}

void CooperateOut::Initial::OnRemoteStartWithOptions(Context &context, const CooperateEvent &event)
{
    DSoftbusCooperateOptions notice = std::get<DSoftbusCooperateOptions>(event.event);
    if (context.IsLocal(notice.networkId)) {
        return;
    }
    FI_HILOGI("[remote start cooperate with options ] Request from '%{public}s'",
        Utility::Anonymize(notice.networkId).c_str());
    if (context.IsPeer(notice.networkId)) {
        FI_HILOGI("[remote start] Reset on request from peer");
        parent_.StopCooperate(context, event);
        return;
    }
    context.OnResetCooperation();
    context.OnRemoteStartCooperate(notice.extra);
    context.eventMgr_.RemoteStartWithOptions(notice);
    context.inputEventInterceptor_.Disable();

    DSoftbusStopCooperate stopNotice{};
    context.dsoftbus_.StopCooperate(context.Peer(), stopNotice);

    context.OnRemoteStart(notice);
    context.inputEventBuilder_.Enable(context);
    context.eventMgr_.RemoteStartWithOptionsFinish(notice);
    FI_HILOGI("[remote start] Cooperation with \'%{public}s\' established", Utility::Anonymize(context.Peer()).c_str());
    TransiteTo(context, CooperateState::COOPERATE_STATE_IN);
    context.OnTransitionIn();
}

void CooperateOut::Initial::OnRemoteStop(Context &context, const CooperateEvent &event)
{
    DSoftbusStopCooperate notice = std::get<DSoftbusStopCooperate>(event.event);

    if (!context.IsPeer(notice.networkId)) {
        return;
    }
    FI_HILOGI("[remote stop] Notification from \'%{public}s\'", Utility::Anonymize(notice.networkId).c_str());
    context.eventMgr_.RemoteStop(notice);
    context.inputEventInterceptor_.Disable();
    context.ResetCursorPosition();
    context.eventMgr_.RemoteStopFinish(notice);
    TransiteTo(context, CooperateState::COOPERATE_STATE_FREE);
    context.OnResetCooperation();
}

void CooperateOut::Initial::OnRelay(Context &context, const CooperateEvent &event)
{
    DSoftbusRelayCooperate notice = std::get<DSoftbusRelayCooperate>(event.event);
    if (!context.IsPeer(notice.networkId)) {
        return;
    }
    DSoftbusRelayCooperateFinished resp {
        .targetNetworkId = notice.targetNetworkId,
        .uid = notice.uid,
    };

    int32_t ret = context.dsoftbus_.OpenSession(notice.targetNetworkId);
    if (ret != RET_OK) {
        FI_HILOGE("[relay cooperate] Failed to connect to \'%{public}s\'",
            Utility::Anonymize(notice.targetNetworkId).c_str());
        resp.normal = false;
        context.dsoftbus_.RelayCooperateFinish(notice.networkId, resp);
        return;
    }

    resp.normal = true;
    context.dsoftbus_.RelayCooperateFinish(notice.networkId, resp);

    context.RelayCooperate(notice);
    context.inputEventInterceptor_.Update(context);
    FI_HILOGI("[relay cooperate] Relay cooperation to \'%{public}s\'", Utility::Anonymize(context.Peer()).c_str());
    context.OnRelayCooperation(context.Peer(), context.NormalizedCursorPosition());
}

void CooperateOut::Initial::OnRelayWithOptions(Context &context, const CooperateEvent &event)
{
    DSoftbusRelayCooperate notice = std::get<DSoftbusRelayCooperate>(event.event);
    if (!context.IsPeer(notice.networkId)) {
        return;
    }
    DSoftbusRelayCooperateFinished resp {
        .targetNetworkId = notice.targetNetworkId,
        .uid = notice.uid,
    };

    int32_t ret = context.dsoftbus_.OpenSession(notice.targetNetworkId);
    if (ret != RET_OK) {
        FI_HILOGE("[relay cooperate] Failed to connect to \'%{public}s\'",
            Utility::Anonymize(notice.targetNetworkId).c_str());
        resp.normal = false;
        context.dsoftbus_.RelayCooperateWithOptionsFinish(notice.networkId, resp);
        return;
    }

    resp.normal = true;
    context.dsoftbus_.RelayCooperateWithOptionsFinish(notice.networkId, resp);

    context.RelayCooperate(notice);
    context.inputEventInterceptor_.Update(context);
    FI_HILOGI("[relay cooperate] Relay cooperation to \'%{public}s\'", Utility::Anonymize(context.Peer()).c_str());
    context.OnRelayCooperation(context.Peer(), context.NormalizedCursorPosition());
}

void CooperateOut::Initial::OnHotplug(Context &context, const CooperateEvent &event)
{
    InputHotplugEvent notice = std::get<InputHotplugEvent>(event.event);
    if (context.GetVirtualTrackpadDeviceId() > 0) {
        return;
    } else if ((context.GetVirtualTrackpadDeviceId() <= 0) &&
        !(parent_.env_->GetDeviceManager().HasLocalPointerDevice())) {
            FI_HILOGI("Cur device not exist pointer device");
            parent_.StopCooperate(context, event);
    } else if (notice.deviceId != context.StartDeviceId()) {
        return;
    }
    FI_HILOGI("Stop cooperation on unplug of dedicated pointer");
    parent_.StopCooperate(context, event);
}

void CooperateOut::Initial::OnAppClosed(Context &context, const CooperateEvent &event)
{
    FI_HILOGI("[app closed] Close all connections");
    context.dsoftbus_.CloseAllSessions();
    FI_HILOGI("[app closed] Stop cooperation");
    parent_.StopCooperate(context, event);
}

void CooperateOut::Initial::OnBoardOffline(Context &context, const CooperateEvent &event)
{
    DDMBoardOfflineEvent notice = std::get<DDMBoardOfflineEvent>(event.event);

    if (!context.IsPeer(notice.networkId)) {
        return;
    }
    FI_HILOGI("[board offline] Peer(\'%{public}s\') is offline", Utility::Anonymize(notice.networkId).c_str());
    parent_.StopCooperate(context, event);
}

void CooperateOut::Initial::OnSwitchChanged(Context &context, const CooperateEvent &event)
{
    DDPCooperateSwitchChanged notice = std::get<DDPCooperateSwitchChanged>(event.event);

    if (!context.IsPeer(notice.networkId) || notice.normal) {
        return;
    }
    FI_HILOGI("[switch off] Peer(\'%{public}s\') switch off", Utility::Anonymize(notice.networkId).c_str());
    parent_.StopCooperate(context, event);
}

void CooperateOut::Initial::OnSoftbusSessionClosed(Context &context, const CooperateEvent &event)
{
    DSoftbusSessionClosed notice = std::get<DSoftbusSessionClosed>(event.event);

    if (!context.IsPeer(notice.networkId)) {
        return;
    }
    FI_HILOGI("[dsoftbus session closed] Disconnected with \'%{public}s\'",
        Utility::Anonymize(notice.networkId).c_str());
    parent_.StopCooperate(context, event);
}

void CooperateOut::Initial::OnStopAboutVirtualTrackpad(Context &context, const CooperateEvent &event)
{
    CALL_INFO_TRACE;
    CHKPV(parent_.env_);
    bool hasLocalPointerDevice =  parent_.env_->GetDeviceManager().HasLocalPointerDevice();
    if (!hasLocalPointerDevice) {
        parent_.StopCooperate(context, event);
    }
}

void CooperateOut::Initial::OnProgress(Context &context, const CooperateEvent &event)
{}

void CooperateOut::Initial::OnProgressWithOptions(Context &context, const CooperateEvent &event)
{}

void CooperateOut::Initial::OnReset(Context &context, const CooperateEvent &event)
{}

void CooperateOut::StopCooperate(Context &context, const CooperateEvent &event)
{
    context.inputEventInterceptor_.Disable();

    DSoftbusStopCooperate notice {};
    context.dsoftbus_.StopCooperate(context.Peer(), notice);

    context.ResetCursorPosition();
    TransiteTo(context, CooperateState::COOPERATE_STATE_FREE);
    context.OnResetCooperation();
}

void CooperateOut::UnchainConnections(Context &context, const StopCooperateEvent &event) const
{
    if (event.isUnchained) {
        FI_HILOGI("Unchain all connections");
        context.dsoftbus_.CloseAllSessions();
        context.eventMgr_.OnUnchain(event);
    }
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
