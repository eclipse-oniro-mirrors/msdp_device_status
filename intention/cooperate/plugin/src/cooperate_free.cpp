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

#include "cooperate_free.h"
#include "cooperate_hisysevent.h"

#include "devicestatus_define.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "CooperateFree"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {

CooperateFree::CooperateFree(IStateMachine &parent, IContext *env)
    : ICooperateState(parent), env_(env)
{
    initial_ = std::make_shared<Initial>(*this);
    Initial::BuildChains(initial_, *this);
    current_ = initial_;
}

CooperateFree::~CooperateFree()
{
    Initial::RemoveChains(initial_);
}

void CooperateFree::OnEvent(Context &context, const CooperateEvent &event)
{
    current_->OnEvent(context, event);
}

void CooperateFree::OnEnterState(Context &context)
{
    CALL_INFO_TRACE;
}

void CooperateFree::OnLeaveState(Context &context)
{
    CALL_INFO_TRACE;
    UpdateCooperateFlagEvent event {
        .mask = COOPERATE_FLAG_HIDE_CURSOR,
    };
    context.UpdateCooperateFlag(event);
}

void CooperateFree::SetPointerVisible(Context &context)
{
    CHKPV(env_);
    bool hasLocalPointerDevice =  env_->GetDeviceManager().HasLocalPointerDevice() ||
        env_->GetInput().HasLocalPointerDevice();
    bool visible = !context.NeedHideCursor() && hasLocalPointerDevice;
    FI_HILOGI("Set pointer visible:%{public}s, HasLocalPointerDevice:%{public}s",
        visible ? "true" : "false", hasLocalPointerDevice ? "true" : "false");
    env_->GetInput().SetPointerVisibility(visible, PRIORITY);
}

void CooperateFree::UnchainConnections(Context &context, const StopCooperateEvent &event) const
{
    CALL_DEBUG_ENTER;
    if (event.isUnchained) {
        FI_HILOGI("Unchain all connections");
        context.dsoftbus_.CloseAllSessions();
        context.eventMgr_.OnUnchain(event);
    }
}

void CooperateFree::SimulateShowPointerEvent()
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
    env_->GetInput().SimulateInputEvent(pointerEvent);
}

CooperateFree::Initial::Initial(CooperateFree &parent)
    : ICooperateStep(parent, nullptr), parent_(parent)
{
    AddHandler(CooperateEventType::START, [this](Context &context, const CooperateEvent &event) {
        this->OnStart(context, event);
    });
    AddHandler(CooperateEventType::WITH_OPTIONS_START, [this](Context &context, const CooperateEvent &event) {
        this->OnStartWithOptions(context, event);
    });
    AddHandler(CooperateEventType::STOP, [this](Context &context, const CooperateEvent &event) {
        this->OnStop(context, event);
    });
    AddHandler(CooperateEventType::DISABLE, [this](Context &context, const CooperateEvent &event) {
        this->OnDisable(context, event);
    });
    AddHandler(CooperateEventType::APP_CLOSED, [this](Context &context, const CooperateEvent &event) {
        this->OnAppClosed(context, event);
    });
    AddHandler(CooperateEventType::DSOFTBUS_START_COOPERATE, [this](Context &context, const CooperateEvent &event) {
        this->OnRemoteStart(context, event);
    });
    AddHandler(CooperateEventType::INPUT_POINTER_EVENT, [this](Context &context, const CooperateEvent &event) {
        this->OnPointerEvent(context, event);
    });
    AddHandler(CooperateEventType::UPDATE_COOPERATE_FLAG,
        [this](Context &context, const CooperateEvent &event) {
            this->OnUpdateCooperateFlag(context, event);
    });
    AddHandler(CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        [this](Context &context, const CooperateEvent &event) {
            this->OnRemoteStartWithOptions(context, event);
    });
}

void CooperateFree::Initial::OnProgress(Context &context, const CooperateEvent &event)
{}

void CooperateFree::Initial::OnProgressWithOptions(Context &context, const CooperateEvent &event)
{}

void CooperateFree::Initial::OnReset(Context &context, const CooperateEvent &event)
{}

void CooperateFree::Initial::BuildChains(std::shared_ptr<Initial> initial, CooperateFree &parent)
{}

void CooperateFree::Initial::RemoveChains(std::shared_ptr<Initial> initial)
{}

void CooperateFree::Initial::OnStart(Context &context, const CooperateEvent &event)
{
    CALL_INFO_TRACE;
    StartCooperateEvent notice = std::get<StartCooperateEvent>(event.event);
    FI_HILOGI("[start cooperation] With \'%{public}s\'", Utility::Anonymize(notice.remoteNetworkId).c_str());
    context.StartCooperate(notice);
    context.eventMgr_.StartCooperate(notice);

    if (parent_.env_->GetDragManager().GetDragState() == DragState::MOTION_DRAGGING) {
        FI_HILOGE("Not allow cooperate");
        NotAollowCooperateWhenMotionDragging result {
            .pid = notice.pid,
            .userData = notice.userData,
            .networkId = notice.remoteNetworkId,
            .success = false,
            .errCode = static_cast<int32_t>(CoordinationErrCode::NOT_AOLLOW_COOPERATE_WHEN_MOTION_DRAGGING)
        };
        context.eventMgr_.ErrorNotAollowCooperateWhenMotionDragging(result);
        return;
    }
    int32_t ret = context.dsoftbus_.OpenSession(context.Peer());
    if (ret != RET_OK) {
        FI_HILOGE("[start cooperation] Failed to connect to \'%{public}s\'",
            Utility::Anonymize(context.Peer()).c_str());
        CooperateRadarInfo radarInfo {
            .funcName = __FUNCTION__,
            .bizState = static_cast<int32_t> (BizState::STATE_END),
            .bizStage = static_cast<int32_t> (BizCooperateStage::STAGE_OPEN_DSOFTBUS_SESSION),
            .stageRes = static_cast<int32_t> (BizCooperateStageRes::RES_FAIL),
            .bizScene = static_cast<int32_t> (BizCooperateScene::SCENE_ACTIVE),
            .errCode = static_cast<int32_t> (CooperateRadarErrCode::OPEN_DSOFTBUS_SESSION_FAILED),
            .localNetId = Utility::DFXRadarAnonymize(context.Local().c_str()),
            .peerNetId = Utility::DFXRadarAnonymize(notice.remoteNetworkId.c_str())
        };
        CooperateRadar::ReportCooperateRadarInfo(radarInfo);
        int32_t errNum = (ret == RET_ERR ? static_cast<int32_t>(CoordinationErrCode::OPEN_SESSION_FAILED) : ret);
        DSoftbusStartCooperateFinished failNotice {
            .success = false,
            .errCode = errNum
        };
        context.eventMgr_.StartCooperateFinish(failNotice);
        return;
    }
    DSoftbusStartCooperate startNotice {
        .originNetworkId = context.Local(),
        .success = true,
        .cursorPos = context.NormalizedCursorPosition(),
        .pointerSpeed = context.GetPointerSpeed(),
        .touchPadSpeed = context.GetTouchPadSpeed(),
    };
    context.OnStartCooperate(startNotice.extra);
    context.dsoftbus_.StartCooperate(context.Peer(), startNotice);
    context.inputEventInterceptor_.Enable(context);
    context.eventMgr_.StartCooperateFinish(startNotice);
    FI_HILOGI("[start cooperation] Cooperation with \'%{public}s\' established",
        Utility::Anonymize(context.Peer()).c_str());
    TransiteTo(context, CooperateState::COOPERATE_STATE_OUT);
    context.OnTransitionOut();
#ifdef ENABLE_PERFORMANCE_CHECK
    std::ostringstream ss;
    ss << "start_cooperation_with_ " << Utility::Anonymize(context.Peer()).c_str();
    context.FinishTrace(ss.str());
#endif // ENABLE_PERFORMANCE_CHECK
}

void CooperateFree::Initial::OnStop(Context &context, const CooperateEvent &event)
{
    CALL_DEBUG_ENTER;
    StopCooperateEvent param = std::get<StopCooperateEvent>(event.event);
    context.eventMgr_.StopCooperate(param);
    param.networkId = context.Peer();
    DSoftbusStopCooperateFinished notice {
        .networkId = context.Peer(),
        .normal = true,
    };
    context.eventMgr_.StopCooperateFinish(notice);
    context.inputDevMgr_.RemoveVirtualInputDevice(context.Peer());
    parent_.UnchainConnections(context, param);
}

void CooperateFree::Initial::OnStartWithOptions(Context &context, const CooperateEvent &event)
{
    CALL_INFO_TRACE;
    StartWithOptionsEvent notice = std::get<StartWithOptionsEvent>(event.event);
    FI_HILOGI("[start cooperation With Options] With \'%{public}s\'",
        Utility::Anonymize(notice.remoteNetworkId).c_str());
    context.StartCooperateWithOptions(notice);
    context.eventMgr_.StartCooperateWithOptions(notice);
    int32_t ret = context.dsoftbus_.OpenSession(context.Peer());
    if (ret != RET_OK) {
        FI_HILOGE("[start cooperation] Failed to connect to \'%{public}s\'",
            Utility::Anonymize(context.Peer()).c_str());
        int32_t errNum = (ret == RET_ERR ? static_cast<int32_t>(CoordinationErrCode::OPEN_SESSION_FAILED) : ret);
        DSoftbusStartCooperateFinished failNotice {
            .success = false,
            .errCode = errNum
        };
        context.eventMgr_.StartCooperateFinish(failNotice);
        return;
    }
    DSoftbusCooperateOptions startNotice {
        .originNetworkId = context.Local(),
        .success = true,
        .cooperateOptions = {notice.displayX, notice.displayY, notice.displayId},
    };
    context.OnStartCooperate(startNotice.extra);
    context.dsoftbus_.StartCooperateWithOptions(context.Peer(), startNotice);
    context.inputEventInterceptor_.Enable(context);
    context.eventMgr_.StartCooperateWithOptinsFinish(startNotice);
    FI_HILOGI("[start cooperation] Cooperation with \'%{public}s\' established",
        Utility::Anonymize(context.Peer()).c_str());
    TransiteTo(context, CooperateState::COOPERATE_STATE_OUT);
    context.OnTransitionOut();
#ifdef ENABLE_PERFORMANCE_CHECK
    std::ostringstream ss;
    ss << "start_cooperation_with_ " << Utility::Anonymize(context.Peer()).c_str();
    context.FinishTrace(ss.str());
#endif // ENABLE_PERFORMANCE_CHECK
}

void CooperateFree::Initial::OnDisable(Context &context, const CooperateEvent &event)
{
    FI_HILOGI("[disable cooperation] Stop cooperation");
    CHKPV(parent_.env_);
    auto dragState = parent_.env_->GetDragManager().GetDragState();
    if (dragState == DragState::START) {
        FI_HILOGI("drag state is start");
        return;
    }
    bool hasLocalPointerDevice =  parent_.env_->GetDeviceManager().HasLocalPointerDevice() ||
        parent_.env_->GetInput().HasLocalPointerDevice();
    FI_HILOGI("HasLocalPointerDevice:%{public}s", hasLocalPointerDevice ? "true" : "false");
    context.inputDevMgr_.RemoveVirtualInputDevice(context.Peer());
    parent_.env_->GetInput().SetPointerVisibility(hasLocalPointerDevice, PRIORITY);
}

void CooperateFree::Initial::OnAppClosed(Context &context, const CooperateEvent &event)
{
    FI_HILOGI("[app closed] Close all connections");
    context.inputDevMgr_.RemoveVirtualInputDevice(context.Peer());
    context.dsoftbus_.CloseAllSessions();
}

void CooperateFree::Initial::OnRemoteStart(Context &context, const CooperateEvent &event)
{
    CALL_INFO_TRACE;
    DSoftbusStartCooperate notice = std::get<DSoftbusStartCooperate>(event.event);
    context.StorePeerPointerSpeed(notice.pointerSpeed);
    context.StorePeerTouchPadSpeed(notice.touchPadSpeed);
    context.OnRemoteStartCooperate(notice.extra);
    context.eventMgr_.RemoteStart(notice);
    context.RemoteStartSuccess(notice);
    context.inputEventBuilder_.Enable(context);
    context.eventMgr_.RemoteStartFinish(notice);
    context.inputDevMgr_.AddVirtualInputDevice(context.Peer());
    FI_HILOGI("[remote start] Cooperation with \'%{public}s\' established", Utility::Anonymize(context.Peer()).c_str());
    TransiteTo(context, CooperateState::COOPERATE_STATE_IN);
    context.OnTransitionIn();
    if (!context.NeedFreezeCursor()) {
        parent_.SimulateShowPointerEvent();
    }
}

void CooperateFree::Initial::OnRemoteStartWithOptions(Context &context, const CooperateEvent &event)
{
    CALL_INFO_TRACE;
    DSoftbusCooperateOptions notice = std::get<DSoftbusCooperateOptions>(event.event);
    context.OnRemoteStartCooperate(notice.extra);
    context.eventMgr_.RemoteStartWithOptions(notice);
    context.OnRemoteStart(notice);
    context.inputEventBuilder_.Enable(context);
    context.eventMgr_.RemoteStartWithOptionsFinish(notice);
    context.inputDevMgr_.AddVirtualInputDevice(context.Peer());
    FI_HILOGI("[remote start with options] Cooperation with \'%{public}s\' established",
        Utility::Anonymize(context.Peer()).c_str());
    TransiteTo(context, CooperateState::COOPERATE_STATE_IN);
    context.OnTransitionIn();
}

void CooperateFree::Initial::OnPointerEvent(Context &context, const CooperateEvent &event)
{
    CALL_DEBUG_ENTER;
    if (context.NeedHideCursor() && context.IsCooperateWithCrossDrag()) {
        FI_HILOGD("Hide cursor before dragData rcvd when come back");
        return;
    }
    InputPointerEvent notice = std::get<InputPointerEvent>(event.event);
    CHKPV(parent_.env_);
    if (auto dragState = parent_.env_->GetDragManager().GetDragState(); dragState == DragState::START) {
        FI_HILOGD("Current dragState:START");
        return;
    }
    if (InputEventBuilder::IsLocalEvent(notice) && context.NeedHideCursor()) {
        UpdateCooperateFlagEvent event {
            .mask = COOPERATE_FLAG_HIDE_CURSOR,
        };
        context.UpdateCooperateFlag(event);
        parent_.SetPointerVisible(context);
    }
}

void CooperateFree::Initial::OnUpdateCooperateFlag(Context &context, const CooperateEvent &event)
{
    CALL_INFO_TRACE;
    UpdateCooperateFlagEvent notice = std::get<UpdateCooperateFlagEvent>(event.event);
    context.UpdateCooperateFlag(notice);
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
