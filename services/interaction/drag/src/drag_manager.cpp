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

#include "drag_manager.h"

#include <atomic>

#include "display_info.h"
#include "display_manager.h"
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#include "extra_data.h"
#ifdef MSDP_HIVIEWDFX_HITRACE_ENABLE
#include "hitrace_meter.h"
#endif // MSDP_HIVIEWDFX_HITRACE_ENABLE
#endif // OHOS_BUILD_ENABLE_ARKUI_X
#include "parameters.h"
#include "pixel_map.h"
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifdef MSDP_FRAMEWORK_UDMF_ENABLED
#include "udmf_client.h"
#endif // MSDP_FRAMEWORK_UDMF_ENABLED
#include "unified_types.h"
#include "window_manager_lite.h"
#endif // OHOS_BUILD_ENABLE_ARKUI_X

#include <dlfcn.h>
#include "device_manager.h"
#include "devicestatus_define.h"
#include "drag_data.h"
#include "drag_data_manager.h"
#include "drag_hisysevent.h"
#include "fi_log.h"
#include "devicestatus_proto.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "DragManager"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t TIMEOUT_MS { 3000 };
constexpr int32_t INTERVAL_MS { 500 };
constexpr int32_t POWER_SQUARED { 2 };
constexpr int32_t TEN_POWER { 10 * 10 };
std::atomic<int64_t> g_startFilterTime { -1 };
const std::string DRAG_STYLE_DEFAULT {"DEFAULT"};
const std::string DRAG_STYLE_FORBIDDEN {"FORBIDDEN"};
const std::string DRAG_STYLE_COPY {"COPY"};
const std::string DRAG_STYLE_MOVE {"MOVE"};
const std::string DRAG_STYLE_UNKNOW {"UNKNOW"};
const std::string DRAG_BEHAVIOR {"DRAG_BEHAVIOR"};
const std::string ORG_PKG_NAME {"device_status"};
const std::string APP_VERSION_ID {"1.0.0"};
const std::string DRAG_FRAMEWORK {"DRAG_FRAMEWORK"};
const std::string START_CROSSING_DRAG {"START_CROSSING_DRAG"};
const std::string END_CROSSING_DRAG {"END_CROSSING_DRAG"};
const std::string DEVICE_TYPE_HPR {"HPR"};
const std::string PRODUCT_TYPE = OHOS::system::GetParameter("const.build.product", "HYM");
// 屏幕坐标常量
constexpr int32_t UP_SCREEN_MAX_Y { 1608 };       // 上屏最大 Y 坐标
constexpr int32_t DOWN_SCREEN_MIN_Y { 1690 };     // 下屏最小 Y 坐标
constexpr int32_t DOWN_SCREEN_MAX_Y { 3296 };     // 下屏最大 Y 坐标
constexpr int32_t TARGET_X { 1236 };              // 目标 X 坐标
constexpr int32_t TARGET_Y_DOWN { 1800 };         // 下屏目标 Y 坐标
constexpr int32_t TARGET_Y_UP { 1500 };           // 上屏目标 Y 坐标
constexpr int32_t TIMER_TIMEOUT_MS { 30000 };     // 定时器超时值，30秒

// 角度常量
constexpr double ANGLE_DOWN_MIN { 65.0 };         // 下方角度范围最小值
constexpr double ANGLE_DOWN_MAX { 115.0 };        // 下方角度范围最大值
constexpr double ANGLE_UP_MIN { 245.0 };          // 上方角度范围最小值
constexpr double ANGLE_UP_MAX { 295.0 };          // 上方角度范围最大值
constexpr double ANGLE_LEFT_MIN { 115.0 };        // 左方角度范围最小值
constexpr double ANGLE_LEFT_MAX { 245.0 };        // 左方角度范围最大值
constexpr double FULL_CIRCLE_DEGREES = { 360.0 };
constexpr double ANGLE_EPSILON {1e-9};
#ifdef OHOS_DRAG_ENABLE_INTERCEPTOR
constexpr int32_t DRAG_PRIORITY { 500 };
#endif // OHOS_DRAG_ENABLE_INTERCEPTOR
} // namespace

#ifdef OHOS_BUILD_ENABLE_ARKUI_X
DragManager &DragManager::GetInstance()
{
    static DragManager instance;
    return instance;
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X
DragManager::DragManager() : listener_(this) {}
DragManager::~DragManager()
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    EventHub::UnRegisterEvent(eventHub_);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
int32_t DragManager::Init(IContext* context)
{
    FI_HILOGI("enter");
    CHKPR(context, RET_ERR);
    context_ = context;
    int32_t repeatCount = 1;
    context_->GetTimerManager().AddTimer(INTERVAL_MS, repeatCount, [this]() {
        if (eventHub_ == nullptr) {
            eventHub_ = EventHub::GetEventHub(context_);
        }
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            FI_HILOGE("samgrProxy is nullptr");
            return;
        }
        statusListener_ = new (std::nothrow) DragAbilityStatusChange(eventHub_);
        if (statusListener_ == nullptr) {
            FI_HILOGE("statusListener_ is nullptr");
            return;
        }
        int32_t ret = samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusListener_);
        FI_HILOGI("SubscribeSystemAbility COMMON_EVENT_SERVICE_ID result:%{public}d", ret);
        displayAbilityStatusChange_ = new (std::nothrow) DisplayAbilityStatusChange(context_);
        if (displayAbilityStatusChange_ == nullptr) {
            FI_HILOGE("displayAbilityStatusChange is nullptr");
            return;
        }
        ret = samgrProxy->SubscribeSystemAbility(DISPLAY_MANAGER_SERVICE_SA_ID, displayAbilityStatusChange_);
        FI_HILOGI("SubscribeSystemAbility DISPLAY_MANAGER_SERVICE_SA_ID result:%{public}d", ret);
        appStateObserverStatusChange_ = new (std::nothrow) AppStateObserverStatusChange(context_);
        if (appStateObserverStatusChange_ == nullptr) {
            FI_HILOGE("appStateObserverStatusChange_ is nullptr");
            return;
        }
        ret = samgrProxy->SubscribeSystemAbility(APP_MGR_SERVICE_ID, appStateObserverStatusChange_);
        FI_HILOGI("SubscribeSystemAbility APP_MGR_SERVICE_ID result:%{public}d", ret);
        CollaborationServiceStatusChange_ = new (std::nothrow) CollaborationServiceStatusChange(context_);
        if (CollaborationServiceStatusChange_ == nullptr) {
            FI_HILOGE("CollaborationServiceStatusChange_ is nullptr");
            return;
        }
        ret = samgrProxy->SubscribeSystemAbility(DEVICE_COLLABORATION_SA_ID, CollaborationServiceStatusChange_);
        FI_HILOGI("SubscribeSystemAbility DEVICE_COLLABORATION_SA_ID result:%{public}d", ret);
        if (!RegisterPullThrowListener()) {
            FI_HILOGE("RegisterPullThrowListener fail");
            return;
        }
    });
    FI_HILOGI("leave");
    return RET_OK;
}

void DragManager::OnSessionLost(SocketSessionPtr session)
{
    CHKPV(session);
    RemoveListener(session->GetPid());
}

int32_t DragManager::AddListener(int32_t pid)
{
    FI_HILOGI("enter");
    CHKPR(context_, RET_ERR);
    auto session = context_->GetSocketSessionManager().FindSessionByPid(pid);
    CHKPR(session, RET_ERR);
    auto info = std::make_shared<StateChangeNotify::MessageInfo>();
    info->session = session;
    info->msgId = MessageId::DRAG_STATE_LISTENER;
    info->msgType = MessageType::NOTIFY_STATE;
    stateNotify_.AddNotifyMsg(info);
    context_->GetSocketSessionManager().AddSessionDeletedCallback(pid,
        [this](SocketSessionPtr session) { this->OnSessionLost(session); });
    FI_HILOGI("leave");
    return RET_OK;
}

int32_t DragManager::RemoveListener(int32_t pid)
{
    FI_HILOGI("Remove listener, pid:%{public}d", pid);
    CHKPR(context_, RET_ERR);
    auto session = context_->GetSocketSessionManager().FindSessionByPid(pid);
    CHKPR(session, RET_ERR);
    auto info = std::make_shared<StateChangeNotify::MessageInfo>();
    info->session = session;
    info->msgType = MessageType::NOTIFY_STATE;
    stateNotify_.RemoveNotifyMsg(info);
    FI_HILOGI("leave");
    return RET_OK;
}

int32_t DragManager::AddSubscriptListener(int32_t pid)
{
    FI_HILOGI("enter");
    CHKPR(context_, RET_ERR);
    auto session = context_->GetSocketSessionManager().FindSessionByPid(pid);
    CHKPR(session, RET_ERR);
    auto info = std::make_shared<StateChangeNotify::MessageInfo>();
    info->session = session;
    info->msgId = MessageId::DRAG_STYLE_LISTENER;
    info->msgType = MessageType::NOTIFY_STYLE;
    stateNotify_.AddNotifyMsg(info);
    FI_HILOGI("leave");
    return RET_OK;
}

int32_t DragManager::RemoveSubscriptListener(int32_t pid)
{
    FI_HILOGI("enter");
    CHKPR(context_, RET_ERR);
    auto session = context_->GetSocketSessionManager().FindSessionByPid(pid);
    CHKPR(session, RET_ERR);
    auto info = std::make_shared<StateChangeNotify::MessageInfo>();
    info->msgType = MessageType::NOTIFY_STYLE;
    info->session = session;
    stateNotify_.RemoveNotifyMsg(info);
    FI_HILOGI("leave");
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

void DragManager::PrintDragData(const DragData &dragData, const std::string &packageName)
{
    FI_HILOGI("enter");
    for (const auto& shadowInfo : dragData.shadowInfos) {
        CHKPV(shadowInfo.pixelMap);
        FI_HILOGI("PixelFormat:%{public}d, PixelAlphaType:%{public}d, PixelAllocatorType:%{public}d,"
            " PixelWidth:%{public}d, PixelHeight:%{public}d, shadowX:%{public}d, shadowY:%{public}d",
            static_cast<int32_t>(shadowInfo.pixelMap->GetPixelFormat()),
            static_cast<int32_t>(shadowInfo.pixelMap->GetAlphaType()),
            static_cast<int32_t>(shadowInfo.pixelMap->GetAllocatorType()),
            shadowInfo.pixelMap->GetWidth(), shadowInfo.pixelMap->GetHeight(), shadowInfo.x, shadowInfo.y);
    }
    std::string summarys;
    for (const auto &[udKey, recordSize] : dragData.summarys) {
        std::string str = udKey + "-" + std::to_string(recordSize) + ";";
        summarys += str;
    }
    FI_HILOGI("SourceType:%{public}d, pointerId:%{public}d, displayId:%{public}d,"
        " displayX:%{private}d, displayY:%{private}d, dragNum:%{public}d,"
        " hasCanceledAnimation:%{public}d, udKey:%{public}s, hasCoordinateCorrected:%{public}d, summarys:%{public}s,"
        " packageName:%{public}s, isDragDelay:%{public}d", dragData.sourceType, dragData.pointerId, dragData.displayId,
        dragData.displayX, dragData.displayY, dragData.dragNum, dragData.hasCanceledAnimation,
        GetAnonyString(dragData.udKey).c_str(), dragData.hasCoordinateCorrected, summarys.c_str(), packageName.c_str(),
        dragData.isDragDelay);
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
void DragManager::ResetMouseDragMonitorTimerId(const DragData &dragData)
{
    if ((context_ != nullptr) && (mouseDragMonitorTimerId_ >= 0) &&
        (dragData.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE)) {
        context_->GetTimerManager().RemoveTimer(mouseDragMonitorTimerId_);
        mouseDragMonitorTimerId_ = -1;
    }
}

std::string DragManager::GetPackageName(int32_t pid)
{
    CHKPS(context_);
    std::string packageName = std::string();
    if (pid == -1) {
        packageName = "Cross-device drag";
    } else {
        context_->GetSocketSessionManager().AddSessionDeletedCallback(pid,
            [this](SocketSessionPtr session) { this->OnSessionLost(session); });
        dragOutSession_ = context_->GetSocketSessionManager().FindSessionByPid(pid);
        if (dragOutSession_ != nullptr) {
            packageName = dragOutSession_->GetProgramName();
        }
    }
    return packageName;
}

bool DragManager::IsCrossDragging()
{
    return isCrossDragging_;
}

DragRadarPackageName DragManager::GetDragRadarPackageName(int32_t pid, const std::string &packageName,
    const std::string &appCaller)
{
    FI_HILOGI("enter");
    DragRadarPackageName dragRadarPackageName;
    dragRadarPackageName.packageName = packageName;
    if (pid == -1) {
        dragRadarPackageName.appCaller = appCaller;
    } else {
        dragRadarPackageName.appCaller = packageName;
    }
    FI_HILOGI("leave");
    return dragRadarPackageName;
}

int32_t DragManager::StartDrag(
    const DragData &dragData, int32_t pid, const std::string &peerNetId, bool isLongPressDrag,
    const std::string &appCaller)
{
    FI_HILOGI("enter");
    ResetMouseDragMonitorTimerId(dragData);
    if (pid == -1) {
        isCrossDragging_ = true;
    } else {
        isCrossDragging_ = false;
    }
    if (dragState_ == DragState::START || dragState_ == DragState::MOTION_DRAGGING) {
        FI_HILOGE("Drag instance already exists, no need to start drag again");
        return RET_ERR;
    }
    peerNetId_ = peerNetId;
    std::string packageName = GetPackageName(pid);
    DragRadarPackageName dragRadarPackageName = GetDragRadarPackageName(pid, packageName, appCaller);
    dragRadarPackageName.dragNum = dragData.dragNum;
    ReportStartDragRadarInfo(BizState::STATE_BEGIN, StageRes::RES_IDLE, DragRadarErrCode::DRAG_SUCCESS, peerNetId,
        dragRadarPackageName);
    dragPackageName_ = dragRadarPackageName;
    PrintDragData(dragData, packageName);
    if (InitDataManager(dragData, dragRadarPackageName.appCaller) != RET_OK) {
        FI_HILOGE("Failed to init data manager");
        ResetMouseDragMonitorInfo();
        ReportStartDragFailedRadarInfo(StageRes::RES_FAIL, DragRadarErrCode::INVALID_DRAG_DATA, __func__,
            dragRadarPackageName);
        return RET_ERR;
    }
    isLongPressDrag_ = isLongPressDrag;
    if (OnStartDrag(dragRadarPackageName, pid) != RET_OK) {
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
        DragDFX::WriteStartDrag(dragState_, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
        FI_HILOGE("Failed to execute OnStartDrag");
        ResetMouseDragMonitorInfo();
        return RET_ERR;
    }
    if (notifyPUllUpCallback_ != nullptr) {
        notifyPUllUpCallback_(false);
    }
    SetDragState(DragState::START);
    dragDrawing_.OnStartDragExt();
    stateNotify_.StateChangedNotify(DragState::START);
    StateChangedNotify(DragState::START);
    ReportStartDragRadarInfo(BizState::STATE_IDLE, StageRes::RES_SUCCESS, DragRadarErrCode::DRAG_SUCCESS, peerNetId,
        dragRadarPackageName);
    if (pid == -1) {
        ReportStartDragUEInfo(packageName);
    }
    FI_HILOGI("leave");
    return RET_OK;
}
#else
int32_t DragManager::StartDrag(const DragData &dragData)
{
    CALL_INFO_TRACE;
    if (dragState_ == DragState::START) {
        FI_HILOGE("Drag instance already exists, no need to start drag again");
        return RET_ERR;
    }
    std::string packageName;
    PrintDragData(dragData, packageName);

    if (InitDataManager(dragData) != RET_OK) {
        FI_HILOGE("Failed to init data manager");
        return RET_ERR;
    }
    if (OnStartDrag() != RET_OK) {
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
        DragDFX::WriteStartDrag(dragState_, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#endif // OHOS_BUILD_ENABLE_ARKUI_X
        FI_HILOGE("Failed to execute OnStartDrag");
        return RET_ERR;
    }
    SetDragState(DragState::START);
    return RET_OK;
}

int32_t DragManager::UpdatePointerAction(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    CALL_INFO_TRACE;
    CHKPR(pointerEvent, RET_ERR);
    if (dragState_ != DragState::START || dragState_ == DragState::MOTION_DRAGGING) {
        FI_HILOGE("ARKUI_X DragState not started");
        return RET_ERR;
    }

    int32_t action = pointerEvent->GetPointerAction();
    switch (action) {
        case MMI::PointerEvent::POINTER_ACTION_MOVE: {
            pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_PULL_MOVE);
            FI_HILOGD("ARKUI_X UpdatePointAction to POINTER_ACTION_PULL_MOVE");
            return OnDragMove(pointerEvent);
        }
        case MMI::PointerEvent::POINTER_ACTION_BUTTON_UP:
        case MMI::PointerEvent::POINTER_ACTION_UP: {
            pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_PULL_UP);
            FI_HILOGD("ARKUI_X UpdatePointAction to POINTER_ACTION_PULL_UP");
            return OnDragUp(pointerEvent);
        }
        default: {
            FI_HILOGD("ARKUI_X unknown action:%{public}d", action);
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t DragManager::OnDragMove(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, RET_ERR);
    MMI::PointerEvent::PointerItem pointerItem;
    int32_t pointerId = pointerEvent->GetPointerId();
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        FI_HILOGE("ARKUI_X GetPointerItem fail");
        return RET_ERR;
    }

    int32_t displayX = pointerItem.GetDisplayX();
    int32_t displayY = pointerItem.GetDisplayY();
    int32_t sourceType = pointerEvent->GetSourceType();
    dragDrawing_.OnDragMove(pointerEvent->GetTargetDisplayId(), displayX,
        displayY, pointerEvent->GetActionTime());
    FI_HILOGD("ARKUI_X SourceType:%{public}d, pointerId:%{public}d, displayX:%{private}d, displayY:%{private}d",
        sourceType, pointerId, displayX, displayY);

    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

int32_t DragManager::StopDrag(const DragDropResult &dropResult, const std::string &packageName, int32_t pid,
    bool isStopCooperate, const DragRadarPackageName &inPackageName)
{
    FI_HILOGI("enter");
    isCrossDragging_ = false;
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    DragRadarPackageName dragRadarPackageName;
    dragRadarPackageName.packageName = packageName;
    if (pid == -1) {
        dragRadarPackageName.appCallee = inPackageName.appCallee;
        dragRadarPackageName.peerNetId = inPackageName.peerNetId;
    } else {
        dragRadarPackageName.appCallee = packageName;
    }
    ReportStopDragRadarInfo(BizState::STATE_IDLE, StageRes::RES_IDLE, DragRadarErrCode::DRAG_SUCCESS, pid,
        dragRadarPackageName);
    std::string dragOutPkgName =
        (dragOutSession_ == nullptr) ? "Cross-device drag" : dragOutSession_->GetProgramName();
    FI_HILOGI("mainWindow:%{public}d, dragResult:%{public}d, drop packageName:%{public}s,"
        "drag out packageName:%{public}s", dropResult.mainWindow, dropResult.result, packageName.c_str(),
        dragOutPkgName.c_str());
    if (dragState_ == DragState::STOP) {
        FI_HILOGE("No drag instance running, can not stop drag");
        ReportStopDragRadarInfo(BizState::STATE_END, StageRes::RES_FAIL, DragRadarErrCode::REPEATE_STOP_DRAG_EXCEPTION,
            pid, dragRadarPackageName);
        return RET_ERR;
    }
#ifdef OHOS_DRAG_ENABLE_ANIMATION
    dragDrawing_.NotifyDragInfo(dragOutPkgName, packageName);
#endif // OHOS_DRAG_ENABLE_ANIMATION
    if ((dropResult.result != DragResult::DRAG_EXCEPTION) && (context_ != nullptr) && (timerId_ >= 0)) {
        context_->GetTimerManager().RemoveTimer(timerId_);
        timerId_ = -1;
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    int32_t ret = RET_OK;
    if (OnStopDrag(dropResult.result, dropResult.hasCustomAnimation, packageName, pid, isStopCooperate) != RET_OK) {
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
        DragDFX::WriteStopDrag(dragState_, dropResult, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#endif // OHOS_BUILD_ENABLE_ARKUI_X
        FI_HILOGE("On stop drag failed");
        ret = RET_ERR;
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (dropResult.result == DragResult::DRAG_SUCCESS && dropResult.mainWindow > 0) {
        Rosen::WMError result = Rosen::WindowManagerLite::GetInstance().RaiseWindowToTop(dropResult.mainWindow);
        if (result != Rosen::WMError::WM_OK) {
            FI_HILOGE("Raise window to top failed, mainWindow:%{public}d", dropResult.mainWindow);
        }
    }
    stateNotify_.StateChangedNotify(DragState::STOP);
    DragBehavior dragBehavior = dropResult.dragBehavior;
    GetDragBehavior(dropResult, dragBehavior);
    if (NotifyDragResult(dropResult.result, dragBehavior) != RET_OK) {
        FI_HILOGE("Notify drag result failed");
        ReportStopDragRadarInfo(BizState::STATE_IDLE, StageRes::RES_FAIL, DragRadarErrCode::FAILED_NOTIFY_DRAG_RESULT,
            pid, dragRadarPackageName);
    }
    lastDisplayId_ = -1;
    lastEventId_ = -1;
    mouseDragMonitorDisplayX_ = -1;
    mouseDragMonitorDisplayY_ = -1;
    mouseDragMonitorState_ = false;
    existMouseMoveDragCallback_ = false;
    needLongPressDragAnimation_ = true;
    isLongPressDrag_ = false;
    DRAG_DATA_MGR.ResetDragData();
    dragResult_ = static_cast<DragResult>(dropResult.result);
    appCallee_ = dragRadarPackageName.appCallee;
    dragPackageName_ = {};
    StateChangedNotify(DragState::STOP);
#else
    DragBehavior dragBehavior = dropResult.dragBehavior;
    GetDragBehavior(dropResult, dragBehavior);
    DRAG_DATA_MGR.ResetDragData();
    dragResult_ = static_cast<DragResult>(dropResult.result);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    SetDragState(DragState::STOP);
    if (GetControlCollaborationVisible()) {
        SetControlCollaborationVisible(false);
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    ReportStopDragRadarInfo(BizState::STATE_END, StageRes::RES_SUCCESS, DragRadarErrCode::DRAG_SUCCESS, pid,
        dragRadarPackageName);
    if (dragOutSession_ == nullptr) {
        ReportStopDragUEInfo(packageName);
    }
    dragOutSession_ = nullptr;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    peerNetId_ = "";
    FI_HILOGI("leave");
    return ret;
}

int32_t DragManager::GetDragTargetPid() const
{
    FI_HILOGI("enter");
    return DRAG_DATA_MGR.GetTargetPid();
}

int32_t DragManager::GetUdKey(std::string &udKey) const
{
    FI_HILOGI("enter");
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    if (dragData.udKey.empty()) {
        FI_HILOGE("Target udKey is empty");
        return RET_ERR;
    }
    udKey = dragData.udKey;
    FI_HILOGI("leave");
    return RET_OK;
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
int32_t DragManager::UpdateDragStyle(DragCursorStyle style, int32_t targetPid, int32_t targetTid, int32_t eventId)
#else
int32_t DragManager::UpdateDragStyle(DragCursorStyle style)
#endif // OHOS_BUILD_ENABLE_ARKUI_X
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    FI_HILOGD("DragStyle from ark is dragStyle:%{public}s, event:%{public}d",
        GetDragStyleName(style).c_str(), eventId);
    if ((eventId != -1) && (eventId < lastEventId_)) {
        FI_HILOGE("Invalid eventId:%{public}d, lastEvent:%{public}d", eventId, lastEventId_);
        return RET_ERR;
    }
    lastEventId_ = eventId;
    auto lastTargetPid = DRAG_DATA_MGR.GetTargetPid();
    DRAG_DATA_MGR.SetTargetPid(targetPid);
    DRAG_DATA_MGR.SetTargetTid(targetTid);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    if (style == DRAG_DATA_MGR.GetDragStyle()) {
        FI_HILOGD("Not need update drag style");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
        if (targetPid != lastTargetPid) {
            stateNotify_.StyleChangedNotify(GetRealDragStyle(style));
        }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
        return RET_OK;
    }
    DRAG_DATA_MGR.SetDragStyle(style);
    if (dragState_ != DragState::START) {
        FI_HILOGE("No drag instance running, can not update drag style");
        return RET_ERR;
    }
    if ((style < DragCursorStyle::DEFAULT) || (style > DragCursorStyle::MOVE)) {
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
        DragDFX::WriteUpdateDragStyle(style, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#endif // OHOS_BUILD_ENABLE_ARKUI_X
        FI_HILOGE("Invalid style:%{public}d", style);
        return RET_ERR;
    }
    if (OnUpdateDragStyle(style) != RET_OK) {
        FI_HILOGE("OnUpdateDragStyle dragStyle:%{public}s failed", GetDragStyleName(style).c_str());
        return RET_ERR;
    }
    return RET_OK;
}

int32_t DragManager::UpdateShadowPic(const ShadowInfo &shadowInfo)
{
    FI_HILOGI("enter");
    if (dragState_ != DragState::START) {
        FI_HILOGE("No drag instance running, can not update shadow picture");
        return RET_ERR;
    }
    DRAG_DATA_MGR.SetShadowInfos({ shadowInfo });
    FI_HILOGI("leave");
    return dragDrawing_.UpdateShadowPic(shadowInfo);
}

int32_t DragManager::GetDragData(DragData &dragData)
{
    FI_HILOGI("enter");
    if ((dragState_ != DragState::START) && (dragState_ != DragState::MOTION_DRAGGING)) {
        FI_HILOGE("No drag instance running, can not get dragData");
        return RET_ERR;
    }
    dragData = DRAG_DATA_MGR.GetDragData();
    FI_HILOGI("leave");
    return RET_OK;
}

int32_t DragManager::GetDragState(DragState &dragState)
{
    FI_HILOGD("enter");
    dragState = GetDragState();
    if (dragState == DragState::ERROR) {
        FI_HILOGE("dragState_ is error");
        return RET_ERR;
    }
    FI_HILOGD("leave");
    return RET_OK;
}

DragCursorStyle DragManager::GetDragStyle() const
{
    return DRAG_DATA_MGR.GetDragStyle();
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
int32_t DragManager::NotifyDragResult(DragResult result, DragBehavior dragBehavior)
{
    FI_HILOGI("enter");
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    int32_t targetPid = GetDragTargetPid();
    NetPacket pkt(MessageId::DRAG_NOTIFY_RESULT);
    if ((result < DragResult::DRAG_SUCCESS) || (result > DragResult::DRAG_EXCEPTION)) {
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
        DragDFX::WriteNotifyDragResult(result, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
        FI_HILOGE("The invalid result:%{public}d", static_cast<int32_t>(result));
        return RET_ERR;
    }
    pkt << dragData.displayX << dragData.displayY << static_cast<int32_t>(result) << targetPid <<
        static_cast<int32_t>(dragBehavior);
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to packet write data");
        return RET_ERR;
    }
    CHKPR(dragOutSession_, RET_ERR);
    if (!dragOutSession_->SendMsg(pkt)) {
        FI_HILOGE("Failed to send message");
        return MSG_SEND_FAIL;
    }
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
    DragDFX::WriteNotifyDragResult(result, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
    FI_HILOGI("leave");
    return RET_OK;
}

int32_t DragManager::NotifyHideIcon()
{
    FI_HILOGD("enter");
    NetPacket pkt(MessageId::DRAG_NOTIFY_HIDE_ICON);
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet write data failed");
        return RET_ERR;
    }
    CHKPR(dragOutSession_, RET_ERR);
    if (!dragOutSession_->SendMsg(pkt)) {
        FI_HILOGE("Send message failed");
        return MSG_SEND_FAIL;
    }
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragManager::DealPullInWindowEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent, int32_t targetDisplayId)
{
    CHKPR(pointerEvent, RET_ERR);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    int32_t displayX = -1;
    int32_t displayY = -1;
    if (MMI::PointerEvent::FixedMode::AUTO == pointerEvent->GetFixedMode()) {
        displayX = pointerItem.GetFixedDisplayX();
        displayY = pointerItem.GetFixedDisplayY();
    } else {
        displayX = pointerItem.GetDisplayX();
        displayY = pointerItem.GetDisplayY();
    }
    dragDrawing_.DetachToDisplay(targetDisplayId);
    bool isNeedAdjustDisplayXY = true;
    bool isMultiSelectedAnimation = false;
    dragDrawing_.Draw(targetDisplayId, displayX, displayY, isNeedAdjustDisplayXY, isMultiSelectedAnimation);
    dragDrawing_.UpdateDragWindowDisplay(targetDisplayId);
    dragDrawing_.OnDragMove(targetDisplayId, displayX, displayY, pointerEvent->GetActionTime());
    lastDisplayId_ = targetDisplayId;
    return RET_OK;
}

double DragManager::NormalizeThrowAngle(double angle)
{
    return (angle < ANGLE_EPSILON) ? angle + FULL_CIRCLE_DEGREES : angle;
}

ThrowDirection DragManager::GetThrowDirection(double angle)
{
    if (angle >= ANGLE_DOWN_MIN && angle < ANGLE_DOWN_MAX) {
        return ThrowDirection::DOWN;
    }
    if (angle >= ANGLE_UP_MIN && angle < ANGLE_UP_MAX) {
        return ThrowDirection::UP;
    }
    if (angle >= ANGLE_LEFT_MIN && angle < ANGLE_LEFT_MAX) {
        return ThrowDirection::LEFT;
    }
    return ThrowDirection::RIGHT;
}

ScreenId DragManager::GetScreenId(int32_t displayY)
{
    if (displayY <= UP_SCREEN_MAX_Y) {
        return ScreenId::UPSCREEN;
    }
    if (displayY >= DOWN_SCREEN_MIN_Y && displayY <= DOWN_SCREEN_MAX_Y) {
        return ScreenId::DOWNSCREEN;
    }
    return ScreenId::INVALID;
}

bool DragManager::ValidateThrowDirection(ScreenId currentScreen, ThrowDirection throwDir)
{
    bool isDownThrow = (throwDir == ThrowDirection::DOWN &&
                        currentScreen == ScreenId::UPSCREEN &&
                        throwState_ == ThrowState::NOT_THROW);

    bool isUpThrow = (throwDir == ThrowDirection::UP &&
                      currentScreen == ScreenId::DOWNSCREEN &&
                      throwState_ == ThrowState::NOT_THROW);

    return isDownThrow || isUpThrow;
}

int32_t DragManager::OnPullThrow(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, RET_ERR);
    dragDrawing_.StopVSyncStation();
    isHPR_ = PRODUCT_TYPE == DEVICE_TYPE_HPR;
    if (!isHPR_) {
        FI_HILOGW("Fail to pull throw, feature not support");
        return RET_ERR;
    }

    if (!ValidateThrowConditions()) {
        FI_HILOGI("ThrowConditions Not satisfied");
        pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_PULL_CANCEL);
        MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
        return RET_ERR;
    }

    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    ScreenId currentScreen = GetScreenId(pointerItem.GetDisplayY());

    double throwAngle = pointerEvent->GetThrowAngle();
    double throwSpeed = pointerEvent->GetThrowSpeed();
    throwAngle = NormalizeThrowAngle(throwAngle);

    ThrowDirection throwDir = GetThrowDirection(throwAngle);
    float vx = std::abs(throwSpeed * std::cos(throwAngle * M_PI / 180.0));
    float vy = std::abs(throwSpeed * std::sin(throwAngle * M_PI / 180.0));

    FI_HILOGI("angle=%{public}f, direction=%{public}d, state=%{public}d, speeds=(%{public}f,%{public}f)",
              throwAngle, throwDir, throwState_, vx, vy);
    
    FI_HILOGD("VK Status: NONE = 0, TOUCHPAD = 1, PIXED = 2, FLOATING = 3");
    FI_HILOGD("Fold Status: UNKNOWN = 0, EXPAND = 1, FOLDED = 2, HALF_FOLD = 3");
    FI_HILOGD("Throw State: Not Throw = 0, In downscreen = 1, In upscreen = 2");

    if (ValidateThrowDirection(currentScreen, throwDir)) {
        throwState_ = (throwDir == ThrowDirection::DOWN) ? ThrowState::IN_DOWNSCREEN : ThrowState::IN_UPSCREEN;
        int targetY = (throwDir == ThrowDirection::DOWN) ? TARGET_Y_DOWN : TARGET_Y_UP;
        FI_HILOGI("SUCCESS: Screen=%{public}d, Direction=%{public}d, Angle=%{public}f, ThrowState=%{public}d",
                  currentScreen, throwDir, throwAngle, throwState_);
        dragDrawing_.PullThrowAnimation(TARGET_X, targetY, vx, vy, pointerEvent);
        
        int32_t repeatCount = 1;
        CHKPR(context_, RET_ERR);
        dragTimerId_ = context_->GetTimerManager().AddTimer(TIMER_TIMEOUT_MS, repeatCount, [this]() {
            FI_HILOGI("Timeout 30s, automatically stop dragging");
            CHKPV(currentPointerEvent_);
            currentPointerEvent_->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_PULL_CANCEL);
            MMI::InputManager::GetInstance()->SimulateInputEvent(currentPointerEvent_);
        });
    } else {
        FI_HILOGD("Screen=%{public}d, Direction=%{public}d, Angle=%{public}f, ThrowState=%{public}d",
                  currentScreen, throwDir, throwAngle, throwState_);
        pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_PULL_CANCEL);
        MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    }
    return RET_OK;
}

void DragManager::InPullThrow(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    DragData dragData = DRAG_DATA_MGR.GetDragData();

    CHKPV(context_);
    if (dragTimerId_ >= 0) {
        context_->GetTimerManager().RemoveTimer(dragTimerId_);
        dragTimerId_ = -1;
        FI_HILOGD("Remove timer");
    }

    if (dragData.shadowInfos.size() <= 0) {
        FI_HILOGE("shadow info size is 0");
        return;
    }
    const ShadowInfo &shadowInfo = dragData.shadowInfos[0];
    CHKPV(shadowInfo.pixelMap);
    double hotZoneX = TARGET_X + shadowInfo.x;
    double baseY = (throwState_ == ThrowState::IN_DOWNSCREEN) ? TARGET_Y_DOWN : TARGET_Y_UP;
    double hotZoneY = baseY + shadowInfo.y;

    FI_HILOGI("DRAGDOWN throw state: %{public}d", throwState_);
    FI_HILOGD("Pointer X: %{public}d, Y: %{public}d",
              pointerItem.GetDisplayX(), pointerItem.GetDisplayY());
    FI_HILOGD("Hotzone X: %{public}f, Y: %{public}f, Width: %{public}d, Height: %{public}d",
              hotZoneX, hotZoneY, shadowInfo.pixelMap->GetWidth(), shadowInfo.pixelMap->GetHeight());

    bool isPointerOutsideHotZone =
        (hotZoneY + shadowInfo.pixelMap->GetHeight() <= pointerItem.GetDisplayY()) ||
        (pointerItem.GetDisplayY() <= hotZoneY) ||
        (hotZoneX + shadowInfo.pixelMap->GetWidth() <= pointerItem.GetDisplayX()) ||
        (pointerItem.GetDisplayX() <= hotZoneX);
    if (isPointerOutsideHotZone) {
        FI_HILOGI("In POINTER_ACTION_DOWN, Cancel, not in hotzone");
        dragDrawing_.StopVSyncStation();
        mouseDragMonitorDisplayX_ = -1;
        mouseDragMonitorDisplayY_ = -1;
        OnDragCancel(pointerEvent);
        throwState_ = ThrowState::NOT_THROW;
    }
}

void DragManager::DragCallback(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    int32_t pointerAction = pointerEvent->GetPointerAction();
    currentPointerEvent_ = pointerEvent;
    if ((pointerEvent->GetSourceType() == MMI::PointerEvent::SOURCE_TYPE_MOUSE) &&
        (pointerAction == MMI::PointerEvent::POINTER_ACTION_MOVE) && mouseDragMonitorState_) {
        MMI::PointerEvent::PointerItem pointerItem;
        pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
        mouseDragMonitorDisplayX_ = pointerItem.GetDisplayX();
        mouseDragMonitorDisplayY_ = pointerItem.GetDisplayY();
        existMouseMoveDragCallback_ = true;
    }
    if (pointerAction == MMI::PointerEvent::POINTER_ACTION_PULL_MOVE) {
        mouseDragMonitorDisplayX_ = -1;
        mouseDragMonitorDisplayY_ = -1;
        OnDragMove(pointerEvent);
        return;
    }
    if (pointerAction == MMI::PointerEvent::POINTER_ACTION_PULL_THROW) {
        int32_t ret = OnPullThrow(pointerEvent);
        if (ret != RET_OK) {
            FI_HILOGE("PullThrow failed");
        }
        return;
    }
    FI_HILOGD("DragCallback, pointerAction:%{public}d", pointerAction);
    if ((pointerAction == MMI::PointerEvent::POINTER_ACTION_PULL_UP) ||
        (pointerAction == MMI::PointerEvent::POINTER_ACTION_PULL_CANCEL)) {
        throwState_ = ThrowState::NOT_THROW;
        dragDrawing_.StopVSyncStation();
        mouseDragMonitorDisplayX_ = -1;
        mouseDragMonitorDisplayY_ = -1;
        CHKPV(context_);
        int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this, pointerEvent] {
            return this->OnDragUp(pointerEvent);
        });
        if (ret != RET_OK) {
            FI_HILOGE("Post async task failed");
        }
        if (dragTimerId_ >= 0 && pointerAction == MMI::PointerEvent::POINTER_ACTION_PULL_CANCEL) {
            CHKPV(context_);
            context_->GetTimerManager().RemoveTimer(dragTimerId_);
            dragTimerId_ = -1;
            FI_HILOGD("Remove timer");
        }
        return;
    }
    if (pointerAction == MMI::PointerEvent::POINTER_ACTION_DOWN && throwState_ != ThrowState::NOT_THROW) {
        InPullThrow(pointerEvent);
        return;
    }
    int32_t targetDisplayId = pointerEvent->GetTargetDisplayId();
    if ((pointerEvent->GetSourceType() == MMI::PointerEvent::SOURCE_TYPE_MOUSE) &&
        (pointerAction == MMI::PointerEvent::POINTER_ACTION_PULL_IN_WINDOW) && (lastDisplayId_ != targetDisplayId)) {
        FI_HILOGI("Interface for processing extended screen access");
        CHKPV(context_);
        int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this, pointerEvent, targetDisplayId] {
            return this->DealPullInWindowEvent(pointerEvent, targetDisplayId);
        });
        if (ret != RET_OK) {
            FI_HILOGE("Post async task failed");
        }
    }
    FI_HILOGD("Unknown action, sourceType:%{public}d, pointerId:%{public}d, pointerAction:%{public}d",
        pointerEvent->GetSourceType(), pointerEvent->GetPointerId(), pointerAction);
}

void DragManager::DoLongPressDragZoomOutAnimation(int32_t displayX, int32_t displayY)
{
    auto LongPressDragZoomOutAnimation = [displayX, displayY, this]() {
        if (needLongPressDragAnimation_) {
            DragData dragData = DRAG_DATA_MGR.GetDragData();
            int32_t deltaX = abs(displayX - dragData.displayX);
            int32_t deltaY = abs(displayY - dragData.displayY);
            if ((pow(deltaX, POWER_SQUARED) + pow(deltaY, POWER_SQUARED)) > TEN_POWER) {
                dragDrawing_.LongPressDragZoomOutAnimation();
                needLongPressDragAnimation_ = false;
            }
        }
        return RET_OK;
    };
    if (isLongPressDrag_) {
        CHKPV(context_);
        int32_t ret = context_->GetDelegateTasks().PostAsyncTask(LongPressDragZoomOutAnimation);
        if (ret != RET_OK) {
            FI_HILOGE("Post async task failed, ret:%{public}d", ret);
        }
    }
}

void DragManager::OnDragMove(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    if (pointerEvent->GetSourceType() != dragData.sourceType) {
        FI_HILOGW("The pointer source type invaild, the event should be ignored,"
            "pointer sourceType:%{public}d, drag sourceType:%{public}d",
            pointerEvent->GetSourceType(), dragData.sourceType);
        return;
    }
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    int32_t pointerId = pointerEvent->GetPointerId();
    int32_t displayX = -1;
    int32_t displayY = -1;
    if (MMI::PointerEvent::FixedMode::AUTO == pointerEvent->GetFixedMode()) {
        displayX = pointerItem.GetFixedDisplayX();
        displayY = pointerItem.GetFixedDisplayY();
    } else {
        displayX = pointerItem.GetDisplayX();
        displayY = pointerItem.GetDisplayY();
    }
    DoLongPressDragZoomOutAnimation(displayX, displayY);
    int32_t targetDisplayId = pointerEvent->GetTargetDisplayId();
    FI_HILOGD("SourceType:%{public}d, pointerId:%{public}d, displayX:%{private}d, displayY:%{private}d, "
        "targetDisplayId:%{public}d, pullId:%{public}d", pointerEvent->GetSourceType(), pointerId, displayX, displayY,
        targetDisplayId, pointerEvent->GetPullId());
    if (lastDisplayId_ == -1) {
        lastDisplayId_ = targetDisplayId;
        dragDrawing_.OnDragMove(targetDisplayId, displayX, displayY, pointerEvent->GetActionTime());
    } else if (lastDisplayId_ != targetDisplayId) {
        dragDrawing_.DetachToDisplay(targetDisplayId);
        bool isNeedAdjustDisplayXY = true;
        bool isMultiSelectedAnimation = false;
        dragDrawing_.Draw(targetDisplayId, displayX, displayY, isNeedAdjustDisplayXY, isMultiSelectedAnimation);
        dragDrawing_.UpdateDragWindowDisplay(targetDisplayId);
        dragDrawing_.OnDragMove(targetDisplayId, displayX, displayY, pointerEvent->GetActionTime());
        lastDisplayId_ = targetDisplayId;
    } else {
        if (throwState_ == ThrowState::NOT_THROW) {
            FI_HILOGD("Drag move ThrowState::NOT_THROW");
            dragDrawing_.OnDragMove(targetDisplayId, displayX, displayY, pointerEvent->GetActionTime());
        } else {
            FI_HILOGD("Drag move other ThrowState");
            dragDrawing_.OnPullThrowDragMove(targetDisplayId, displayX, displayY, pointerEvent->GetActionTime());
        }
    }
}

void DragManager::OnDragCancel(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    FI_HILOGI("enter");
    CHKPV(pointerEvent);
    if (dragState_ != DragState::START) {
        FI_HILOGW("No drag instance running");
        return;
    }
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    if (dragData.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        dragDrawing_.EraseMouseIcon();
        FI_HILOGI("Set the pointer cursor visible");
        MMI::InputManager::GetInstance()->SetPointerVisible(true);
    }
    DragDropResult dropResult { DragResult::DRAG_CANCEL, false, -1 };
    StopDrag(dropResult);
    DragRadarInfo dragRadarInfo;
    dragRadarInfo.funcName = __func__;
    dragRadarInfo.bizState = static_cast<int32_t>(BizState::STATE_END);
    dragRadarInfo.bizStage = static_cast<int32_t>(BizStage::STAGE_STOP_DRAG);
    dragRadarInfo.stageRes = static_cast<int32_t>(StageRes::RES_FAIL);
    dragRadarInfo.errCode = static_cast<int32_t>(DragRadarErrCode::DRAG_STOP_CANCEL);
    dragRadarInfo.hostName = "";
    dragRadarInfo.callingPid = "";
    ReportDragRadarInfo(dragRadarInfo);
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

void DragManager::SendDragData(int32_t targetTid, const std::string &udKey)
{
    FI_HILOGI("enter");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifdef MSDP_FRAMEWORK_UDMF_ENABLED
    UDMF::QueryOption option;
    option.key = udKey;
    UDMF::Privilege privilege;
    privilege.tokenId = static_cast<uint32_t>(targetTid);
    int32_t ret = UDMF::UdmfClient::GetInstance().AddPrivilege(option, privilege);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to send pid to Udmf client");
    }
#endif // MSDP_FRAMEWORK_UDMF_ENABLED
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    FI_HILOGI("leave");
}

int32_t DragManager::OnDragUp(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    FI_HILOGI("enter");
    CHKPR(pointerEvent, RET_ERR);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (notifyPUllUpCallback_ != nullptr) {
        notifyPUllUpCallback_(true);
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    if (dragState_ != DragState::START) {
        FI_HILOGW("No drag instance running");
        return RET_ERR;
    }
    DragData dragData = DRAG_DATA_MGR.GetDragData();
#ifndef OHOS_BUILD_PC_PRODUCT
    if (dragData.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        dragDrawing_.EraseMouseIcon();
        FI_HILOGI("Set the pointer cursor visible");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
        MMI::InputManager::GetInstance()->SetPointerVisible(true);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    }
#endif // OHOS_BUILD_PC_PRODUCT

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    CHKPR(context_, RET_ERR);
    int32_t repeatCount = 1;
    timerId_ = context_->GetTimerManager().AddTimer(TIMEOUT_MS, repeatCount, [this, dragData]() {
        DragDropResult dropResult { DragResult::DRAG_EXCEPTION, false, -1 };
        FI_HILOGW("Timeout, automatically stop dragging");
        this->StopDrag(dropResult);
        DragRadarInfo dragRadarInfo;
        dragRadarInfo.funcName = __func__;
        dragRadarInfo.bizState = static_cast<int32_t>(BizState::STATE_END);
        dragRadarInfo.bizStage = static_cast<int32_t>(BizStage::STAGE_STOP_DRAG);
        dragRadarInfo.stageRes = static_cast<int32_t>(StageRes::RES_FAIL);
        dragRadarInfo.errCode = static_cast<int32_t>(DragRadarErrCode::DRAG_STOP_EXCEPTION);
        dragRadarInfo.hostName = "";
        dragRadarInfo.callingPid = "";
        ReportDragRadarInfo(dragRadarInfo);
    });
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    FI_HILOGI("leave");
    return RET_OK;
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifdef OHOS_DRAG_ENABLE_INTERCEPTOR
void DragManager::InterceptorConsumer::OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const
{
}

void DragManager::InterceptorConsumer::OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
    CHKPV(pointerEvent);
    if (g_startFilterTime > 0) {
        auto actionTime = pointerEvent->GetActionTime();
        if (g_startFilterTime >= actionTime
            && pointerEvent->GetPointerAction() == MMI::PointerEvent::POINTER_ACTION_PULL_MOVE) {
            FI_HILOGW("Invalid event");
            return;
        }
        g_startFilterTime = -1;
    }
    CHKPV(pointerEventCallback_);
    pointerEventCallback_(pointerEvent);
    pointerEvent->AddFlag(MMI::InputEvent::EVENT_FLAG_NO_INTERCEPT);
    MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    if (pointerEvent->GetPointerAction() == MMI::PointerEvent::POINTER_ACTION_PULL_UP) {
        FI_HILOGI("Pointer button is released, appened extra data");
        MMI::InputManager::GetInstance()->AppendExtraData(DragManager::CreateExtraData(false));
    }
}

void DragManager::InterceptorConsumer::OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const
{
}
#endif // OHOS_DRAG_ENABLE_INTERCEPTOR

#ifdef OHOS_DRAG_ENABLE_MONITOR
void DragManager::MonitorConsumer::OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const
{
    FI_HILOGD("enter");
}

void DragManager::MonitorConsumer::OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
    FI_HILOGD("enter");
    CHKPV(pointerEvent);
    CHKPV(pointerEventCallback_);
    pointerEventCallback_(pointerEvent);
    if (pointerEvent->GetPointerAction() == MMI::PointerEvent::POINTER_ACTION_PULL_UP) {
        FI_HILOGI("Pointer button is released, appened extra data");
        int32_t ret = context_->GetDelegateTasks().PostAsyncTask([] {
            return MMI::InputManager::GetInstance()->AppendExtraData(DragManager::CreateExtraData(false));
        });
        if (ret != RET_OK) {
            FI_HILOGE("Post async task failed");
        }
    }
    FI_HILOGD("leave");
}

void DragManager::MonitorConsumer::OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const
{
    FI_HILOGD("enter");
}
#endif // OHOS_DRAG_ENABLE_MONITOR

void DragManager::Dump(int32_t fd) const
{
    DragCursorStyle style = DRAG_DATA_MGR.GetDragStyle();
    int32_t targetTid = DRAG_DATA_MGR.GetTargetTid();
    dprintf(fd, "Drag information:\n");
#ifdef OHOS_DRAG_ENABLE_INTERCEPTOR
    dprintf(fd,
            "dragState:%s | dragResult:%s | interceptorId:%d | dragTargetPid:%d | dragTargetTid:%d | "
            "cursorStyle:%s | isWindowVisble:%s\n", GetDragState(dragState_).c_str(),
            GetDragResult(dragResult_).c_str(), pointerEventInterceptorId_, GetDragTargetPid(), targetTid,
            GetDragCursorStyle(style).c_str(), DRAG_DATA_MGR.GetDragWindowVisible() ? "true" : "false");
#endif // OHOS_DRAG_ENABLE_INTERCEPTOR
#ifdef OHOS_DRAG_ENABLE_MONITOR
    dprintf(fd,
            "dragState:%s | dragResult:%s | monitorId:%d | dragTargetPid:%d | dragTargetTid:%d | "
            "cursorStyle:%s | isWindowVisble:%s\n", GetDragState(dragState_).c_str(),
            GetDragResult(dragResult_).c_str(), pointerEventMonitorId_, GetDragTargetPid(), targetTid,
            GetDragCursorStyle(style).c_str(), DRAG_DATA_MGR.GetDragWindowVisible() ? "true" : "false");
#endif // OHOS_DRAG_ENABLE_MONITOR
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    std::string udKey;
    if (RET_ERR == GetUdKey(udKey)) {
        FI_HILOGE("Target udKey is empty");
        udKey = "";
    }
    for (const auto& shadowInfo : dragData.shadowInfos) {
        dprintf(fd, "dragData = {\n""\tshadowInfoX:%d\n\tshadowInfoY\n", shadowInfo.x, shadowInfo.y);
    }
    dprintf(fd, "dragData = {\n"
            "\tudKey:%s\n\tfilterInfo:%s\n\textraInfo:%s\n\tsourceType:%d"
            "\tdragNum:%d\n\tpointerId:%d\n\tdisplayX:%d\n\tdisplayY:%d\n""\tdisplayId:%d\n\thasCanceledAnimation:%s\n",
            GetAnonyString(dragData.udKey).c_str(), dragData.filterInfo.c_str(), dragData.extraInfo.c_str(),
            dragData.sourceType, dragData.dragNum, dragData.pointerId, dragData.displayX, dragData.displayY,
            dragData.displayId, dragData.hasCanceledAnimation ? "true" : "false");
    if (dragState_ != DragState::STOP) {
        for (const auto& shadowInfo : dragData.shadowInfos) {
            CHKPV(shadowInfo.pixelMap);
            dprintf(fd, "\tpixelMapWidth:%d\n\tpixelMapHeight:%d\n", shadowInfo.pixelMap->GetWidth(),
                shadowInfo.pixelMap->GetHeight());
        }
    }
    dprintf(fd, "}\n");
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

std::string DragManager::GetDragState(DragState value) const
{
    std::string state = "unknown";
    const std::map<DragState, std::string> dragStates = {
        { DragState::START, "start" },
        { DragState::STOP, "stop" },
        { DragState::CANCEL, "cancel" },
        { DragState::ERROR, "error" }
    };
    auto iter = dragStates.find(value);
    if (iter != dragStates.end()) {
        state = iter->second;
    }
    return state;
}

std::string DragManager::GetDragResult(DragResult value) const
{
    std::string result = "unknown";
    const std::map<DragResult, std::string> dragResults = {
        { DragResult::DRAG_SUCCESS, "success" },
        { DragResult::DRAG_FAIL, "fail" },
        { DragResult::DRAG_CANCEL, "cancel" },
        { DragResult::DRAG_EXCEPTION, "abnormal" }
    };
    auto iter = dragResults.find(value);
    if (iter != dragResults.end()) {
        result = iter->second;
    }
    return result;
}

std::string DragManager::GetDragCursorStyle(DragCursorStyle value) const
{
    std::string style = "unknown";
    const std::map<DragCursorStyle, std::string> cursorStyles = {
        { DragCursorStyle::COPY, "copy" },
        { DragCursorStyle::DEFAULT, "default" },
        { DragCursorStyle::FORBIDDEN, "forbidden" },
        { DragCursorStyle::MOVE, "move" }
    };
    auto iter = cursorStyles.find(value);
    if (iter != cursorStyles.end()) {
        style = iter->second;
    }
    return style;
}

MMI::ExtraData DragManager::CreateExtraData(bool appended, bool drawCursor)
{
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    MMI::ExtraData extraData;
    extraData.buffer = dragData.buffer;
    extraData.toolType = dragData.toolType;
    extraData.sourceType = dragData.sourceType;
    extraData.pointerId = dragData.pointerId;
    extraData.appended = appended;
    extraData.pullId = pullId_;
    extraData.drawCursor = drawCursor;
    extraData.eventId = DRAG_DATA_MGR.GetEventId();
    FI_HILOGD("sourceType:%{public}d, pointerId:%{public}d, eventId:%{public}d",
        extraData.sourceType, extraData.pointerId, extraData.eventId);
    return extraData;
}

int32_t DragManager::InitDataManager(const DragData &dragData, const std::string &appCaller)
{
    FI_HILOGI("enter");
    DRAG_DATA_MGR.Init(dragData, appCaller);
    FI_HILOGI("leave");
    return RET_OK;
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
int32_t DragManager::AddDragEventHandler(int32_t sourceType)
{
    FI_HILOGI("enter");
    uint32_t deviceTags = 0;
#ifdef OHOS_DRAG_ENABLE_INTERCEPTOR
    if (sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        deviceTags = MMI::CapabilityToTags(MMI::INPUT_DEV_CAP_POINTER);
    } else if (sourceType == MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        deviceTags = MMI::CapabilityToTags(MMI::INPUT_DEV_CAP_TOUCH) |
            MMI::CapabilityToTags(MMI::INPUT_DEV_CAP_TABLET_TOOL);
    } else {
        FI_HILOGW("Drag is not supported for this device type:%{public}d", sourceType);
        return RET_ERR;
    }
#endif // OHOS_DRAG_ENABLE_INTERCEPTOR
    if (AddKeyEventMonitor() != RET_OK) {
        FI_HILOGE("Failed to add key event handler");
        return RET_ERR;
    }
    if (AddPointerEventHandler(deviceTags) != RET_OK) {
        FI_HILOGE("Failed to add pointer event handler");
        return RET_ERR;
    }
    FI_HILOGI("leave");
    return RET_OK;
}

int32_t DragManager::AddPointerEventHandler(uint32_t deviceTags)
{
    FI_HILOGI("enter");
    if (pointerEventMonitorId_ <= 0) {
#ifdef OHOS_DRAG_ENABLE_MONITOR
        auto monitor = std::make_shared<MonitorConsumer>([this](std::shared_ptr<MMI::PointerEvent> pointerEvent) {
            return this->DragCallback(pointerEvent);
        }, context_);
        pointerEventMonitorId_ = MMI::InputManager::GetInstance()->AddMonitor(monitor);
        if (pointerEventMonitorId_ <= 0) {
            FI_HILOGE("Failed to add pointer event monitor");
            return RET_ERR;
        }
#else
        auto callback = [this](std::shared_ptr<MMI::PointerEvent> pointerEvent) {
            return this->DragCallback(pointerEvent);
        };
        auto interceptor = std::make_shared<InterceptorConsumer>(callback);
        pointerEventInterceptorId_ = MMI::InputManager::GetInstance()->AddInterceptor(
            interceptor, DRAG_PRIORITY, deviceTags);
        if (pointerEventInterceptorId_ <= 0) {
            FI_HILOGE("Failed to add pointer event interceptor");
            return RET_ERR;
        }
#endif // OHOS_DRAG_ENABLE_MONITOR
        FI_HILOGI("Add drag poniter event handle successfully");
        FI_HILOGI("leave");
        return RET_OK;
    } else {
        FI_HILOGI("leave");
        return RET_ERR;
    }
}

int32_t DragManager::AddKeyEventMonitor()
{
    FI_HILOGI("enter");
    if (keyEventMonitorId_ <= 0) {
        keyEventMonitorId_ = MMI::InputManager::GetInstance()->AddMonitor(
            [this](std::shared_ptr<MMI::KeyEvent> keyEvent) {
                return this->DragKeyEventCallback(keyEvent);
            });
        if (keyEventMonitorId_ <= 0) {
            FI_HILOGE("Failed to add key event monitor");
            return RET_ERR;
        }
        FI_HILOGI("Add drag key event monitor successfully");
        FI_HILOGI("leave");
        return RET_OK;
    } else {
        FI_HILOGI("leave");
        return RET_ERR;
    }
}

int32_t DragManager::RemovePointerEventHandler()
{
    FI_HILOGI("enter");
#ifdef OHOS_DRAG_ENABLE_MONITOR
    if (pointerEventMonitorId_ <= 0) {
        FI_HILOGE("Invalid pointer event monitor id:%{public}d", pointerEventMonitorId_);
        return RET_ERR;
    }
    MMI::InputManager::GetInstance()->RemoveMonitor(pointerEventMonitorId_);
    pointerEventMonitorId_ = -1;
#else
    if (pointerEventInterceptorId_ <= 0) {
        FI_HILOGE("Invalid pointer event interceptor id:%{public}d", pointerEventInterceptorId_);
    }
    MMI::InputManager::GetInstance()->RemoveInterceptor(pointerEventInterceptorId_);
    pointerEventInterceptorId_ = -1;
#endif // OHOS_DRAG_ENABLE_MONITOR
    FI_HILOGI("Remove drag pointer event handler successfully");
    return RET_OK;
}

int32_t DragManager::RemoveDragEventHandler()
{
    FI_HILOGI("enter");
    if (RemoveKeyEventMonitor() != RET_OK) {
        FI_HILOGE("Failed to remove key event handler");
        return RET_ERR;
    }
    if (RemovePointerEventHandler() != RET_OK) {
        FI_HILOGE("Failed to remove pointer event handler");
        return RET_ERR;
    }
    FI_HILOGI("leave");
    return RET_OK;
}

int32_t DragManager::RemoveKeyEventMonitor()
{
    FI_HILOGI("enter");
    if (keyEventMonitorId_ <= 0) {
        FI_HILOGE("Invalid key event monitor id:%{public}d", keyEventMonitorId_);
        return RET_ERR;
    }
    MMI::InputManager::GetInstance()->RemoveMonitor(keyEventMonitorId_);
    keyEventMonitorId_ = -1;
    FI_HILOGI("Remove drag key event handle successfully");
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

int32_t DragManager::OnStartDrag(const struct DragRadarPackageName &dragRadarPackageName, int32_t pid)
{
    FI_HILOGI("enter");
    pullId_ = GenerateId();
    FI_HILOGI("Current pullId:%{public}d", pullId_.load());
    if (GetControlCollaborationVisible()) {
        SetControlCollaborationVisible(false);
    }
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    bool drawCursor = false;
#ifdef OHOS_BUILD_PC_PRODUCT
    if (dragData.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        drawCursor = true;
    }
#endif // OHOS_BUILD_PC_PRODUCT
    auto extraData = CreateExtraData(true, drawCursor);
    bool isHicarOrSuperLauncher = false;
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(dragData.displayId);
    if (display != nullptr) {
        std::string displayName = display->GetName();
        isHicarOrSuperLauncher = ((displayName == "HiCar") || (displayName == "SuperLauncher"));
    }
    dragDrawing_.SetScreenId(dragData.displayId);
    if (Rosen::DisplayManager::GetInstance().IsFoldable() && !isHicarOrSuperLauncher) {
        if (static_cast<uint64_t>(dragData.displayId) == displayId_) {
            dragDrawing_.SetScreenId(screenId_);
        }
    }
    int32_t ret = dragDrawing_.Init(dragData, context_, isLongPressDrag_);
#else
    int32_t ret = dragDrawing_.Init(dragData);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    if (ret == INIT_FAIL) {
        FI_HILOGE("Init drag drawing failed");
        dragDrawing_.DestroyDragWindow();
        dragDrawing_.UpdateDrawingState();
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
        ReportStartDragFailedRadarInfo(StageRes::RES_FAIL, DragRadarErrCode::FAILED_INIT_DRAWING, __func__,
            dragRadarPackageName);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
        return RET_ERR;
    }
    if (ret == INIT_CANCEL) {
        FI_HILOGE("Init drag drawing cancel, drag animation is running");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
        ReportStartDragFailedRadarInfo(StageRes::RES_CANCEL, DragRadarErrCode::REPEATE_START_DRAG_EXCEPTION, __func__,
            dragRadarPackageName);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
        return RET_ERR;
    }
    bool isNeedAdjustDisplayXY = true;
    bool isMultiSelectedAnimation = false;
    if (!mouseDragMonitorState_ || !existMouseMoveDragCallback_) {
        dragDrawing_.Draw(dragData.displayId, dragData.displayX, dragData.displayY, isNeedAdjustDisplayXY,
            isMultiSelectedAnimation);
    } else if (mouseDragMonitorState_ && existMouseMoveDragCallback_ && (mouseDragMonitorDisplayX_ != -1)
        && (mouseDragMonitorDisplayY_ != -1)) {
        dragDrawing_.Draw(dragData.displayId, mouseDragMonitorDisplayX_, mouseDragMonitorDisplayY_,
            isNeedAdjustDisplayXY, isMultiSelectedAnimation);
    }
    FI_HILOGI("Start drag, appened extra data");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    ret = AddDragEvent(dragData, dragRadarPackageName);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to add drag event handler");
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    dragAction_.store(DragAction::MOVE);
    FI_HILOGI("leave");
    return RET_OK;
}

int32_t DragManager::OnStopDrag(DragResult result, bool hasCustomAnimation, const std::string &packageName, int32_t pid,
    bool isStopCooperate)
{
    FI_HILOGI("Add custom animation:%{public}s", hasCustomAnimation ? "true" : "false");
    DragData dragData = DRAG_DATA_MGR.GetDragData();
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if ((RemovePointerEventHandler()!= RET_OK) || (RemoveKeyEventMonitor() != RET_OK)) {
        DragRadarInfo dragRadarInfo;
        dragRadarInfo.funcName = __func__;
        dragRadarInfo.bizState = static_cast<int32_t>(BizState::STATE_END);
        dragRadarInfo.bizStage = static_cast<int32_t>(BizStage::STAGE_STOP_DRAG);
        dragRadarInfo.stageRes = static_cast<int32_t>(StageRes::RES_FAIL);
        dragRadarInfo.errCode = static_cast<int32_t>(DragRadarErrCode::FAILED_REMOVE_INPUT_MONITOR);
        dragRadarInfo.hostName = packageName;
        dragRadarInfo.callingPid = pid;
        ReportDragRadarInfo(dragRadarInfo);
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    dragAction_.store(DragAction::MOVE);
    FI_HILOGI("Stop drag, appened extra data");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    MMI::InputManager::GetInstance()->AppendExtraData(DragManager::CreateExtraData(false));
#endif // OHOS_BUILD_ENABLE_ARKUI_X

#ifndef OHOS_BUILD_PC_PRODUCT
    if (dragData.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        dragDrawing_.EraseMouseIcon();
        if (dragState_ != DragState::MOTION_DRAGGING) {
            FI_HILOGI("Set the pointer cursor visible");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
            if (isStopCooperate) {
                CHKPR(context_, RET_ERR);
                bool hasLocalPointerDevice = context_->GetDeviceManager().HasLocalPointerDevice() ||
                    context_->GetInput().HasLocalPointerDevice();
                MMI::InputManager::GetInstance()->SetPointerVisible(hasLocalPointerDevice);
            } else {
                MMI::InputManager::GetInstance()->SetPointerVisible(true);
            }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
        }
    }
#endif // OHOS_BUILD_PC_PRODUCT

    pullId_ = -1;
    return HandleDragResult(result, hasCustomAnimation);
}

int32_t DragManager::OnSetDragWindowVisible(bool visible, bool isForce, bool isZoomInAndAlphaChanged)
{
    FI_HILOGI("Set drag window visibleion:%{public}s", visible ? "true" : "false");
    if (dragState_ == DragState::MOTION_DRAGGING) {
        FI_HILOGW("Currently in motion dragging");
        return RET_OK;
    }
    if (dragState_ == DragState::STOP) {
        FI_HILOGW("No drag instance running, can not set drag window visible");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
        ReportDragWindowVisibleRadarInfo(StageRes::RES_FAIL, DragRadarErrCode::FAILED_SET_DRAG_VISIBLE, __func__);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
        return RET_ERR;
    }
    if (!isForce && GetControlCollaborationVisible()) {
        FI_HILOGW("The drag-and-drop window is controlled by multi-screen coordination,"
            "can not set drag window visible:%{public}d", visible);
        return RET_OK;
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
    DragDFX::WriteDragWindowVisible(dragState_, visible, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    DRAG_DATA_MGR.SetDragWindowVisible(visible);
    dragDrawing_.UpdateDragWindowState(visible, isZoomInAndAlphaChanged);
    DragData dragData = DRAG_DATA_MGR.GetDragData();
#ifndef OHOS_BUILD_PC_PRODUCT
    if (dragData.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE && visible) {
        FI_HILOGI("Set the pointer cursor invisible");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
        MMI::InputManager::GetInstance()->SetPointerVisible(false);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    }
#endif // OHOS_BUILD_PC_PRODUCT

    if (isForce) {
        SetControlCollaborationVisible(isForce);
        FI_HILOGW("The drag-and-drop window is controlled by multi-screen coordination");
    }
    return RET_OK;
}

int32_t DragManager::OnGetShadowOffset(ShadowOffset &shadowOffset)
{
    FI_HILOGI("enter");
    return DRAG_DATA_MGR.GetShadowOffset(shadowOffset);
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
void DragManager::RegisterStateChange(std::function<void(DragState)> callback)
{
    FI_HILOGI("enter");
    CHKPV(callback);
    stateChangedCallback_ = callback;
    FI_HILOGI("leave");
}

void DragManager::UnregisterStateChange()
{
    FI_HILOGI("Unregister state-change callback");
    stateChangedCallback_ = nullptr;
}

void DragManager::RegisterNotifyPullUp(std::function<void(bool)> callback)
{
    FI_HILOGI("enter");
    CHKPV(callback);
    notifyPUllUpCallback_ = callback;
    FI_HILOGI("leave");
}

void DragManager::UnregisterNotifyPullUp()
{
    FI_HILOGI("Unregister notify-pullup callback");
    notifyPUllUpCallback_ = nullptr;
}

void DragManager::RegisterCrossDrag(std::function<void(bool)> callback)
{
    FI_HILOGD("Register cross_drag callback");
    crossDragCallback_ = callback;
}

void DragManager::UnregisterCrossDrag()
{
    FI_HILOGD("Unregister cross_drag callback");
    crossDragCallback_ = nullptr;
}

void DragManager::NotifyCrossDrag(bool isButtonDown)
{
    CHKPV(crossDragCallback_);
    crossDragCallback_(isButtonDown);
}

void DragManager::StateChangedNotify(DragState state)
{
    FI_HILOGD("enter");
    CHKPV(stateChangedCallback_);
    if (state == DragState::STOP) {
        stateChangedCallback_(state);
    } else if (dragState_ != DragState::MOTION_DRAGGING) {
        stateChangedCallback_(state);
    }
    FI_HILOGD("leave");
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

MMI::ExtraData DragManager::GetExtraData(bool appended) const
{
    return CreateExtraData(appended);
}

DragState DragManager::GetDragState() const
{
    return dragState_;
}

void DragManager::GetAllowDragState(bool &isAllowDrag)
{
    FI_HILOGD("enter");
    if (dragState_ != DragState::START) {
        FI_HILOGW("Currently state is \'%{public}d\', allow cooperate", static_cast<int32_t>(dragState_));
        return;
    }
    isAllowDrag = dragDrawing_.GetAllowDragState();
    FI_HILOGD("leave");
}

void DragManager::SetDragState(DragState state)
{
    FI_HILOGI("SetDragState:%{public}d to %{public}d", static_cast<int32_t>(dragState_), static_cast<int32_t>(state));
    if ((dragState_ == DragState::STOP) && (state == DragState::MOTION_DRAGGING)) {
        FI_HILOGW("Unreasonable drag state switching");
        return;
    }
    dragState_ = state;
    dragDrawing_.UpdateDragState(state);
    if (state == DragState::START) {
        UpdateDragStyleCross();
    }
}

void DragManager::SetDragOriginDpi(float dragOriginDpi)
{
    DRAG_DATA_MGR.SetDragOriginDpi(dragOriginDpi);
}

DragResult DragManager::GetDragResult() const
{
    return dragResult_;
}

std::string DragManager::GetAppCallee() const
{
    return appCallee_;
}

void DragManager::SetControlCollaborationVisible(bool visible)
{
    isControlCollaborationVisible_ = visible;
}
bool DragManager::GetControlCollaborationVisible() const
{
    return isControlCollaborationVisible_;
}

int32_t DragManager::GetDragSummary(std::map<std::string, int64_t> &summarys)
{
    FI_HILOGI("enter");
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    summarys = dragData.summarys;
    if (summarys.empty()) {
        FI_HILOGD("Summarys is empty");
    }
    FI_HILOGI("leave");
    return RET_OK;
}

int32_t DragManager::HandleDragResult(DragResult result, bool hasCustomAnimation)
{
    FI_HILOGI("enter");
    switch (result) {
        case DragResult::DRAG_SUCCESS: {
            if (!hasCustomAnimation) {
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
                dragDrawing_.OnDragSuccess(context_);
#else
                dragDrawing_.OnDragSuccess();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
            } else {
                dragDrawing_.DestroyDragWindow();
                dragDrawing_.UpdateDrawingState();
            }
            break;
        }
        case DragResult::DRAG_FAIL:
        case DragResult::DRAG_CANCEL: {
            if (!hasCustomAnimation) {
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
                dragDrawing_.OnDragFail(context_, isLongPressDrag_);
#else
                dragDrawing_.OnDragFail();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
            } else {
                dragDrawing_.DestroyDragWindow();
                dragDrawing_.UpdateDrawingState();
            }
            break;
        }
        case DragResult::DRAG_EXCEPTION: {
            dragDrawing_.DestroyDragWindow();
            dragDrawing_.UpdateDrawingState();
            break;
        }
        default: {
            FI_HILOGW("Unsupported DragResult type, DragResult:%{public}d", result);
            break;
        }
    }
    FI_HILOGI("leave");
    return RET_OK;
}

void DragManager::SetPointerEventFilterTime(int64_t filterTime)
{
    FI_HILOGD("enter");
    g_startFilterTime = filterTime;
    FI_HILOGD("leave");
}

void DragManager::MoveTo(int32_t x, int32_t y, bool isMultiSelectedAnimation)
{
    if (dragState_ != DragState::START && dragState_ != DragState::MOTION_DRAGGING) {
        FI_HILOGE("Drag instance not running");
        return;
    }
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    FI_HILOGI("displayId:%{public}d, x:%{private}d, y:%{private}d", dragData.displayId, x, y);
    dragDrawing_.Draw(dragData.displayId, x, y, true, isMultiSelectedAnimation);
}

void DragManager::SetMultiSelectedAnimationFlag(bool needMultiSelectedAnimation)
{
    FI_HILOGI("needMultiSelectedAnimation:%{public}d", needMultiSelectedAnimation);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    CHKPV(context_);
    int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this, needMultiSelectedAnimation] {
        this->dragDrawing_.SetMultiSelectedAnimationFlag(needMultiSelectedAnimation);
        return RET_OK;
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post async task failed, ret:%{public}d", ret);
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
}

int32_t DragManager::UpdatePreviewStyle(const PreviewStyle &previewStyle)
{
    if (dragState_ != DragState::START && dragState_ != DragState::MOTION_DRAGGING) {
        FI_HILOGE("Drag instance not running");
        return RET_ERR;
    }
    if (previewStyle == DRAG_DATA_MGR.GetPreviewStyle()) {
        FI_HILOGD("Not need to update previewStyle");
        return RET_OK;
    }
    DRAG_DATA_MGR.SetPreviewStyle(previewStyle);
    FI_HILOGI("Update previewStyle successfully");
    return dragDrawing_.UpdatePreviewStyle(previewStyle);
}

int32_t DragManager::UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle,
    const PreviewAnimation &animation)
{
    if (dragState_ != DragState::START && dragState_ != DragState::MOTION_DRAGGING) {
        FI_HILOGE("Drag instance not running");
        return RET_ERR;
    }
    if (previewStyle == DRAG_DATA_MGR.GetPreviewStyle()) {
        FI_HILOGD("Not need to update previewStyle");
        return RET_OK;
    }
    DRAG_DATA_MGR.SetPreviewStyle(previewStyle);
    FI_HILOGI("Update previewStyle successfully");
    return dragDrawing_.UpdatePreviewStyleWithAnimation(previewStyle, animation);
}

int32_t DragManager::RotateDragWindowSync(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    return dragDrawing_.RotateDragWindowSync(rsTransaction);
}

void DragManager::SetDragWindowScreenId(uint64_t displayId, uint64_t screenId)
{
    FI_HILOGI("displayId:%{public}" PRId64 ", screenId:%{public}" PRId64 "", displayId, screenId);
    displayId_ = displayId;
    screenId_ = screenId;
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
void DragManager::DragKeyEventCallback(std::shared_ptr<MMI::KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    auto keyItems = keyEvent->GetKeyItems();
    auto iter = std::find_if(keyItems.begin(), keyItems.end(),
        [] (std::optional<MMI::KeyEvent::KeyItem> keyItem) {
            return ((keyItem->GetKeyCode() == MMI::KeyEvent::KEYCODE_CTRL_LEFT) ||
                    (keyItem->GetKeyCode() == MMI::KeyEvent::KEYCODE_CTRL_RIGHT));
        });
    if (iter == keyItems.end()) {
        dragAction_.store(DragAction::MOVE);
        return;
    }
    if ((DRAG_DATA_MGR.GetDragStyle() == DragCursorStyle::DEFAULT) ||
        (DRAG_DATA_MGR.GetDragStyle() == DragCursorStyle::FORBIDDEN)) {
        dragAction_.store(DragAction::MOVE);
        return;
    }
    if (!iter->IsPressed()) {
        CtrlKeyStyleChangedNotify(DRAG_DATA_MGR.GetDragStyle(), DragAction::MOVE);
        HandleCtrlKeyEvent(DRAG_DATA_MGR.GetDragStyle(), DragAction::MOVE);
        dragAction_.store(DragAction::MOVE);
        return;
    }
    if (DRAG_DATA_MGR.GetDragStyle() == DragCursorStyle::COPY) {
        FI_HILOGD("Not need update drag style");
        return;
    }
    CtrlKeyStyleChangedNotify(DragCursorStyle::COPY, DragAction::COPY);
    HandleCtrlKeyEvent(DragCursorStyle::COPY, DragAction::COPY);
    dragAction_.store(DragAction::COPY);
}

void DragManager::HandleCtrlKeyEvent(DragCursorStyle style, DragAction action)
{
    FI_HILOGD("enter");
    if (action == dragAction_.load()) {
        FI_HILOGD("Not need update drag style");
        return;
    }
    CHKPV(context_);
    int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this, style] {
        return this->dragDrawing_.UpdateDragStyle(style);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post async task failed");
    }
    FI_HILOGD("leave");
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

int32_t DragManager::OnUpdateDragStyle(DragCursorStyle style)
{
    FI_HILOGD("enter");
    DragCursorStyle updateStyle = GetRealDragStyle(style);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    stateNotify_.StyleChangedNotify(updateStyle);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    if (dragDrawing_.UpdateDragStyle(updateStyle) != RET_OK) {
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
        DragDFX::WriteUpdateDragStyle(updateStyle, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#endif // OHOS_BUILD_ENABLE_ARKUI_X
        return RET_ERR;
    }
    FI_HILOGD("Update dragStyle:%{public}s successfully", GetDragStyleName(updateStyle).c_str());
    return RET_OK;
}

void DragManager::UpdateDragStyleCross()
{
    FI_HILOGD("enter");
    auto dragStyle = DRAG_DATA_MGR.GetDragStyle();
    FI_HILOGI("OnUpdateDragStyle dragStyle:%{public}s", GetDragStyleName(dragStyle).c_str());
    if (OnUpdateDragStyle(DRAG_DATA_MGR.GetDragStyle()) != RET_OK) {
        FI_HILOGE("OnUpdateDragStyle failed");
    }
    FI_HILOGD("leave");
}

std::string DragManager::GetDragStyleName(DragCursorStyle style)
{
    switch (style) {
        case DragCursorStyle::DEFAULT : {
            return DRAG_STYLE_DEFAULT;
        }
        case DragCursorStyle::FORBIDDEN : {
            return DRAG_STYLE_FORBIDDEN;
        }
        case DragCursorStyle::COPY : {
            return DRAG_STYLE_COPY;
        }
        case DragCursorStyle::MOVE : {
            return DRAG_STYLE_MOVE;
        }
        default:
            break;
    }
    return DRAG_STYLE_UNKNOW;
}

DragCursorStyle DragManager::GetRealDragStyle(DragCursorStyle style)
{
    if ((dragAction_ == DragAction::COPY) && (style == DragCursorStyle::MOVE)) {
        return DragCursorStyle::COPY;
    }
    return style;
}

void DragManager::GetDragBehavior(const DragDropResult &dropResult, DragBehavior &dragBehavior)
{
    FI_HILOGD("enter");
    if (dropResult.result != DragResult::DRAG_SUCCESS) {
        dragBehavior = DragBehavior::UNKNOWN;
        return;
    }
    if (dragBehavior == DragBehavior::UNKNOWN) {
        if (DRAG_DATA_MGR.GetDragStyle() == DragCursorStyle::COPY) {
            dragBehavior = DragBehavior::COPY;
            return;
        }
        if (dragAction_.load()== DragAction::COPY) {
            dragBehavior = DragBehavior::COPY;
            return;
        }
        DragData dragData = DRAG_DATA_MGR.GetDragData();
        if (dropResult.mainWindow == dragData.mainWindow) {
            dragBehavior = DragBehavior::MOVE;
        } else {
            dragBehavior = DragBehavior::COPY;
        }
    }
    FI_HILOGD("leave");
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
void DragManager::CtrlKeyStyleChangedNotify(DragCursorStyle style, DragAction action)
{
    FI_HILOGD("enter");
    if (action == dragAction_.load()) {
        FI_HILOGD("Has notified");
        return;
    }
    CHKPV(context_);
    int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this, style] {
        return this->stateNotify_.StyleChangedNotify(style);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post async task failed");
    }
    FI_HILOGD("leave");
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

int32_t DragManager::GetDragAction(DragAction &dragAction) const
{
    FI_HILOGD("enter");
    if (dragState_ != DragState::START) {
        FI_HILOGE("No drag instance running, can not get drag action");
        return RET_ERR;
    }
    dragAction = dragAction_.load();
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragManager::EnterTextEditorArea(bool enable)
{
    FI_HILOGD("enter");
    if (dragState_ != DragState::START) {
        FI_HILOGE("No drag instance running");
        return RET_ERR;
    }
    if (DRAG_DATA_MGR.GetTextEditorAreaFlag() == enable) {
        FI_HILOGE("Set textEditorArea:%{public}s already", (enable ? "true" : "false"));
        return RET_ERR;
    }
    if (DRAG_DATA_MGR.GetCoordinateCorrected()) {
        FI_HILOGE("GetCoordinateCorrected failed");
        return RET_ERR;
    }
    FI_HILOGD("leave");
    return dragDrawing_.EnterTextEditorArea(enable);
}

int32_t DragManager::GetExtraInfo(std::string &extraInfo) const
{
    FI_HILOGD("enter");
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    if (dragData.extraInfo.empty()) {
        FI_HILOGE("The extraInfo is empty");
        return RET_ERR;
    }
    extraInfo = dragData.extraInfo;
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragManager::AddPrivilege(int32_t tokenId)
{
    FI_HILOGD("enter");
    if (dragState_ != DragState::START && dragState_ != DragState::MOTION_DRAGGING) {
        FI_HILOGE("Drag instance not running");
        return RET_ERR;
    }
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    FI_HILOGD("Target window drag tid:%{public}d", tokenId);
    SendDragData(tokenId, dragData.udKey);
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragManager::EraseMouseIcon()
{
    FI_HILOGD("enter");
    if (dragState_ != DragState::START && dragState_ != DragState::MOTION_DRAGGING) {
        FI_HILOGE("Drag instance not running");
        return RET_ERR;
    }
    dragDrawing_.EraseMouseIcon();
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragManager::GetDragBundleInfo(DragBundleInfo &dragBundleInfo) const
{
    FI_HILOGD("enter");
    if (dragState_ != DragState::START && dragState_ != DragState::MOTION_DRAGGING) {
        FI_HILOGE("No drag instance running, can not get drag bundle info");
        return RET_ERR;
    }

    dragBundleInfo.isCrossDevice = isCrossDragging_;

    dragBundleInfo.bundleName = dragPackageName_.appCaller;
    FI_HILOGD("leave, bundleName:%{public}s, isCrossDevice:%{public}d",
        dragBundleInfo.bundleName.c_str(), dragBundleInfo.isCrossDevice);
    return RET_OK;
}

int32_t DragManager::RotateDragWindow(Rosen::Rotation rotation)
{
    FI_HILOGI("Rotation:%{public}d", static_cast<int32_t>(rotation));
    auto SetDragWindowRotate = [rotation, this]() {
        dragDrawing_.SetRotation(rotation);
        if ((dragState_ == DragState::START) || (dragState_ == DragState::MOTION_DRAGGING)) {
            dragDrawing_.RotateDragWindowAsync(rotation);
        }
        return RET_OK;
    };
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    CHKPR(context_, RET_ERR);
    int32_t ret = context_->GetDelegateTasks().PostAsyncTask(SetDragWindowRotate);
    if (ret != RET_OK) {
        FI_HILOGE("Post async task failed, ret:%{public}d", ret);
        return ret;
    }
#else
    SetDragWindowRotate();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragManager::ScreenRotate(Rosen::Rotation rotation, Rosen::Rotation lastRotation)
{
    FI_HILOGI("Rotation:%{public}d, lastRotation:%{public}d",
        static_cast<int32_t>(rotation), static_cast<int32_t>(lastRotation));
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    if (dragData.sourceType != MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        FI_HILOGD("Not need screen rotate");
        return RET_OK;
    }
    auto SetDragWindowRotate = [rotation, lastRotation, this]() {
        if ((dragState_ == DragState::START) || (dragState_ == DragState::MOTION_DRAGGING)) {
            dragDrawing_.ScreenRotate(rotation, lastRotation);
        }
        return RET_OK;
    };
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    CHKPR(context_, RET_ERR);
    int32_t ret = context_->GetDelegateTasks().PostAsyncTask(SetDragWindowRotate);
    if (ret != RET_OK) {
        FI_HILOGE("Post async task failed, ret:%{public}d", ret);
        return ret;
    }
#else
    SetDragWindowRotate();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    FI_HILOGD("leave");
    return RET_OK;
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
int32_t DragManager::NotifyAddSelectedPixelMapResult(bool result)
{
    FI_HILOGD("enter");
    NetPacket pkt(MessageId::ADD_SELECTED_PIXELMAP_RESULT);
    pkt << result;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to packet write data");
        return RET_ERR;
    }
    CHKPR(dragOutSession_, RET_ERR);
    if (!dragOutSession_->SendMsg(pkt)) {
        FI_HILOGE("Failed to send message");
        return MSG_SEND_FAIL;
    }
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragManager::AddSelectedPixelMap(std::shared_ptr<OHOS::Media::PixelMap> pixelMap)
{
    FI_HILOGD("enter");
    if (dragState_ != DragState::START) {
        FI_HILOGE("Drag not running");
        if (NotifyAddSelectedPixelMapResult(false) != RET_OK) {
            FI_HILOGE("Notify addSelectedPixelMap result failed");
        }
        return RET_ERR;
    }
    if (dragDrawing_.AddSelectedPixelMap(pixelMap) != RET_OK) {
        FI_HILOGE("Add select pixelmap fail");
        if (NotifyAddSelectedPixelMapResult(false) != RET_OK) {
            FI_HILOGE("Notify addSelectedPixelMap result failed");
        }
        return RET_ERR;
    }
    DRAG_DATA_MGR.UpdateShadowInfos(pixelMap);
    if (NotifyAddSelectedPixelMapResult(true) != RET_OK) {
        FI_HILOGW("Notify addSelectedPixelMap result failed");
    }
    FI_HILOGD("leave");
    return RET_OK;
}

#else
void DragManager::SetDragWindow(std::shared_ptr<OHOS::Rosen::Window> window)
{
    dragDrawing_.SetDragWindow(window);
}

void DragManager::AddDragDestroy(std::function<void()> cb)
{
    dragDrawing_.AddDragDestroy(cb);
}

void DragManager::SetSVGFilePath(const std::string &filePath)
{
    dragDrawing_.SetSVGFilePath(filePath);
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
int32_t DragManager::AddDragEvent(const DragData &dragData, const struct DragRadarPackageName &dragRadarPackageName)
{
    bool drawCursor = false;
#ifdef OHOS_BUILD_PC_PRODUCT
    if (dragData.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        drawCursor = true;
    }
#endif // OHOS_BUILD_PC_PRODUCT
    auto extraData = CreateExtraData(true, drawCursor);
    if (MMI::InputManager::GetInstance()->AppendExtraData(extraData) != RET_OK) {
        FI_HILOGE("Failed to append extra data to MMI");
        dragDrawing_.DestroyDragWindow();
        dragDrawing_.UpdateDrawingState();
        ReportStartDragFailedRadarInfo(StageRes::RES_FAIL, DragRadarErrCode::FAILED_APPEND_EXTRA_DATA, __func__,
            dragRadarPackageName);
        return RET_ERR;
    }
    if (pointerEventMonitorId_ <= 0) {
        if (AddDragEventHandler(dragData.sourceType) != RET_OK) {
            FI_HILOGE("Failed to add drag event handler");
            dragDrawing_.DestroyDragWindow();
            dragDrawing_.UpdateDrawingState();
            ReportStartDragFailedRadarInfo(StageRes::RES_FAIL, DragRadarErrCode::FAILED_ADD_INPUT_MONITOR, __func__,
                dragRadarPackageName);
            return RET_ERR;
        }
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
void DragManager::ResetMouseDragMonitorInfo()
{
    FI_HILOGI("enter");
    RemoveDragEventHandler();
    mouseDragMonitorDisplayX_ = -1;
    mouseDragMonitorDisplayY_ = -1;
    existMouseMoveDragCallback_ = false;
    mouseDragMonitorState_ = false;
    DRAG_DATA_MGR.SetEventId(-1);
    if ((context_ != nullptr) && (mouseDragMonitorTimerId_ >= 0)) {
        context_->GetTimerManager().RemoveTimer(mouseDragMonitorTimerId_);
        mouseDragMonitorTimerId_ = -1;
    }
    FI_HILOGI("leave");
}

int32_t DragManager::SetMouseDragMonitorState(bool state)
{
    if (state) {
        if (AddDragEventHandler(MMI::PointerEvent::SOURCE_TYPE_MOUSE) != RET_OK) {
            FI_HILOGE("Failed to add drag event handler");
            return RET_ERR;
        }
        if (context_ != nullptr) {
            int32_t repeatCount = 1;
            mouseDragMonitorTimerId_ = context_->GetTimerManager().AddTimer(TIMEOUT_MS,
                repeatCount, [this]() {
                FI_HILOGW("Timeout, automatically remove monitor");
                this->ResetMouseDragMonitorInfo();
            });
        }
    } else {
        ResetMouseDragMonitorInfo();
    }
    mouseDragMonitorState_ = state;
    return RET_OK;
}

void DragManager::ReportDragWindowVisibleRadarInfo(StageRes stageRes, DragRadarErrCode errCode,
    const std::string &funcName)
{
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MSDP,
        DRAG_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "ORG_PKG", ORG_PKG_NAME,
        "FUNC", funcName,
        "BIZ_SCENE", 1,
        "BIZ_STATE", static_cast<int32_t>(BizState::STATE_IDLE),
        "BIZ_STAGE", static_cast<int32_t>(BizStage::STAGE_DRAGGING),
        "STAGE_RES", static_cast<int32_t>(stageRes),
        "ERROR_CODE", static_cast<int32_t>(errCode),
        "HOST_PKG", "",
        "LOCAL_NET_ID", "",
        "PEER_NET_ID", "",
        "DRAG_SUMMARY", "");
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
}
 
void DragManager::ReportStopDragRadarInfo(BizState bizState, StageRes stageRes, DragRadarErrCode errCode, int32_t pid,
    struct DragRadarPackageName &dragRadarPackageName)
{
    DragRadarInfo dragRadarInfo;
    dragRadarInfo.funcName = "StopDrag";
    dragRadarInfo.bizState = static_cast<int32_t>(bizState);
    dragRadarInfo.bizStage = static_cast<int32_t>(BizStage::STAGE_STOP_DRAG);
    dragRadarInfo.stageRes = static_cast<int32_t>(stageRes);
    dragRadarInfo.errCode = static_cast<int32_t>(errCode);
    dragRadarInfo.hostName = dragRadarPackageName.packageName;
    dragRadarInfo.callingPid = std::to_string(pid);
    dragRadarInfo.appCallee = dragRadarPackageName.appCallee;
    dragRadarInfo.peerNetId = dragRadarPackageName.peerNetId;
    ReportDragRadarInfo(dragRadarInfo);
}

void DragManager::ReportStartDragRadarInfo(BizState bizState, StageRes stageRes, DragRadarErrCode errCode,
    const std::string &peerNetId, struct DragRadarPackageName &dragRadarPackageName)
{
    DragRadarInfo dragRadarInfo;
    dragRadarInfo.funcName = "StartDrag";
    dragRadarInfo.bizState = static_cast<int32_t>(bizState);
    dragRadarInfo.bizStage = static_cast<int32_t>(BizStage::STAGE_START_DRAG);
    dragRadarInfo.stageRes = static_cast<int32_t>(stageRes);
    dragRadarInfo.errCode = static_cast<int32_t>(errCode);
    dragRadarInfo.hostName = dragRadarPackageName.packageName;
    dragRadarInfo.peerNetId = peerNetId;
    dragRadarInfo.appCaller = dragRadarPackageName.appCaller;
    dragRadarInfo.dragNum = dragRadarPackageName.dragNum;
    ReportDragRadarInfo(dragRadarInfo);
}

void DragManager::ReportStartDragFailedRadarInfo(StageRes stageRes, DragRadarErrCode errCode,
    const std::string &funcName, const struct DragRadarPackageName &dragRadarPackageName)
{
    DragRadarInfo dragRadarInfo;
    dragRadarInfo.funcName = funcName;
    dragRadarInfo.bizState = static_cast<int32_t>(BizState::STATE_END);
    dragRadarInfo.bizStage = static_cast<int32_t>(BizStage::STAGE_START_DRAG);
    dragRadarInfo.stageRes = static_cast<int32_t>(stageRes);
    dragRadarInfo.errCode = static_cast<int32_t>(errCode);
    dragRadarInfo.hostName = dragRadarPackageName.packageName;
    dragRadarInfo.appCaller = dragRadarPackageName.appCaller;
    ReportDragRadarInfo(dragRadarInfo);
}

void DragManager::ReportDragRadarInfo(struct DragRadarInfo &dragRadarInfo)
{
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
    DragData dragData = DRAG_DATA_MGR.GetDragData();
    std::string summary;
    for (const auto &[udKey, recordSize] : dragData.summarys) {
        std::string str = udKey + "-" + std::to_string(recordSize) + ";";
        summary += str;
    }
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MSDP,
        DRAG_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "ORG_PKG", ORG_PKG_NAME,
        "FUNC", dragRadarInfo.funcName,
        "BIZ_SCENE", 1,
        "BIZ_STATE", dragRadarInfo.bizState,
        "BIZ_STAGE", dragRadarInfo.bizStage,
        "STAGE_RES", dragRadarInfo.stageRes,
        "ERROR_CODE", dragRadarInfo.errCode,
        "HOST_PKG", dragRadarInfo.hostName,
        "LOCAL_NET_ID", dragRadarInfo.localNetId,
        "PEER_NET_ID", dragRadarInfo.peerNetId,
        "DRAG_SUMMARY", summary,
        "PACKAGE_NAME", dragRadarInfo.callingPid,
        "APP_CALLEE", dragRadarInfo.appCallee,
        "APP_CALLER", dragRadarInfo.appCaller,
        "DRAG_NUM", dragRadarInfo.dragNum);
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
}

void DragManager::ReportStartDragUEInfo(const std::string &packageName)
{
    DragRadarInfo dragRadarInfo;
    dragRadarInfo.packageName = DRAG_FRAMEWORK;
    dragRadarInfo.appVersionId = APP_VERSION_ID;
    dragRadarInfo.hostName = packageName;
    dragRadarInfo.localNetId = Utility::DFXRadarAnonymize(IDSoftbusAdapter::GetLocalNetworkId().c_str());
    dragRadarInfo.peerNetId = peerNetId_;
    ReportDragUEInfo(dragRadarInfo, START_CROSSING_DRAG);
}

void DragManager::ReportStopDragUEInfo(const std::string &packageName)
{
    DragRadarInfo dragRadarInfo;
    dragRadarInfo.packageName = DRAG_FRAMEWORK;
    dragRadarInfo.appVersionId = APP_VERSION_ID;
    dragRadarInfo.hostName = packageName;
    dragRadarInfo.localNetId = Utility::DFXRadarAnonymize(IDSoftbusAdapter::GetLocalNetworkId().c_str());
    dragRadarInfo.peerNetId = peerNetId_;
    ReportDragUEInfo(dragRadarInfo, END_CROSSING_DRAG);
}

void DragManager::ReportDragUEInfo(struct DragRadarInfo &dragRadarInfo, const std::string &eventDescription)
{
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::DRAG_UE,
        eventDescription,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "PNAMEID", dragRadarInfo.packageName,
        "PVERSIONID", dragRadarInfo.appVersionId,
        "HOSTNAME", dragRadarInfo.hostName,
        "LOCAL_NET_ID", dragRadarInfo.localNetId,
        "PEER_NET_ID", dragRadarInfo.peerNetId);
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
