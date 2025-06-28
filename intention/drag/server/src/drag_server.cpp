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

#include "drag_server.h"

#include "tokenid_kit.h"

#include "accesstoken_kit.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "DragServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

#ifdef OHOS_BUILD_UNIVERSAL_DRAG
DragServer::DragServer(IContext *env)
    : env_(env), universalDragWrapper_(env)
#else
DragServer::DragServer(IContext *env)
    : env_(env)
#endif // OHOS_BUILD_UNIVERSAL_DRAG
{
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
    bool ret = universalDragWrapper_.InitUniversalDrag();
    if (!ret) {
        FI_HILOGW("Init universal drag failed");
    }
#endif // OHOS_BUILD_UNIVERSAL_DRAG
}

int32_t DragServer::StartDrag(CallingContext &context, const DragData &dragData)
{
    CHKPR(env_, RET_ERR);
    auto session = env_->GetSocketSessionManager().FindSessionByPid(context.pid);
    CHKPR(session, RET_ERR);
    session->SetProgramName(GetPackageName(context.tokenId));
    return env_->GetDragManager().StartDrag(dragData, context.pid);
}

int32_t DragServer::StopDrag(CallingContext &context, const DragDropResult &dropResult)
{
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
    universalDragWrapper_.StopLongPressDrag();
#endif // OHOS_BUILD_UNIVERSAL_DRAG
    CHKPR(env_, RET_ERR);
    return env_->GetDragManager().StopDrag(dropResult, GetPackageName(context.tokenId), context.pid);
}

int32_t DragServer::EnableInternalDropAnimation(CallingContext &context, const std::string &animationInfo)
{
#ifdef OHOS_BUILD_INTERNAL_DROP_ANIMATION
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    CHKPR(env_, RET_ERR);
    return env_->GetDragManager().EnableInternalDropAnimation(animationInfo);
#endif // OHOS_BUILD_INTERNAL_DROP_ANIMATION
    return COMMON_CAPABILITY_NOT_SUPPORT;
}

int32_t DragServer::AddDraglistener(CallingContext &context, bool isJsCaller)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    FI_HILOGI("Add drag listener, from:%{public}d", context.pid);
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().AddListener(context.pid); ret != RET_OK) {
        FI_HILOGE("IDragManager::AddListener fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::RemoveDraglistener(CallingContext &context, bool isJsCaller)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    FI_HILOGD("Remove drag listener, from:%{public}d", context.pid);
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().RemoveListener(context.pid); ret != RET_OK) {
        FI_HILOGE("IDragManager::RemoveListener fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::AddSubscriptListener(CallingContext &context)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    FI_HILOGD("Add subscript listener, from:%{public}d", context.pid);
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().AddSubscriptListener(context.pid); ret != RET_OK) {
        FI_HILOGE("IDragManager::AddSubscriptListener fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::RemoveSubscriptListener(CallingContext &context)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    FI_HILOGD("Remove subscript listener, from:%{public}d", context.pid);
    CHKPR(env_, RET_ERR);
     if (int32_t ret = env_->GetDragManager().RemoveSubscriptListener(context.pid); ret != RET_OK) {
        FI_HILOGE("IDragManager::RemoveSubscriptListener fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::SetDragWindowVisible(bool visible, bool isForce,
    const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    FI_HILOGI("SetDragWindowVisible(%{public}d, %{public}d)", visible, isForce);
    CHKPR(env_, RET_ERR);
    return env_->GetDragManager().OnSetDragWindowVisible(visible, isForce, false, rsTransaction);
}

int32_t DragServer::GetDragTargetPid(CallingContext &context, int32_t &targetPid)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    CHKPR(env_, RET_ERR);
    targetPid = env_->GetDragManager().GetDragTargetPid();
    return RET_OK;
}

int32_t DragServer::GetUdKey(std::string &udKey)
{
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().GetUdKey(udKey); ret != RET_OK) {
        FI_HILOGE("IDragManager::GetUdKey fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::GetShadowOffset(ShadowOffset &shadowOffset)
{
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().OnGetShadowOffset(shadowOffset); ret != RET_OK) {
        FI_HILOGE("IDragManager::OnGetShadowOffset fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::UpdateDragStyle(CallingContext &context, DragCursorStyle style, int32_t eventId)
{
    CHKPR(env_, RET_ERR);
    int32_t ret = env_->GetDragManager().UpdateDragStyle(style, context.pid, context.tokenId, eventId);
    if (ret != RET_OK) {
        FI_HILOGE("IDragManager::UpdateDragStyle fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::UpdateShadowPic(const ShadowInfo &shadowInfo)
{
    CHKPR(env_, RET_ERR);
    int32_t ret = env_->GetDragManager().UpdateShadowPic(shadowInfo);
    if (ret != RET_OK) {
        FI_HILOGE("IDragManager::UpdateShadowPic fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::GetDragData(CallingContext &context, DragData &dragData)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().GetDragData(dragData); ret != RET_OK) {
        FI_HILOGE("IDragManager::GetDragData fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::UpdatePreviewStyle(const PreviewStyle &previewStyle)
{
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().UpdatePreviewStyle(previewStyle); ret != RET_OK) {
        FI_HILOGE("IDragManager::UpdatePreviewStyle fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle, const PreviewAnimation &animation)
{
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().UpdatePreviewStyleWithAnimation(previewStyle, animation); ret != RET_OK) {
        FI_HILOGE("IDragManager::UpdatePreviewStyleWithAnimation fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::RotateDragWindowSync(CallingContext &context,
    const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().RotateDragWindowSync(rsTransaction); ret != RET_OK) {
        FI_HILOGE("IDragManager::RotateDragWindowSync fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::SetDragWindowScreenId(CallingContext &context, uint64_t displayId, uint64_t screenId)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    CHKPR(env_, RET_ERR);
    env_->GetDragManager().SetDragWindowScreenId(displayId, screenId);
    return RET_OK;
}

int32_t DragServer::GetDragSummary(CallingContext &context, std::map<std::string, int64_t> &summarys, bool isJsCaller)
{
    if (isJsCaller && !IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().GetDragSummary(summarys); ret != RET_OK) {
        FI_HILOGE("IDragManager::GetDragSummary fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::SetDragSwitchState(CallingContext &context, bool enable, bool isJsCaller)
{
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    universalDragWrapper_.SetDragSwitchState(enable);
#endif // OHOS_BUILD_UNIVERSAL_DRAG
    return RET_OK;
}

int32_t DragServer::SetAppDragSwitchState(
    CallingContext &context, bool enable, const std::string &pkgName, bool isJsCaller)
{
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    universalDragWrapper_.SetAppDragSwitchState(enable, pkgName);
#endif // OHOS_BUILD_UNIVERSAL_DRAG
    return RET_OK;
}

int32_t DragServer::GetDragState(CallingContext &context, DragState &dragState)
{
    CHKPR(env_, RET_ERR);
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }

    if (int32_t ret = env_->GetDragManager().GetDragState(dragState); ret != RET_OK) {
        FI_HILOGE("IDragManager::GetDragState fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::EnableUpperCenterMode(bool enable)
{
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().EnterTextEditorArea(enable); ret != RET_OK) {
        FI_HILOGE("IDragManager::EnableUpperCenterMode fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::GetDragAction(DragAction &dragAction)
{
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().GetDragAction(dragAction); ret != RET_OK) {
        FI_HILOGE("IDragManager::GetDragAction fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::GetExtraInfo(std::string &extraInfo)
{
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().GetExtraInfo(extraInfo); ret != RET_OK) {
        FI_HILOGE("IDragManager::GetExtraInfo fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::AddPrivilege(CallingContext &context)
{
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().AddPrivilege(context.tokenId); ret != RET_OK) {
        FI_HILOGE("IDragManager::AddPrivilege fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::EraseMouseIcon(CallingContext &context)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().EraseMouseIcon(); ret != RET_OK) {
        FI_HILOGE("IDragManager::EraseMouseIcon fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::SetMouseDragMonitorState(bool state)
{
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().SetMouseDragMonitorState(state); ret != RET_OK) {
        FI_HILOGE("IDragManager::SetMouseDragMonitorState fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t DragServer::SetDraggableState(bool state)
{
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
    universalDragWrapper_.SetDragableState(state);
#endif // OHOS_BUILD_UNIVERSAL_DRAG
    return RET_OK;
}

int32_t DragServer::GetAppDragSwitchState(bool &state)
{
    state = false;
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
    if (int32_t ret = universalDragWrapper_.GetAppDragSwitchState(state); ret != RET_OK) {
        FI_HILOGE("IDragManager::GetAppDragSwitchState fail, error:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_UNIVERSAL_DRAG
    return RET_OK;
}

int32_t DragServer::SetDraggableStateAsync(bool state, int64_t downTime)
{
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
    CHKPR(env_, RET_ERR);
    env_->GetDelegateTasks().PostAsyncTask([this, state, downTime] {
        this->universalDragWrapper_.SetDraggableStateAsync(state, downTime);
        return RET_OK;
    });
#endif // OHOS_BUILD_UNIVERSAL_DRAG
    return RET_OK;
}

int32_t DragServer::GetDragBundleInfo(DragBundleInfo &dragBundleInfo)
{
    CHKPR(env_, RET_ERR);
    if (int32_t ret = env_->GetDragManager().GetDragBundleInfo(dragBundleInfo); ret != RET_OK) {
        FI_HILOGE("IDragManager::GetDragBundleInfo fail, error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

std::string DragServer::GetPackageName(Security::AccessToken::AccessTokenID tokenId)
{
    std::string packageName = std::string();
    int32_t tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    switch (tokenType) {
        case Security::AccessToken::ATokenTypeEnum::TOKEN_HAP: {
            Security::AccessToken::HapTokenInfo hapInfo;
            if (Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapInfo) != 0) {
                FI_HILOGE("Get hap token info failed");
            } else {
                packageName = hapInfo.bundleName;
            }
            break;
        }
        case Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE:
        case Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL: {
            Security::AccessToken::NativeTokenInfo tokenInfo;
            if (Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo) != 0) {
                FI_HILOGE("Get native token info failed");
            } else {
                packageName = tokenInfo.processName;
            }
            break;
        }
        default: {
            FI_HILOGW("token type not match");
            break;
        }
    }
    return packageName;
}

bool DragServer::IsSystemServiceCalling(CallingContext &context)
{
    auto flag = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    if ((flag == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) ||
        (flag == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL)) {
        FI_HILOGI("system service calling, flag:%{public}u", flag);
        return true;
    }
    return false;
}

bool DragServer::IsSystemHAPCalling(CallingContext &context)
{
    if (IsSystemServiceCalling(context)) {
        return true;
    }
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(context.fullTokenId);
}

int32_t DragServer::IsDragStart(bool &isStart)
{
    CHKPR(env_, RET_ERR);
    isStart = env_->GetDragManager().IsDragStart();
    return RET_OK;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS