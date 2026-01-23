/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "display_change_event_listener.h"

#include "devicestatus_define.h"
#include "product_name_definition_parser.h"
#include "parameters.h"

#undef LOG_TAG
#define LOG_TAG "DisplayChangeEventListener"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t INDEX_FOLDED { 0 };
constexpr int32_t INDEX_EXPAND { 1 };
constexpr size_t MAX_INDEX_LENGTH { 2 };
const std::string SCREEN_ROTATION { "1" };
const std::string SYS_PRODUCT_TYPE = OHOS::system::GetParameter("const.build.product", "HYM");
} // namespace

DisplayChangeEventListener::DisplayChangeEventListener(IContext *context)
    : context_(context)
{
}

void DisplayChangeEventListener::OnCreate(Rosen::DisplayId displayId)
{
    FI_HILOGI("display:%{public}" PRIu64"", displayId);
}

void DisplayChangeEventListener::OnDestroy(Rosen::DisplayId displayId)
{
    FI_HILOGI("display:%{public}" PRIu64"", displayId);
    CHKPV(context_);
    context_->GetDragManager().RemoveDisplayIdFromMap(displayId);
}

void DisplayChangeEventListener::OnChange(Rosen::DisplayId displayId)
{
    CHKPV(context_);
    Rosen::Rotation lastRotation = context_->GetDragManager().GetRotation(displayId);
    if (IsRotateDragScreen()) {
        HandleScreenRotation(displayId, lastRotation);
        return;
    }
    sptr<Rosen::DisplayInfo> displayInfo = GetDisplayInfo(displayId);
    if (displayInfo == nullptr) {
        FI_HILOGE("displayInfo is nullptr");
        return;
    }
    Rosen::Rotation currentRotation = displayInfo->GetRotation();
    if (!IsRotation(displayId, currentRotation)) {
        return;
    }

    bool isScreenRotation = false;
    std::vector<std::string> foldRotatePolicys;
    GetRotatePolicy(isScreenRotation, foldRotatePolicys);
    FI_HILOGI("Current rotation:%{public}d, lastRotation:%{public}d",
        static_cast<int32_t>(currentRotation), static_cast<int32_t>(lastRotation));
    if (isScreenRotation) {
        ScreenRotate(currentRotation, lastRotation);
        return;
    }
    RotateDragWindow(displayId, currentRotation);
}

bool DisplayChangeEventListener::IsRotateDragScreen()
{
    if (Rosen::DisplayManager::GetInstance().IsFoldable()) {
#ifdef OHOS_ENABLE_PULLTHROW
        if (IsFoldPC()) {
            return true;
        }
#endif // OHOS_ENABLE_PULLTHROW
        bool isScreenRotation = false;
        std::vector<std::string> foldRotatePolicys;
        GetRotatePolicy(isScreenRotation, foldRotatePolicys);
        if (foldRotatePolicys.size() < MAX_INDEX_LENGTH) {
            FI_HILOGE("foldRotatePolicys is invalid");
            return false;
        }
        Rosen::FoldStatus foldStatus = Rosen::DisplayManager::GetInstance().GetFoldStatus();
        bool isExpand = (foldStatus == Rosen::FoldStatus::EXPAND || foldStatus == Rosen::FoldStatus::HALF_FOLD);
        bool isFold = (foldStatus == Rosen::FoldStatus::FOLDED);
        if (IsSecondaryDevice()) {
            isExpand = (foldStatus == Rosen::FoldStatus::EXPAND || foldStatus == Rosen::FoldStatus::HALF_FOLD ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_EXPAND_WITH_SECOND_EXPAND ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_EXPAND_WITH_SECOND_HALF_FOLDED ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_HALF_FOLDED_WITH_SECOND_EXPAND ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_HALF_FOLDED_WITH_SECOND_HALF_FOLDED);
            isFold = (foldStatus == Rosen::FoldStatus::FOLDED ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_FOLDED_WITH_SECOND_EXPAND ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_FOLDED_WITH_SECOND_HALF_FOLDED);
        }
        if ((isExpand && (foldRotatePolicys[INDEX_EXPAND] == SCREEN_ROTATION)) ||
            (isFold && (foldRotatePolicys[INDEX_FOLDED] == SCREEN_ROTATION))) {
            return true;
        }
    }
    return false;
}

void DisplayChangeEventListener::HandleScreenRotation(Rosen::DisplayId displayId, Rosen::Rotation rotation)
{
    FI_HILOGI("Handleing Screen Rotation for displayId:%{public}" PRIu64", current rotation:%{public}d",
        displayId, rotation);
    if (rotation == Rosen::Rotation::ROTATION_0) {
        FI_HILOGD("Last rotation is zero");
        return;
    }
    CHKPV(context_);
    context_->GetDragManager().SetRotation(displayId, Rosen::Rotation::ROTATION_0);
    int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this, displayId] {
        CHKPR(this->context_, RET_ERR);
        return this->context_->GetDragManager().RotateDragWindow(displayId, Rosen::Rotation::ROTATION_0);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post async task failed");
    }
    return;
}

void DisplayChangeEventListener::GetAllScreenAngles()
{
    std::vector<Rosen::DisplayId> displayIds = Rosen::DisplayManager::GetInstance().GetAllDisplayIds();
    for (const auto& displayId : displayIds) {
        sptr<Rosen::DisplayInfo> displayInfo = GetDisplayInfo(displayId);
        if (displayInfo == nullptr) {
            FI_HILOGE("displayInfo is nullptr");
            continue;
        }
        Rosen::Rotation rotation = displayInfo->GetRotation();
        FI_HILOGI("Get displayId:%{public}" PRIu64 ", rotation:%{public}d", displayId, rotation);
        CHKPV(context_);
        context_->GetDragManager().SetRotation(displayId, rotation);
    }
}

sptr<Rosen::DisplayInfo> DisplayChangeEventListener::GetDisplayInfoById(Rosen::DisplayId displayId)
{
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(displayId);
    if (display == nullptr) {
        FI_HILOGE("Get display failed, display is nullptr");
        return nullptr;
    }
    return display->GetDisplayInfo();
}

sptr<Rosen::DisplayInfo> DisplayChangeEventListener::GetDisplayInfo(Rosen::DisplayId displayId)
{
    sptr<Rosen::DisplayInfo> displayInfo = nullptr;
#ifndef OHOS_BUILD_PC_PRODUCT
    displayInfo = GetDisplayInfoById(displayId);
#else
    displayInfo = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(displayId);
#endif // OHOS_BUILD_PC_PRODUCT
    if (displayInfo == nullptr) {
        FI_HILOGE("Get display info failed, display id:%{public}" PRIu64 "", displayId);
#ifndef OHOS_BUILD_PC_PRODUCT
        displayInfo = GetDisplayInfoById(0);
#else
        displayInfo = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(0);
#endif // OHOS_BUILD_PC_PRODUCT
        if (displayInfo == nullptr) {
            FI_HILOGE("Get display info failed, displayInfo is nullptr");
            return nullptr;
        }
    }
    return displayInfo;
}

void DisplayChangeEventListener::RotateDragWindow(Rosen::DisplayId displayId, Rosen::Rotation rotation)
{
    FI_HILOGI("Rotation:%{public}d", static_cast<int32_t>(rotation));
    CHKPV(context_);
    int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this, displayId, rotation] {
        CHKPR(this->context_, RET_ERR);
        return this->context_->GetDragManager().RotateDragWindow(displayId, rotation);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post async task failed");
    }
}

bool DisplayChangeEventListener::IsRotation(Rosen::DisplayId displayId, Rosen::Rotation currentRotation)
{
    CHKPF(context_);
    Rosen::Rotation lastRotation = context_->GetDragManager().GetRotation(displayId);
    if (lastRotation != currentRotation) {
        FI_HILOGI("Need to rotate window for display id:%{public}d angle from %{public}d to %{public}d",
            static_cast<int32_t>(displayId), static_cast<int32_t>(lastRotation), static_cast<int32_t>(currentRotation));
            return true;
    }
    return false;
}

void DisplayChangeEventListener::ScreenRotate(Rosen::Rotation rotation, Rosen::Rotation lastRotation)
{
    FI_HILOGI("Rotation:%{public}d, lastRotation:%{public}d",
        static_cast<int32_t>(rotation), static_cast<int32_t>(lastRotation));
    CHKPV(context_);
    int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this, rotation, lastRotation] {
        CHKPR(this->context_, RET_ERR);
        return this->context_->GetDragManager().ScreenRotate(rotation, lastRotation);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post async task failed");
    }
}

DisplayAbilityStatusChange::DisplayAbilityStatusChange(IContext *context)
    : context_(context)
{}

void DisplayAbilityStatusChange::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    FI_HILOGI("systemAbilityId:%{public}d", systemAbilityId);
    if (systemAbilityId != DISPLAY_MANAGER_SERVICE_SA_ID) {
        FI_HILOGE("systemAbilityId is not DISPLAY_MANAGER_SERVICE_SA_ID");
        return;
    }
    CHKPV(context_);
    displayChangeEventListener_ = sptr<DisplayChangeEventListener>::MakeSptr(context_);
    CHKPV(displayChangeEventListener_);
    Rosen::DisplayManager::GetInstance().RegisterDisplayListener(displayChangeEventListener_);
#ifdef OHOS_ENABLE_PULLTHROW
    displayChangeEventListener_->SetFoldPC(
        SYS_PRODUCT_TYPE == PRODUCT_NAME_DEFINITION_PARSER.GetProductName("DEVICE_TYPE_FOLD_PC"));
    if (displayChangeEventListener_->IsFoldPC()) {
        FI_HILOGI("device foldPC check ok");
        if (!context_->GetDragManager().RegisterPullThrowListener()) {
            FI_HILOGE("RegisterPullThrowListener fail");
            return;
        }
    }
#endif // OHOS_ENABLE_PULLTHROW
    if (!displayChangeEventListener_->IsRotateDragScreen()) {
        displayChangeEventListener_->GetAllScreenAngles();
    }
}

void DisplayAbilityStatusChange::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    FI_HILOGI("systemAbilityId:%{public}d", systemAbilityId);
}

AppStateObserverStatusChange::AppStateObserverStatusChange(IContext *context)
    : context_(context)
{}

void AppStateObserverStatusChange::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    FI_HILOGI("systemAbilityId:%{public}d", systemAbilityId);
    if (systemAbilityId != APP_MGR_SERVICE_ID) {
        FI_HILOGE("systemAbilityId is not APP_MGR_SERVICE_ID");
        return;
    }
    CHKPV(context_);
    context_->GetSocketSessionManager().RegisterApplicationState();
}

void AppStateObserverStatusChange::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    FI_HILOGI("systemAbilityId:%{public}d", systemAbilityId);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS