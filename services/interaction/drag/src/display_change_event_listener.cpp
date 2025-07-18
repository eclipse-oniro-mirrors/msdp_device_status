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
const std::string DEVICE_TYPE_HPR {"HPR"};
const std::string HPR_PRODUCT_TYPE = OHOS::system::GetParameter("const.build.product", "HYM");
} // namespace

DisplayChangeEventListener::DisplayChangeEventListener(IContext *context)
    : context_(context)
{
}

void DisplayChangeEventListener::OnCreate(Rosen::DisplayId displayId)
{
    FI_HILOGI("display:%{public}" PRIu64"", displayId);
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(displayId);
    if (display == nullptr) {
        FI_HILOGW("Get display info failed, display:%{public}" PRIu64"", displayId);
        display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
        if (display == nullptr) {
            FI_HILOGE("Get display info failed, display is nullptr");
            return;
        }
    }
    Rosen::Rotation rotation = display->GetRotation();
    CHKPV(context_);
    context_->GetDragManager().SetRotation(displayId, rotation);
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
    if (Rosen::DisplayManager::GetInstance().IsFoldable()) {
        bool isScreenRotation = false;
        std::vector<std::string> foldRotatePolicys;
        GetRotatePolicy(isScreenRotation, foldRotatePolicys);
        if (foldRotatePolicys.size() < MAX_INDEX_LENGTH) {
            FI_HILOGE("foldRotatePolicys is invalid");
            return;
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
            if (lastRotation == Rosen::Rotation::ROTATION_0) {
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
    }
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(displayId);
    if (display == nullptr) {
        FI_HILOGW("Get display info failed, display:%{public}" PRIu64"", displayId);
        display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
        if (display == nullptr) {
            FI_HILOGE("Get display info failed, display is nullptr");
            return;
        }
    }
    Rosen::Rotation currentRotation = display->GetRotation();
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
        CHKPV(context_);
        context_->GetDragManager().SetRotation(displayId, currentRotation);
        return;
    }
    RotateDragWindow(displayId, currentRotation);
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
    isHPR_ = HPR_PRODUCT_TYPE == DEVICE_TYPE_HPR;
    if (isHPR_) {
        FI_HILOGI("device hpr checkok");
        if (!context_->GetDragManager().RegisterPullThrowListener()) {
            FI_HILOGE("RegisterPullThrowListener fail");
            return;
        }
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