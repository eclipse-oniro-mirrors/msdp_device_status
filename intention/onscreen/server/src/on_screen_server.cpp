/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "on_screen_server.h"

#include <algorithm>
#include <dlfcn.h>
#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "devicestatus_define.h"
#include "parameters.h"
#include "tokenid_kit.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
namespace {
const char *LIB_ON_SCREEN_ALGO_PATH = "/system/lib64/libon_screen.z.so";
const char *PERMISSION_GET_PAGE_CONTENT = "ohos.permission.GET_SCREEN_CONTENT";
const char *PERMISSION_SEND_CONTROL_EVENT = "ohos.permission.SIMULATE_USER_INPUT";
const char *DEVICE_TYPE_PARA_NAME = "const.product.devicetype";
const std::vector<std::string> SUPPORT_DEVICE_TYPE = { "phone", "tablet" };
constexpr int32_t RET_NO_SUPPORT = 801;
constexpr int32_t RET_NO_PERMISSION = 201;
constexpr int32_t RET_NO_SYSTEM_CALLING = 202;
}

OnScreenAlgorithmHandle::~OnScreenAlgorithmHandle()
{
    Clear();
}

void OnScreenAlgorithmHandle::Clear()
{
    handle = nullptr;
    pAlgorithm = nullptr;
    create = nullptr;
    destroy = nullptr;
}

OnScreenServer::~OnScreenServer()
{
    UnloadAlgoLib();
}

int32_t OnScreenServer::GetPageContent(const CallingContext &context, const ContentOption &option,
    PageContent &pageContent)
{
    std::lock_guard lockGrd(mtx_);
    int32_t ret = RET_OK;
    if (!CheckDeviceType()) {
        FI_HILOGE("device type is not support");
        return RET_NO_SUPPORT;
    }
    if (!CheckPermission(context, PERMISSION_GET_PAGE_CONTENT)) {
        FI_HILOGE("checkpermission failed, premission = %{public}s", PERMISSION_GET_PAGE_CONTENT);
        return RET_NO_PERMISSION;
    }
    if (!IsSystemCalling(context)) {
        FI_HILOGE("calling is not system calling");
        return RET_NO_SYSTEM_CALLING;
    }
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    OnScreenCallingContext onScreenContext {
        .fullTokenId = context.fullTokenId,
        .tokenId = context.tokenId,
        .uid = context.uid,
        .pid = context.pid,
    };
    FI_HILOGI("get page content invoke algo lib");
    ret = handle_.pAlgorithm->GetPageContent(onScreenContext, option, pageContent);
    if (ret != RET_OK) {
        FI_HILOGE("failed to get page content, err=%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::SendControlEvent(const CallingContext &context, const ControlEvent &event)
{
    std::lock_guard lockGrd(mtx_);
    if (!CheckDeviceType()) {
        FI_HILOGE("device type is not support");
        return RET_NO_SUPPORT;
    }
    int32_t ret = RET_OK;
    if (!CheckPermission(context, PERMISSION_SEND_CONTROL_EVENT)) {
        FI_HILOGE("checkpermission failed, premission = %{public}s", PERMISSION_SEND_CONTROL_EVENT);
        return RET_NO_PERMISSION;
    }
    if (!IsSystemCalling(context)) {
        FI_HILOGE("calling is not system calling");
        return RET_NO_SYSTEM_CALLING;
    }
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    OnScreenCallingContext onScreenContext {
        .fullTokenId = context.fullTokenId,
        .tokenId = context.tokenId,
        .uid = context.uid,
        .pid = context.pid,
    };
    FI_HILOGI("send control event invoke algo lib");
    ret = handle_.pAlgorithm->SendControlEvent(onScreenContext, event);
    if (ret != RET_OK) {
        FI_HILOGE("failed to send control event, err=%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    std::lock_guard lockGrd(mtx_);
    int32_t ret = RET_OK;
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    FI_HILOGI("dump invoke algo lib");
    ret = handle_.pAlgorithm->Dump(fd, args);
    if (ret != RET_OK) {
        FI_HILOGE("failed to dump, err=%{public}d", ret);
    }
    return ret;
}

int32_t OnScreenServer::RegisterScreenEventCallback(const CallingContext& context,
    int32_t windowId, const std::string& event, const sptr<IRemoteOnScreenCallback>& callback)
{
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    FI_HILOGI("RegisterScreenEventCallback algo lib");
    auto ret = handle_.pAlgorithm->RegisterScreenEventCallback(windowId, event, callback);
    if (ret != RET_OK) {
        FI_HILOGE("failed to RegisterScreenEventCallback, err = %{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::UnregisterScreenEventCallback(const CallingContext& context,
    int32_t windowId, const std::string& event, const sptr<IRemoteOnScreenCallback>& callback)
{
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    FI_HILOGI("RegisterScreenEventCallback algo lib");
    auto ret = handle_.pAlgorithm->UnregisterScreenEventCallback(windowId, event, callback);
    if (ret != RET_OK) {
        FI_HILOGE("failed to UnregisterScreenEventCallback, err = %{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::IsParallelFeatureEnabled(const CallingContext& context,
    int32_t windowId, int32_t& outStatus)
{
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }

    auto ret = handle_.pAlgorithm->IsParallelFeatureEnabled(windowId, outStatus);
    if (ret != RET_OK) {
        FI_HILOGE("failed to check screen change access, err=%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::ConnectAlgoLib()
{
    return handle_.pAlgorithm == nullptr ? LoadAlgoLib() : RET_OK;
}

int32_t OnScreenServer::LoadAlgoLib()
{
    char libRealPath[PATH_MAX] = { 0 };
    if (realpath(LIB_ON_SCREEN_ALGO_PATH, libRealPath) == nullptr) {
        FI_HILOGE("get absolute path failed, ret = %{public}d", errno);
        return RET_ERR;
    }
    handle_.handle = dlopen(libRealPath, RTLD_LAZY);
    if (handle_.handle == nullptr) {
        FI_HILOGE("dlopen failed, err:%{public}sn", dlerror());
        return RET_ERR;
    }
    handle_.create = reinterpret_cast<IOnScreenAlgorithm*(*)()>(dlsym(handle_.handle, "Create"));
    handle_.destroy = reinterpret_cast<void(*)(const IOnScreenAlgorithm*)>(dlsym(handle_.handle, "Destroy"));
    if (handle_.create == nullptr || handle_.destroy == nullptr) {
        FI_HILOGE("create is null or destoy is null");
        return RET_ERR;
    }
    if (handle_.pAlgorithm == nullptr) {
        FI_HILOGI("get on screen algo object");
        handle_.pAlgorithm = handle_.create();
        if (handle_.pAlgorithm == nullptr) {
            FI_HILOGE("create on screen algo object failed");
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t OnScreenServer::UnloadAlgoLib()
{
    FI_HILOGE("unload exit");
    if (handle_.pAlgorithm != nullptr && handle_.destroy != nullptr) {
        handle_.destroy(handle_.pAlgorithm);
        handle_.pAlgorithm = nullptr;
    }
    handle_.Clear();
    return RET_OK;
}

bool OnScreenServer::CheckPermission(const CallingContext &context, const std::string &permission)
{
    auto type = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    FI_HILOGD("called tokenType is %{public}d", type);
    if (type == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        FI_HILOGD("called tokenType is shell, verify succ");
    }
    return Security::AccessToken::AccessTokenKit::VerifyAccessToken(context.tokenId, permission) == RET_OK;
}

bool OnScreenServer::IsSystemCalling(const CallingContext &context)
{
    if (IsSystemServiceCalling(context)) {
        return true;
    }
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(context.fullTokenId);
}

bool OnScreenServer::IsSystemServiceCalling(const CallingContext &context)
{
    auto flag = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    if ((flag == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) ||
        (flag == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL)) {
        FI_HILOGI("system service calling, flag:%{public}u", flag);
        return true;
    }
    return false;
}

bool OnScreenServer::CheckDeviceType()
{
    std::string deviceType = OHOS::system::GetParameter(DEVICE_TYPE_PARA_NAME, "");
    return std::find(SUPPORT_DEVICE_TYPE.begin(), SUPPORT_DEVICE_TYPE.end(), deviceType) != SUPPORT_DEVICE_TYPE.end();
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS