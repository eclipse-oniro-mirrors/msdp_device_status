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
#include <vector>

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
namespace {
const char *LIB_ON_SCREEN_ALGO_PATH = "/system/lib64/libon_screen.z.so";
const char *PERMISSION_GET_PAGE_CONTENT = "ohos.permission.ON_SCREEN_GET_CONTENT";
const char *PERMISSION_SEND_CONTROL_EVENT = "ohos.permission.ON_SCREEN_CONTROL";
constexpr int32_t RET_NO_SUPPORT = 801;
constexpr int32_t RET_NO_PERMISSION = 201;
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

int32_t OnScreenServer::GetPageContent(CallingContext &context, const ContentOption &option, PageContent &pageContent)
{
    int32_t ret = RET_OK;
    if (CheckPermission(context, PERMISSION_GET_PAGE_CONTENT) != RET_OK) {
        return RET_NO_PERMISSION;
    }
    if (handle_.pAlgorithm == nullptr) {
        ret = LoadAlgoLib();
        if (ret != RET_OK) {
            return RET_NO_SUPPORT;
        }
    }
    if (handle_.pAlgorithm == nullptr) {
        return RET_NO_SUPPORT;
    }
    ret = handle_.pAlgorithm->GetPageContent(option, pageContent);
    if (ret != RET_OK) {
        FI_HILOGE("failed to get page content, err=%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::SendControlEvent(CallingContext &context, const ControlEvent &event)
{
    int32_t ret = RET_OK;
    if (CheckPermission(context, PERMISSION_SEND_CONTROL_EVENT) != RET_OK) {
        return RET_NO_PERMISSION;
    }
    if (handle_.pAlgorithm == nullptr) {
        ret = LoadAlgoLib();
        if (ret != RET_OK) {
            return RET_NO_SUPPORT;
        }
    }
    if (handle_.pAlgorithm == nullptr) {
        return RET_NO_SUPPORT;
    }
    ret = handle_.pAlgorithm->SendControlEvent(event);
    if (ret != RET_OK) {
        FI_HILOGE("failed to send control event, err=%{public}d", ret);
        return ret;
    }
    return RET_OK;
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
        FI_HILOGI("get object");
        handle_.pAlgorithm = handle_.create();
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

int32_t OnScreenServer::CheckPermission(CallingContext &context, const std::string &permission)
{
    return RET_OK;
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS