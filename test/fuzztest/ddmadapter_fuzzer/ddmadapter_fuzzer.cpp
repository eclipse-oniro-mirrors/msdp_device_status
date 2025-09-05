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

#include "ddmadapter_fuzzer.h"

#include "accesstoken_kit.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "nativetoken_kit.h"
#include "singleton.h"
#include "token_setproc.h"

#include "ddm_adapter.h"
#include "devicestatus_define.h"
#include "socket_session_manager.h"

#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "DDMAdapterFuzzTest"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
uint64_t g_tokenID { 0 };
const std::string SYSTEM_CORE { "system_core" };
const char* g_cores[] = { "ohos.permission.INPUT_MONITORING" };
constexpr size_t STR_LEN = 255;

class BoardObserverTest final : public IBoardObserver {
public:
    explicit BoardObserverTest() {}
    ~BoardObserverTest() = default;
    DISALLOW_COPY_AND_MOVE(BoardObserverTest);

    void OnBoardOnline(const std::string &networkId) override
    {
        FI_HILOGD("\'%{public}s\' is online", networkId.c_str());
    }

    void OnBoardOffline(const std::string &networkId) override
    {
        FI_HILOGD("\'%{public}s\' is offline", networkId.c_str());
    }
};

void SetPermission(const std::string &level, const char** perms, size_t permAmount)
{
    CALL_DEBUG_ENTER;
    if (perms == nullptr || permAmount == 0) {
        FI_HILOGE("The perms is empty");
        return;
    }

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permAmount,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "DDMAdapterTest",
        .aplStr = level.c_str(),
    };
    g_tokenID = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(g_tokenID);
    OHOS::Security::AccessToken::AccessTokenKit::AccessTokenKit::ReloadNativeTokenInfo();
}

void RemovePermission()
{
    CALL_DEBUG_ENTER;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenID);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to remove permission");
        return;
    }
}

bool DDMAdapterFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return false;
    }
    FuzzedDataProvider provider(data, size);
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    int32_t srcUserId = provider.ConsumeIntegral<int32_t>();
    std::string networkId =  provider.ConsumeRandomLengthString(STR_LEN);
    std::string srcNetworkId =  provider.ConsumeRandomLengthString(STR_LEN);
    std::string srcAccountId =  provider.ConsumeRandomLengthString(STR_LEN);
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DDMAdapter ddmAdapter;
    ddmAdapter.Enable();
    auto boardObserver = std::make_shared<BoardObserverTest>();
    ddmAdapter.AddBoardObserver(boardObserver);
    ddmAdapter.CheckSameAccountToLocal(networkId);
    ddmAdapter.CheckSameAccountToLocalWithUid(networkId, uid);
    ddmAdapter.CheckSinkIsSameAccount(srcNetworkId, srcUserId, srcAccountId);
    ddmAdapter.CheckSrcIsSameAccount(networkId);
    ddmAdapter.RemoveBoardObserver(boardObserver);
    ddmAdapter.Disable();
    RemovePermission();
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    } 
    OHOS::Msdp::DeviceStatus::DDMAdapterFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS