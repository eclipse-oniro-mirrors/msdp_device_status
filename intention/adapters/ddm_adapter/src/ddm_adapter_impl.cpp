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

#include "ddm_adapter_impl.h"

#include <algorithm>

#include "devicestatus_define.h"
#include "i_dsoftbus_adapter.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "DDMAdapterImpl"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
#define D_DEV_MGR   DistributedHardware::DeviceManager::GetInstance()

DDMAdapterImpl::~DDMAdapterImpl()
{
    Disable();
}

int32_t DDMAdapterImpl::Enable()
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    std::string pkgName(FI_PKG_NAME);
    std::string extra;
    initCb_ = std::make_shared<DmInitCb>();

    int32_t ret = D_DEV_MGR.InitDeviceManager(pkgName, initCb_);
    if (ret != 0) {
        FI_HILOGE("DM::InitDeviceManager fail");
        goto INIT_FAIL;
    }
    boardStateCb_ = std::make_shared<DmBoardStateCb>(shared_from_this());

    ret = D_DEV_MGR.RegisterDevStateCallback(pkgName, extra, boardStateCb_);
    if (ret != 0) {
        FI_HILOGE("DM::RegisterDevStateCallback fail");
        goto REG_FAIL;
    }
    return RET_OK;

REG_FAIL:
    ret = D_DEV_MGR.UnInitDeviceManager(pkgName);
    if (ret != 0) {
        FI_HILOGE("DM::UnInitDeviceManager fail");
    }
    boardStateCb_.reset();

INIT_FAIL:
    initCb_.reset();
    return RET_ERR;
}

void DDMAdapterImpl::Disable()
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    std::string pkgName(FI_PKG_NAME);

    if (boardStateCb_ != nullptr) {
        boardStateCb_.reset();
        int32_t ret = D_DEV_MGR.UnRegisterDevStateCallback(pkgName);
        if (ret != 0) {
            FI_HILOGE("DM::UnRegisterDevStateCallback fail");
        }
    }
    if (initCb_ != nullptr) {
        initCb_.reset();
        int32_t ret = D_DEV_MGR.UnInitDeviceManager(pkgName);
        if (ret != 0) {
            FI_HILOGE("DM::UnInitDeviceManager fail");
        }
    }
}

void DDMAdapterImpl::AddBoardObserver(std::shared_ptr<IBoardObserver> observer)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    CHKPV(observer);
    observers_.erase(Observer());
    observers_.emplace(observer);
}

void DDMAdapterImpl::RemoveBoardObserver(std::shared_ptr<IBoardObserver> observer)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    CHKPV(observer);
    observers_.erase(Observer());
    if (auto iter = observers_.find(Observer(observer)); iter != observers_.end()) {
        observers_.erase(iter);
    }
}

int32_t DDMAdapterImpl::GetTrustedDeviceList(std::vector<DistributedHardware::DmDeviceInfo> &deviceList)
{
    CALL_INFO_TRACE;
    deviceList.clear();
    if (int32_t ret = D_DEV_MGR.GetTrustedDeviceList(FI_PKG_NAME, "", deviceList); ret != RET_OK) {
        FI_HILOGE("GetTrustedDeviceList failed, ret %{public}d.", ret);
        return RET_ERR;
    }
    return RET_OK;
}

bool DDMAdapterImpl::CheckSameAccountToLocal(const std::string &networkId, const int32_t uid)
{
    CALL_INFO_TRACE;
    int32_t appUserId = -1;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, appUserId);
    FI_HILOGI("GetOsAccountLocalIdFromUid uid:%{public}d, localId:%{public}d", uid, appUserId);
    bool isForegroundUser = false;
    int32_t res = OHOS::AccountSA::OsAccountManager::IsOsAccountForeground(appUserId, isForegroundUser);
    if (res != ERR_OK) {
        FI_HILOGI("app userId %{public}d is not Foreground, ret:%{public}d", appUserId, res);
        return false;
    }
    if (!isForegroundUser) {
        FI_HILOGI("app userId is not Foreground");
        return false;
    }
    isForegroundUser = false;
    std::vector<AccountSA::ForegroundOsAccount> accounts;
    ErrCode errCode = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccounts(accounts);
    if (errCode != ERR_OK || accounts.empty()) {
        FI_HILOGE("GetForegroundOsAccounts fail, ret : %{public}d", errCode);
        return false;
    }
    for (auto account : accounts) {
        if (account.localId == appUserId) {
            isForegroundUser = true;
            break;
        }
    }
    if (!isForegroundUser) {
        FI_HILOGI("app userId is not Foreground");
        return false;
    }
    return CheckIsSameAccount(networkId);
}

bool DDMAdapterImpl::CheckIsSameAccount(const std::string &networkId)
{
    CALL_INFO_TRACE;
    std::vector<int32_t> ids;
    ErrCode ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != ERR_OK || ids.empty()) {
        FI_HILOGE("Get userId from active Os AccountIds fail, ret : %{public}d", ret);
        return false;
    }
    OHOS::AccountSA::OhosAccountInfo osAccountInfo;
    ret = OHOS::AccountSA::OhosAccountKits::GetInstance().GetOhosAccountInfo(osAccountInfo);
    if (ret != 0 || osAccountInfo.uid_ == "") {
        FI_HILOGE("Get accountId from Ohos account info fail, ret: %{public}d.", ret);
        return false;
    }
    DistributedHardware::DmAccessCaller Caller = {
        .accountId = osAccountInfo.uid_,
        .networkId = IDSoftbusAdapter::GetLocalNetworkId(),
        .userId = ids[0],
        .tokenId = IPCSkeleton::GetCallingTokenID(),
    };
    DistributedHardware::DmAccessCallee Callee = {
        .networkId = networkId,
        .peerId = "",
    };
    if (D_DEV_MGR.CheckIsSameAccount(Caller, Callee)) {
            return true;
        }
    FI_HILOGI("check same account fail, will try check access Group by hichain");
    return false;
}

void DDMAdapterImpl::OnBoardOnline(const std::string &networkId)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    FI_HILOGI("Board \'%{public}s\' is online", Utility::Anonymize(networkId).c_str());
    std::for_each(observers_.cbegin(), observers_.cend(),
        [&networkId](const auto &item) {
            if (auto observer = item.Lock(); observer != nullptr) {
                observer->OnBoardOnline(networkId);
            }
        });
}

void DDMAdapterImpl::OnBoardOffline(const std::string &networkId)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    FI_HILOGI("Board \'%{public}s\' is offline", Utility::Anonymize(networkId).c_str());
    std::for_each(observers_.cbegin(), observers_.cend(),
        [&networkId](const auto &item) {
            if (auto observer = item.Lock(); observer != nullptr) {
                observer->OnBoardOffline(networkId);
            }
        });
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
