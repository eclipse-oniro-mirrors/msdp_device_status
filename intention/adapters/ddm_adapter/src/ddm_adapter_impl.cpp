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

bool DDMAdapterImpl::CheckSameAccountToLocal(const std::string &networkId)
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

bool DDMAdapterImpl::CheckSameAccountToLocalWithUid(const std::string &networkId, const int32_t uid)
{
    CALL_INFO_TRACE;
    int32_t appUserId = -1;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, appUserId);
    FI_HILOGI("GetOsAccountLocalIdFromUid uid:%{private}d, localId:%{private}d", uid, appUserId);
    bool isForegroundUser = false;
    int32_t res = OHOS::AccountSA::OsAccountManager::IsOsAccountForeground(appUserId, isForegroundUser);
    if (res != ERR_OK) {
        FI_HILOGE("app userId %{private}d is not Foreground, ret:%{public}d", appUserId, res);
        return false;
    }
    if (!isForegroundUser) {
        FI_HILOGW("app userId is not Foreground");
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
        FI_HILOGW("app userId is not Foreground");
        return false;
    }
    return CheckSameAccountToLocal(networkId);
}

bool DDMAdapterImpl::CheckSrcIsSameAccount(const std::string &sinkNetworkId)
{
    CALL_INFO_TRACE;
    DistributedHardware::DmAccessCaller caller;
    if (!GetDmAccessCallerSrc(caller)) {
        FI_HILOGE("GetDmAccessCallerSrc failed");
        return false;
    }
    DistributedHardware::DmAccessCallee callee;
    if (!GetDmAccessCalleeSrc(callee, sinkNetworkId)) {
        FI_HILOGE("GetDmAccessCalleeSrc failed");
        return false;
    }
    if (!D_DEV_MGR.CheckSrcIsSameAccount(caller, callee)) {
        FI_HILOGE("CheckSrcIsSameAccount failed");
        return false;
    }
    return true;
}

bool DDMAdapterImpl::CheckSinkIsSameAccount(const std::string &srcNetworkId, int32_t srcUserId,
    const std::string &srcAccountId)
{
    CALL_INFO_TRACE;
    DistributedHardware::DmAccessCaller caller;
    if (!GetDmAccessCallerSink(caller, srcNetworkId, srcUserId, srcAccountId)) {
        FI_HILOGE("GetDmAccessCallerSrc failed");
        return false;
    }
    DistributedHardware::DmAccessCallee callee;
    if (!GetDmAccessCalleeSink(callee)) {
        FI_HILOGE("GetDmAccessCalleeSink failed");
        return false;
    }
    if (!D_DEV_MGR.CheckSinkIsSameAccount(caller, callee)) {
        FI_HILOGE("CheckSinkIsSameAccount failed");
        return false;
    }
    return true;
}

bool DDMAdapterImpl::GetDmAccessCallerSrc(DistributedHardware::DmAccessCaller &caller)
{
    std::vector<int32_t> ids;
    if (int32_t ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids); ret != ERR_OK || ids.empty()) {
        FI_HILOGE("QueryActiveOsAccountIds failed, ret:%{public}d", ret);
        return false;
    }
    OHOS::AccountSA::OhosAccountInfo osAccountInfo;
    if (int32_t ret = OHOS::AccountSA::OhosAccountKits::GetInstance().GetOhosAccountInfo(osAccountInfo);
        ret != RET_OK || osAccountInfo.uid_ == "") {
        FI_HILOGE("GetOhosAccountInfo failed, ret:%{public}d", ret);
        return false;
    }
    caller = {
        .accountId = osAccountInfo.uid_,
        .networkId = IDSoftbusAdapter::GetLocalNetworkId(),
        .userId = ids[0],
        .tokenId = IPCSkeleton::GetCallingTokenID(),
    };
    SetUserId(caller.userId);
    SetAccountId(caller.accountId);
    return true;
}

bool DDMAdapterImpl::GetDmAccessCalleeSrc(DistributedHardware::DmAccessCallee &callee, const std::string &sinkNetworkId)
{
    callee.networkId = sinkNetworkId;
    return true;
}

bool DDMAdapterImpl::GetDmAccessCallerSink(DistributedHardware::DmAccessCaller &caller, const std::string &srcNetworkId,
    int32_t srcUserId, const std::string &srcAccountId)
{
    caller.networkId = srcNetworkId;
    caller.userId = srcUserId;
    caller.accountId = srcAccountId;
    return true;
}

bool DDMAdapterImpl::GetDmAccessCalleeSink(DistributedHardware::DmAccessCallee &callee)
{
    std::vector<int32_t> ids;
    if (int32_t ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids); ret != RET_OK || ids.empty()) {
        FI_HILOGE("QueryActiveOsAccountIds failed, ret:%{public}d", ret);
        return false;
    }
    OHOS::AccountSA::OhosAccountInfo osAccountInfo;
    if (int32_t ret = OHOS::AccountSA::OhosAccountKits::GetInstance().GetOhosAccountInfo(osAccountInfo);
        ret != RET_OK || osAccountInfo.uid_ == "") {
        FI_HILOGE("GetOhosAccountInfo failed, ret:%{public}d", ret);
        return false;
    }
    callee = {
        .accountId = osAccountInfo.uid_,
        .networkId = IDSoftbusAdapter::GetLocalNetworkId(),
        .userId = ids[0],
    };
    return true;
}

void DDMAdapterImpl::SetUserId(int32_t userId)
{
    userId_ = userId;
}

void DDMAdapterImpl::SetAccountId(const std::string &accountId)
{
    accountId_ = accountId;
}

int32_t DDMAdapterImpl::GetUserId()
{
    return userId_;
}

std::string DDMAdapterImpl::GetAccountId()
{
    return accountId_;
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
