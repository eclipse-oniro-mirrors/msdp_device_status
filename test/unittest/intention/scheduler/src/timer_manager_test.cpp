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

#include "timer_manager_test.h"

#include <unistd.h>
#include "ddm_adapter.h"

#undef LOG_TAG
#define LOG_TAG "TimerManagerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

using namespace testing::ext;
namespace {
struct device_status_epoll_event {
    int32_t fd { -1 };
    EpollEventType event_type { EPOLL_EVENT_BEGIN };
};

ContextService *g_instance = nullptr;
constexpr int32_t TIME_WAIT_FOR_OP_MS { 100 };
constexpr int32_t DEFAULT_DELAY_TIME { 40 };
constexpr int32_t RETRY_TIME { 2 };
constexpr int32_t DEFAULT_TIMEOUT { 30 };
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t DEFAULT_UNLOAD_COOLING_TIME_MS { 600 };
constexpr int32_t ERROR_TIMERID { -1 };
constexpr size_t ERROR_REPEAT_COUNT { 128 };
constexpr int32_t ERROR_INTERVAL_MS { 1000000 };
} // namespace

ContextService::ContextService()
{
    ddm_ = std::make_unique<DDMAdapter>();
    FI_HILOGI("OHOS_BUILD_ENABLE_INTENTION_FRAMEWORK is on");
    OnStart();
}

ContextService::~ContextService()
{
    OnStop();
}

IDelegateTasks& ContextService::GetDelegateTasks()
{
    return delegateTasks_;
}

IDeviceManager& ContextService::GetDeviceManager()
{
    return devMgr_;
}

ITimerManager& ContextService::GetTimerManager()
{
    return timerMgr_;
}

IDragManager& ContextService::GetDragManager()
{
    return dragMgr_;
}

__attribute__((no_sanitize("cfi"))) ContextService* ContextService::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        ContextService *cooContext = new (std::nothrow) ContextService();
        CHKPL(cooContext);
        g_instance = cooContext;
    });
    return g_instance;
}

ISocketSessionManager& ContextService::GetSocketSessionManager()
{
    return socketSessionMgr_;
}

IDDMAdapter& ContextService::GetDDM()
{
    return *ddm_;
}

IPluginManager& ContextService::GetPluginManager()
{
    return *pluginMgr_;
}

IInputAdapter& ContextService::GetInput()
{
    return *input_;
}

IDSoftbusAdapter& ContextService::GetDSoftbus()
{
    return *dsoftbusAda_;
}

bool ContextService::Init()
{
    CALL_DEBUG_ENTER;
    if (EpollCreate() != RET_OK) {
        FI_HILOGE("Create epoll failed");
        return false;
    }
    if (InitDelegateTasks() != RET_OK) {
        FI_HILOGE("Delegate tasks init failed");
        goto INIT_FAIL;
    }

    if (InitTimerMgr() != RET_OK) {
        FI_HILOGE("TimerMgr init failed");
        goto INIT_FAIL;
    }

    return true;

INIT_FAIL:
    EpollClose();
    return false;
}

__attribute__((no_sanitize("cfi"))) int32_t ContextService::InitTimerMgr()
{
    CALL_DEBUG_ENTER;
    int32_t ret = timerMgr_.Init(this);
    if (ret != RET_OK) {
        FI_HILOGE("TimerMgr init failed");
        return ret;
    }

    ret = AddEpoll(EPOLL_EVENT_TIMER, timerMgr_.GetTimerFd());
    if (ret != RET_OK) {
        FI_HILOGE("AddEpoll for timer failed");
    }
    return ret;
}

int32_t ContextService::InitDelegateTasks()
{
    CALL_DEBUG_ENTER;
    if (!delegateTasks_.Init()) {
        FI_HILOGE("The delegate task init failed");
        return RET_ERR;
    }
    int32_t ret = AddEpoll(EPOLL_EVENT_ETASK, delegateTasks_.GetReadFd());
    if (ret != RET_OK) {
        FI_HILOGE("AddEpoll error ret:%{public}d", ret);
    }
    FI_HILOGI("AddEpoll, epollfd:%{public}d, fd:%{public}d", epollFd_, delegateTasks_.GetReadFd());
    return ret;
}

int32_t ContextService::EpollCreate()
{
    CALL_DEBUG_ENTER;
    epollFd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epollFd_ < 0) {
        FI_HILOGE("epoll_create1 failed:%{public}s", ::strerror(errno));
        return RET_ERR;
    }
    return RET_OK;
}

int32_t ContextService::AddEpoll(EpollEventType type, int32_t fd)
{
    CALL_DEBUG_ENTER;
    if (!(type >= EPOLL_EVENT_BEGIN && type < EPOLL_EVENT_END)) {
        FI_HILOGE("Invalid type:%{public}d", type);
        return RET_ERR;
    }
    if (fd < 0) {
        FI_HILOGE("Invalid fd:%{public}d", fd);
        return RET_ERR;
    }
    auto eventData = static_cast<device_status_epoll_event*>(malloc(sizeof(device_status_epoll_event)));
    if (!eventData) {
        FI_HILOGE("Malloc failed");
        return RET_ERR;
    }
    eventData->fd = fd;
    eventData->event_type = type;
    FI_HILOGD("EventData:[fd:%{public}d, type:%{public}d]", eventData->fd, eventData->event_type);

    struct epoll_event ev {};
    ev.events = EPOLLIN;
    ev.data.ptr = eventData;
    if (EpollCtl(fd, EPOLL_CTL_ADD, ev) != RET_OK) {
        free(eventData);
        eventData = nullptr;
        ev.data.ptr = nullptr;
        FI_HILOGE("EpollCtl failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t ContextService::DelEpoll(EpollEventType type, int32_t fd)
{
    CALL_DEBUG_ENTER;
    if (!(type >= EPOLL_EVENT_BEGIN && type < EPOLL_EVENT_END)) {
        FI_HILOGE("Invalid type:%{public}d", type);
        return RET_ERR;
    }
    if (fd < 0) {
        FI_HILOGE("Invalid fd:%{public}d", fd);
        return RET_ERR;
    }
    struct epoll_event ev {};
    if (EpollCtl(fd, EPOLL_CTL_DEL, ev) != RET_OK) {
        FI_HILOGE("DelEpoll failed");
        return RET_ERR;
    }
    return RET_OK;
}

void ContextService::EpollClose()
{
    CALL_DEBUG_ENTER;
    if (epollFd_ >= 0) {
        if (close(epollFd_) < 0) {
            FI_HILOGE("Close epoll fd failed, error:%{public}s, epollFd_:%{public}d", strerror(errno), epollFd_);
        }
        epollFd_ = -1;
    }
}

int32_t ContextService::EpollCtl(int32_t fd, int32_t op, struct epoll_event &event)
{
    CALL_DEBUG_ENTER;
    if (fd < 0) {
        FI_HILOGE("Invalid fd:%{public}d", fd);
        return RET_ERR;
    }
    if (epollFd_ < 0) {
        FI_HILOGE("Invalid epollFd:%{public}d", epollFd_);
        return RET_ERR;
    }
    if (::epoll_ctl(epollFd_, op, fd, &event) != 0) {
        FI_HILOGE("epoll_ctl(%{public}d,%{public}d,%{public}d) failed:%{public}s", epollFd_, op, fd, ::strerror(errno));
        return RET_ERR;
    }
    return RET_OK;
}

int32_t ContextService::EpollWait(int32_t maxevents, int32_t timeout, struct epoll_event &events)
{
    if (epollFd_ < 0) {
        FI_HILOGE("Invalid epollFd:%{public}d", epollFd_);
        return RET_ERR;
    }
    return epoll_wait(epollFd_, &events, maxevents, timeout);
}

void ContextService::OnTimeout(const struct epoll_event &ev)
{
    CALL_DEBUG_ENTER;
    if ((ev.events & EPOLLIN) == EPOLLIN) {
        uint64_t expiration {};
        ssize_t ret = read(timerMgr_.GetTimerFd(), &expiration, sizeof(expiration));
        if (ret < 0) {
            FI_HILOGE("Read expiration failed:%{public}s", strerror(errno));
        }
        timerMgr_.ProcessTimers();
    } else if ((ev.events & (EPOLLHUP | EPOLLERR)) != 0) {
        FI_HILOGE("Epoll hangup:%{public}s", strerror(errno));
    }
}

void ContextService::OnStart()
{
    CALL_DEBUG_ENTER;
    uint64_t tid = GetThisThreadId();
    delegateTasks_.SetWorkerThreadId(tid);

    if (!Init()) {
        FI_HILOGE("On start call init failed");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    ready_ = true;

    worker_ = std::thread(std::bind(&ContextService::OnThread, this));
}

void ContextService::OnStop()
{
    CALL_DEBUG_ENTER;
    if (timerMgr_.GetTimerFd() >= 0) {
        if (close(timerMgr_.GetTimerFd()) < 0) {
            FI_HILOGE("Close timer fd failed, error:%{public}s", strerror(errno));
        }
    }
    if (!ready_) {
        FI_HILOGI("ready state is false");
        return;
    }
    ready_ = false;
    state_ = ServiceRunningState::STATE_EXIT;

    delegateTasks_.PostAsyncTask([]() -> int32_t {
        FI_HILOGD("No asynchronous operations");
        return RET_OK;
    });
    if (worker_.joinable()) {
        worker_.join();
    }
    EpollClose();
    FI_HILOGI("OnStop leave");
}

void ContextService::OnThread()
{
    CALL_DEBUG_ENTER;
    SetThreadName(std::string("os_ds_service"));
    uint64_t tid = GetThisThreadId();
    delegateTasks_.SetWorkerThreadId(tid);
    FI_HILOGD("Main worker thread start, tid:%{public}" PRId64 "", tid);

    while (state_ == ServiceRunningState::STATE_RUNNING) {
        struct epoll_event ev[MAX_EVENT_SIZE] {};
        int32_t count = EpollWait(MAX_EVENT_SIZE, -1, ev[0]);
        for (int32_t i = 0; i < count && state_ == ServiceRunningState::STATE_RUNNING; i++) {
            auto epollEvent = reinterpret_cast<device_status_epoll_event*>(ev[i].data.ptr);
            CHKPC(epollEvent);
            if (epollEvent->event_type == EPOLL_EVENT_TIMER) {
                OnTimeout(ev[i]);
            } else if (epollEvent->event_type == EPOLL_EVENT_ETASK) {
                OnDelegateTask(ev[i]);
            } else {
                FI_HILOGW("Unknown epoll event type:%{public}d", epollEvent->event_type);
            }
        }
    }
    FI_HILOGD("Main worker thread stop, tid:%{public}" PRId64 "", tid);
}

void ContextService::OnDelegateTask(const struct epoll_event &ev)
{
    if ((ev.events & EPOLLIN) == 0) {
        FI_HILOGW("Not epollin");
        return;
    }
    DelegateTasks::TaskData data {};
    ssize_t res = read(delegateTasks_.GetReadFd(), &data, sizeof(data));
    if (res == -1) {
        FI_HILOGW("Read failed erron:%{public}d", errno);
    }
    FI_HILOGD("RemoteRequest notify td:%{public}" PRId64 ", std:%{public}" PRId64 ""
        ", taskId:%{public}d", GetThisThreadId(), data.tid, data.taskId);
    delegateTasks_.ProcessTasks();
}

void TimerManagerTest::SetUpTestCase() {}

void TimerManagerTest::TearDownTestCase()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void TimerManagerTest::SetUp() {}

void TimerManagerTest::TearDown() {}

/**
 * @tc.name: TimerManagerTest_AddTimer001
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_DELAY_TIME, RETRY_TIME, [this, env]() {
        if (timerInfo_.times == 0) {
            FI_HILOGI("It will be retry to call callback next time");
            timerInfo_.times++;
            return;
        }
        env->GetTimerManager().RemoveTimer(timerInfo_.timerId);
    });
    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }

    timerInfo_.timerId = timerId_;
    timerInfo_.times = 0;

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS * RETRY_TIME));
    timerId_ = -1;
    timerInfo_.timerId = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimer002
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        FI_HILOGI("Timer %{public}d excute one times", timerId_);
        EXPECT_GE(timerId_, 0);
        env->GetTimerManager().RemoveTimer(timerId_);
    });
    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimer003
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            env->GetTimerManager().RemoveTimer(timerId_);
            EXPECT_GE(timerId_, 0);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }
    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimer004
 * @tc.desc: Test AddTimer, Invalid number of repetitions, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, ERROR_REPEAT_COUNT, [this, env]() {
        FI_HILOGI("Timer %{public}d excute onetimes", timerId_);
        env->GetTimerManager().RemoveTimer(timerId_);
        EXPECT_GE(timerId_, 0);
        timerId_ = -1;
    });
    if (timerId_ < 0) {
        FI_HILOGI("Invalid repeat-count value, then error, so success");
    } else {
        FI_HILOGE("Invalid repeat-count value, but okay, so failed");
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: TimerManagerTest_AddTimer005
 * @tc.desc: Test AddTimer, Invalid interval time, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    timerId_ = env->GetTimerManager().AddTimer(ERROR_INTERVAL_MS, REPEAT_ONCE, [this, env]() {
        FI_HILOGI("Timer %{public}d excute onetimes", timerId_);
        env->GetTimerManager().RemoveTimer(timerId_);
        EXPECT_GE(timerId_, 0);
    });
    if (timerId_ < 0) {
        FI_HILOGI("Invalid interval value, then error, so success");
    } else {
        FI_HILOGE("Invalid interval value, but okay, so failed");
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimer006
 * @tc.desc: Test AddTimer, Invalid callback function, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    timerId_ = env->GetTimerManager().AddTimer(ERROR_INTERVAL_MS, REPEAT_ONCE, nullptr);
    if (timerId_ < 0) {
        FI_HILOGI("Invalid callback value, then error, so success");
    } else {
        FI_HILOGE("Invalid callback value, but okay, so failed");
    }

    EXPECT_LT(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync001
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimerAsync(DEFAULT_DELAY_TIME, RETRY_TIME, [this, env]() {
        if (timerInfo_.times == 0) {
            FI_HILOGI("It will be retry to call callback next time");
            timerInfo_.times++;
        } else {
            env->GetTimerManager().RemoveTimerAsync(timerInfo_.timerId);
        }
    });
    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }

    timerInfo_.timerId = timerId_;
    timerInfo_.times = 0;

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS * RETRY_TIME));
    timerId_ = -1;
    timerInfo_.timerId = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync002
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimerAsync(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        FI_HILOGI("Timer %{public}d excute one times", timerId_);
        EXPECT_GE(timerId_, 0);
        env->GetTimerManager().RemoveTimerAsync(timerId_);
    });
    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync003
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimerAsync(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            env->GetTimerManager().RemoveTimerAsync(timerId_);
            EXPECT_GE(timerId_, 0);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync004
 * @tc.desc: Test AddTimer, Invalid number of repetitions, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimerAsync(DEFAULT_TIMEOUT, ERROR_REPEAT_COUNT, [this, env]() {
        FI_HILOGI("Timer %{public}d excute onetimes", timerId_);
        env->GetTimerManager().RemoveTimerAsync(timerId_);
        EXPECT_GE(timerId_, 0);
        timerId_ = -1;
    });

    if (timerId_ < 0) {
        FI_HILOGI("Invalid repeat-count value, then error, so success");
    } else {
        FI_HILOGE("Invalid repeat-count value, but okay, so failed");
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync005
 * @tc.desc: Test AddTimer, Invalid interval time, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimerAsync(ERROR_INTERVAL_MS, REPEAT_ONCE, [this, env]() {
        FI_HILOGI("Timer %{public}d excute onetimes", timerId_);
        env->GetTimerManager().RemoveTimerAsync(timerId_);
        EXPECT_GE(timerId_, 0);
    });
    if (timerId_ < 0) {
        FI_HILOGI("Invalid interval value, then error, so success");
    } else {
        FI_HILOGE("Invalid interval value, but okay, so failed");
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync006
 * @tc.desc: Test AddTimer, Invalid callback function, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    timerId_ = env->GetTimerManager().AddTimerAsync(ERROR_INTERVAL_MS, REPEAT_ONCE, nullptr);
    if (timerId_ < 0) {
        FI_HILOGI("Invalid callback value, then error, so success");
    } else {
        FI_HILOGE("Invalid callback value, but okay, so failed");
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_GetTimerFd001
 * @tc.desc: Test GetTimerFd, Obtaining initialized TimerFd, expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_GetTimerFd001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    TimerManager *timerMgr = static_cast<TimerManager *>(&env->GetTimerManager());
    int32_t timerFd = timerMgr->GetTimerFd();
    if (timerFd < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }
    EXPECT_GE(timerFd, 0);
}

/**
 * @tc.name: TimerManagerTest_GetTimerFd002
 * @tc.desc: Test GetTimerFd, Uninitialized, directly obtaining TimerFd, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_GetTimerFd002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timerMgr;
    int32_t timerFd = timerMgr.GetTimerFd();
    if (timerFd < 0) {
        FI_HILOGI("TimerFd is less than zero. the value is %{public}d", timerFd);
    } else {
        FI_HILOGE("Get TimerFd failed. the value is %{public}d", timerFd);
    }
    EXPECT_LT(timerFd, 0);
}

/**
 * @tc.name: TimerManagerTest_IsExist001
 * @tc.desc: Test IsExist, The newly added clock ID has been determined to exist and is expected to succeed
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_IsExist001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            env->GetTimerManager().RemoveTimer(timerId_);
            EXPECT_GE(timerId_, 0);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }
    EXPECT_GE(timerId_, 0);
    TimerManager *timerMgr = static_cast<TimerManager *>(&env->GetTimerManager());
    bool exist = timerMgr->IsExist(timerId_);
    if (exist) {
        FI_HILOGI("timerId_ is exist, so success");
    } else {
        FI_HILOGE("timerId_ is exist, but response unexist, so failed");
    }
    EXPECT_TRUE(exist);

    exist = timerMgr->IsExist(ERROR_TIMERID);
    if (!exist) {
        FI_HILOGI("The TimerFd(-1) does not exist, so success");
    } else {
        FI_HILOGE("The TimerFd(-1) does not exist, but response exist, so failed");
    }
    EXPECT_FALSE(exist);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_IsExist002
 * @tc.desc: Test IsExist, Invalid clock ID, determine if it does not exist
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_IsExist002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timerMgr;
    bool exist = timerMgr.IsExist(ERROR_TIMERID);

    if (!exist) {
        FI_HILOGI("The TimerFd(-1) is not exist, so success");
    } else {
        FI_HILOGE("The TimerFd(-1) is not exist, but response exist, so failed");
    }
    EXPECT_FALSE(exist);
}

/**
 * @tc.name: TimerManagerTest_ResetTimer001
 * @tc.desc: Test ResetTimer, After adding the clock and resetting it, expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ResetTimer001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_UNLOAD_COOLING_TIME_MS, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            env->GetTimerManager().RemoveTimer(timerId_);
            EXPECT_GE(timerId_, 0);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        TimerManager *timerMgr = static_cast<TimerManager *>(&env->GetTimerManager());
        int32_t ret = timerMgr->ResetTimer(timerId_);
        if (ret == RET_OK) {
            FI_HILOGI("Reset timer success");
        } else {
            FI_HILOGI("Reset timer %{public}d failed", timerId_);
        }
        EXPECT_EQ(ret, RET_OK);
    }
    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_UNLOAD_COOLING_TIME_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_ResetTimer002
 * @tc.desc: Test ResetTimer, Reset after deleting clock, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ResetTimer002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            env->GetTimerManager().RemoveTimer(timerId_);
            EXPECT_GE(timerId_, 0);
            TimerManager *timerMgr = static_cast<TimerManager *>(&env->GetTimerManager());
            int32_t ret = timerMgr->ResetTimer(timerId_);
            if (ret == RET_ERR) {
                FI_HILOGI("Reset unexist timerid sucess");
            } else {
                FI_HILOGE("Reset unexist timerid %{public}d failed", timerId_);
            }
            EXPECT_EQ(ret, RET_ERR);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("AddTimer success");
    }
    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_RemoveTimer001
 * @tc.desc: Test RemoveTimer, Repeated deletion of clock, first successful, others failed
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_RemoveTimer001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            int32_t ret = env->GetTimerManager().RemoveTimer(timerId_);
            ret = env->GetTimerManager().RemoveTimer(timerId_);
            if (ret == RET_ERR) {
                FI_HILOGI("Remove timer two times, then error, this case success");
            } else {
                FI_HILOGE("Remove timer two times, but okay, this case failed");
            }
            EXPECT_EQ(ret, RET_ERR);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("AddTimer success");
    }
    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS