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

import stationary from '@ohos.stationary';
import { BusinessError, AsyncCallback} from '@ohos.base';

const Tag:String = "stationary"

const ERR_INVALID_PARAM = 1;
const  OVERTIME_QUERY: long = 1000;
const  WAIT_OPER: long = 10000;
function wait(delay: long) {
    let start = new Date().getTime();
    while (new Date().getTime() - start < delay) {
    }
}

function test_once_change() {
    let fun_name: string = 'test_once_change_001';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: stationary.ActivityResponse) => {
            console.log(Tag,  `Stationary ${fun_name} on success`);
            console.log(Tag,  `Stationary ${fun_name} on success ${JSON.stringify(info)}`);
        };
        stationary.once('still', fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(WAIT_OPER);
        console.log(Tag, `${fun_name} end wait`);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on ${fun_name}`);
}

function test_activity_change() {
    let fun_name: string = 'test_activity_change';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: stationary.ActivityResponse) => {
            console.log(Tag,  `Stationary ${fun_name} on success`);
            console.log(Tag,  `Stationary ${fun_name} on success ${JSON.stringify(info)}`);
        };
        let event : stationary.ActivityEvent = stationary.ActivityEvent.ENTER;
        let reportLatencyNs = 1;
        stationary.on('still', event, reportLatencyNs, fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(WAIT_OPER);
        console.log(Tag, `${fun_name} end wait`);
        stationary.off('still', event, fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on ${fun_name}`);
}

function main() {
    console.println(Tag + ` into main`);
    test_once_change();
    test_activity_change();
    console.println(Tag + ` out main`);
}